import copy
import hashlib
import json
import unittest
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal, localcontext

import test_docker_profile

from failroom_sandbox.docker_cli import DockerCli, DockerError, ProcessResult
from failroom_sandbox.docker_lifecycle import DockerDiagnosticLifecycle
from failroom_sandbox.docker_profile import DockerBinding, compile_create_argv
from failroom_sandbox.models import QualificationContext, RuntimeIdentity
from failroom_sandbox.qualification import ProfileNotQualified

CID = "c" * 64
IMAGE_ID = "sha256:" + "d" * 64
BINDING = DockerBinding("attempt-123", "sandbox-456", 1)
OP = "operation-789"


def observation(profile, seccomp_path):
    return {
        "Id": CID,
        "Name": "/" + compile_create_argv(profile, BINDING, OP)[4],
        "Image": IMAGE_ID,
        "Config": {
            "Image": profile.image,
            "User": "10001:10001",
            "Entrypoint": ["/bin/sleep"],
            "Cmd": ["60"],
            "Healthcheck": {"Test": ["NONE"]},
            "Env": ["PATH=/usr/bin:/bin"],
            "Volumes": None,
            "Labels": {
                "failroom.kind": "diagnostic",
                "failroom.attempt_id": BINDING.attempt_id,
                "failroom.sandbox_id": BINDING.sandbox_id,
                "failroom.generation": "1",
                "failroom.operation_id": OP,
            },
        },
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": [
                "no-new-privileges",
                "seccomp=" + seccomp_path,
            ],
            "PidMode": "",
            "IpcMode": "private",
            "CgroupnsMode": "private",
            "Runtime": "runc",
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
            "LogConfig": {"Type": "none", "Config": {}},
            "Memory": 134217728,
            "MemorySwap": 134217728,
            "NanoCpus": 500000000,
            "PidsLimit": 64,
            "ShmSize": 16777216,
            "Tmpfs": {
                "/workspace": "rw,size=67108864,nosuid,nodev,noexec",
                "/tmp": "rw,size=16777216,nosuid,nodev,noexec",
            },
            "Ulimits": [
                {"Name": "nofile", "Soft": 256, "Hard": 256},
                {"Name": "core", "Soft": 0, "Hard": 0},
            ],
            "BlkioDeviceReadBps": [{"Path": "/dev/loop0", "Rate": 1048576}],
            "BlkioDeviceWriteBps": [{"Path": "/dev/loop0", "Rate": 1048576}],
            "Binds": None,
            "Mounts": None,
            "VolumesFrom": None,
            "Devices": [],
            "DeviceRequests": None,
            "DeviceCgroupRules": None,
            "PortBindings": {},
            "PublishAllPorts": False,
            "Links": None,
        },
        "Mounts": [
            {"Type": "tmpfs", "Destination": "/workspace", "Source": ""},
            {"Type": "tmpfs", "Destination": "/tmp", "Source": ""},
        ],
        "State": {"Running": False, "Status": "created"},
    }


class Policy:
    path = "/trusted/policies/verified.json"

    def __init__(self):
        self.active = False
        self.reject = False

    @contextmanager
    def pin(self, source_path, expected_digest):
        if self.reject:
            raise DockerError("PROFILE_UNVERIFIED")
        self.active = True
        try:
            yield self.path
        finally:
            self.active = False


class Engine:
    def __init__(self, profile, seccomp_path):
        self.calls = []
        self.created = False
        self.resource = observation(profile, seccomp_path)
        self.image = {
            "Id": IMAGE_ID,
            "Os": "linux",
            "RepoDigests": [profile.image],
            "Config": {"Volumes": None, "Env": ["PATH=/usr/bin:/bin"]},
        }
        self.after_create = None
        self.after_start = None
        self.keep_after_remove = False

    def __call__(self, argv, *, timeout, max_output_bytes):
        self.calls.append(argv)
        args = argv[3:]
        if args[:2] == ("image", "inspect"):
            return ProcessResult(0, json.dumps([self.image]).encode(), b"")
        if args[:2] == ("container", "create"):
            self.created = True
            if self.after_create:
                self.after_create(self.resource)
            return ProcessResult(0, (CID + "\n").encode(), b"")
        if args[:2] == ("container", "inspect"):
            return (
                ProcessResult(0, json.dumps([self.resource]).encode(), b"")
                if self.created
                else ProcessResult(1, b"[]", b"not found")
            )
        if args[:2] == ("container", "ls"):
            return ProcessResult(0, (CID if self.created else "").encode(), b"")
        if args[:2] == ("container", "start"):
            self.resource["State"] = {"Running": True, "Status": "running"}
            if self.after_start:
                self.after_start(self.resource)
        elif args[:2] == ("container", "stop"):
            self.resource["State"] = {"Running": False, "Status": "exited"}
        elif args[:2] == ("container", "rm"):
            self.created = self.keep_after_remove
        else:
            raise AssertionError(args)
        return ProcessResult(0, (CID + "\n").encode(), b"")


class DockerLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.seccomp_policy = '{"defaultAction":"SCMP_ACT_ERRNO"}'
        self.profile = replace(
            test_docker_profile.DockerProfileTests()._profile(),
            seccomp_digest="sha256:"
            + hashlib.sha256(self.seccomp_policy.encode("utf-8")).hexdigest(),
        )
        self.policy = Policy()
        self.engine = Engine(self.profile, self.policy.path)
        self.cli = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=65536,
            runner=self.engine,
        )
        self.lifecycle = DockerDiagnosticLifecycle(self.cli, self.policy)

    def create(self):
        return self.lifecycle.create_diagnostic(self.profile, BINDING, OP)

    def test_create_inspects_image_and_pinned_policy_before_start(self):
        result = self.create()
        self.assertEqual(result.container_id, CID)
        self.assertTrue(result.running)
        create = next(
            call for call in self.engine.calls if call[3:5] == ("container", "create")
        )
        self.assertIn("seccomp=/trusted/policies/verified.json", create)
        self.assertFalse(self.policy.active)
        self.assertEqual(self.create().container_id, CID)
        self.assertEqual(
            sum(call[3:5] == ("container", "create") for call in self.engine.calls), 1
        )

    def test_declared_image_volume_or_missing_metadata_denies_without_create(self):
        for value in ({"/data": {}}, [], "bad"):
            with self.subTest(value=value):
                self.engine.image["Config"]["Volumes"] = value
                with self.assertRaises(DockerError):
                    self.create()
                self.assertFalse(self.engine.created)
        del self.engine.image["Config"]["Volumes"]
        with self.assertRaises(DockerError):
            self.create()

    def test_wrong_image_digest_os_or_env_denies(self):
        for field, value in (("RepoDigests", []), ("Id", "short"), ("Os", "windows")):
            original = copy.deepcopy(self.engine.image)
            self.engine.image[field] = value
            with self.subTest(field=field), self.assertRaises(DockerError):
                self.create()
            self.assertFalse(self.engine.created)
            self.engine.image = original

    def test_unexpected_mount_is_never_started_and_cleanup_is_unverified(self):
        self.engine.after_create = lambda r: r.update(
            Mounts=[{"Type": "volume", "Name": "unowned", "Destination": "/data"}]
        )
        with self.assertRaisesRegex(DockerError, "CLEANUP_INCOMPLETE"):
            self.create()
        self.assertFalse(
            any(c[3:5] == ("container", "start") for c in self.engine.calls)
        )

    def test_hardening_drift_is_cleaned_without_start(self):
        self.engine.after_create = lambda r: r["HostConfig"].update(Privileged=True)
        with self.assertRaises(DockerError):
            self.create()
        self.assertFalse(self.engine.created)
        self.assertFalse(
            any(c[3:5] == ("container", "start") for c in self.engine.calls)
        )

    def test_seccomp_inspect_path_must_match_the_pinned_snapshot(self):
        self.engine.resource["HostConfig"]["SecurityOpt"][1] = (
            "seccomp=/trusted/policies/other.json"
        )
        with self.assertRaisesRegex(DockerError, "^PROFILE_UNVERIFIED$"):
            self.create()
        self.assertFalse(self.engine.created)

    def test_missing_required_tmpfs_is_cleaned_without_start(self):
        self.engine.after_create = lambda r: r.update(
            Mounts=[
                {
                    "Type": "tmpfs",
                    "Destination": "/workspace",
                    "Source": "",
                }
            ]
        )
        with self.assertRaisesRegex(DockerError, "^CLEANUP_INCOMPLETE$"):
            self.create()
        self.assertFalse(self.engine.created)
        self.assertFalse(
            any(c[3:5] == ("container", "start") for c in self.engine.calls)
        )

    def test_cpu_verification_uses_exact_nanocpus_independent_of_decimal_context(self):
        self.profile = replace(self.profile, cpu_limit=Decimal("1.234567891"))
        self.engine = Engine(self.profile, self.policy.path)
        self.engine.resource["HostConfig"]["NanoCpus"] = 1_234_567_891
        self.cli = DockerCli(
            context="desktop-linux",
            timeout=5,
            max_output_bytes=65536,
            runner=self.engine,
        )
        self.lifecycle = DockerDiagnosticLifecycle(self.cli, self.policy)
        with localcontext() as context:
            context.prec = 1
            self.assertEqual(self.create().container_id, CID)

    def test_policy_pin_rejection_does_not_remove_an_existing_operation(self):
        self.create()
        self.policy.reject = True
        with self.assertRaisesRegex(DockerError, "^PROFILE_UNVERIFIED$"):
            self.create()
        self.assertTrue(self.engine.created)

    def test_ownership_mismatch_or_missing_label_never_removes(self):
        for label in (
            "failroom.attempt_id",
            "failroom.sandbox_id",
            "failroom.generation",
            "failroom.operation_id",
            "failroom.kind",
        ):
            self.engine.created = True
            self.engine.resource = observation(self.profile, self.policy.path)
            self.engine.resource["Config"]["Labels"].pop(label)
            self.engine.calls.clear()
            with self.subTest(label=label), self.assertRaises(DockerError):
                self.lifecycle.destroy(BINDING, CID)
            self.assertFalse(
                any(
                    c[3:5] in (("container", "stop"), ("container", "rm"))
                    for c in self.engine.calls
                )
            )

    def test_destroy_requires_post_remove_absence_and_is_idempotent(self):
        self.create()
        evidence = self.lifecycle.destroy(BINDING, CID)
        self.assertRegex(evidence, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(evidence, self.lifecycle.destroy(BINDING, CID))
        self.assertFalse(self.engine.created)

    def test_remove_success_without_absence_does_not_succeed(self):
        self.create()
        self.engine.keep_after_remove = True
        with self.assertRaisesRegex(DockerError, "CLEANUP_INCOMPLETE"):
            self.lifecycle.destroy(BINDING, CID)

    def test_unknown_container_id_is_reconciled_from_exact_binding(self):
        self.create()
        self.assertRegex(self.lifecycle.destroy(BINDING, None), r"^sha256:")
        self.assertFalse(self.engine.created)

    def test_prepared_operation_persists_pin_through_create_then_start(self):
        with self.lifecycle.prepare(self.profile, BINDING, OP) as operation:
            created = operation.create_verified()
            self.assertEqual(created.container_id, CID)
            self.assertFalse(created.running)
            self.assertTrue(self.policy.active)
            result = operation.start_verified(created)
            self.assertTrue(result.running)
            self.assertRegex(result.evidence_digest, r"^sha256:[0-9a-f]{64}$")
        self.assertFalse(self.policy.active)

    def test_start_response_loss_reconciles_running_container(self):
        self.engine.after_start = lambda _: (_ for _ in ()).throw(
            DockerError("RUNTIME_UNAVAILABLE")
        )
        with self.lifecycle.prepare(self.profile, BINDING, OP) as operation:
            created = operation.create_verified()
            result = operation.start_verified(created)
        self.assertTrue(result.running)
        self.assertTrue(self.engine.created)
        self.assertEqual(
            sum(call[3:5] == ("container", "start") for call in self.engine.calls),
            1,
        )

    def test_preexisting_ownership_mismatch_is_not_started_or_removed(self):
        self.engine.created = True
        self.engine.resource["Config"]["Labels"]["failroom.operation_id"] = "other"
        self.engine.calls.clear()
        with self.assertRaisesRegex(DockerError, "^OWNERSHIP_MISMATCH$"):
            with self.lifecycle.prepare(self.profile, BINDING, OP) as operation:
                operation.create_verified()
        self.assertFalse(
            any(
                call[3:5] in (("container", "start"), ("container", "rm"))
                for call in self.engine.calls
            )
        )

    def test_recovery_after_create_response_loss_reuses_exact_owned_container(self):
        self.engine.after_create = lambda _: (_ for _ in ()).throw(
            DockerError("RUNTIME_UNAVAILABLE")
        )
        with self.assertRaises(DockerError):
            with self.lifecycle.prepare(self.profile, BINDING, OP) as operation:
                operation.create_verified()
        self.engine.after_create = None
        with self.lifecycle.prepare(self.profile, BINDING, OP) as operation:
            self.assertEqual(operation.create_verified().container_id, CID)
        self.assertEqual(
            sum(call[3:5] == ("container", "create") for call in self.engine.calls),
            1,
        )

    def test_qualification_denial_has_zero_docker_calls(self):
        context = QualificationContext(
            RuntimeIdentity("engine", "boot", "epoch", "sha256:" + "a" * 64),
            "sha256:" + "a" * 64,
            "sha256:" + "b" * 64,
        )
        with self.assertRaises(ProfileNotQualified):
            self.lifecycle.create_qualified(
                self.profile,
                BINDING,
                OP,
                context=context,
                report=None,
                now=datetime.now(UTC),
                max_age=timedelta(minutes=5),
            )
        self.assertEqual(self.engine.calls, [])
