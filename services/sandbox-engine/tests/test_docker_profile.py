import ast
import inspect
import unittest
from dataclasses import MISSING, FrozenInstanceError, fields, replace
from decimal import Decimal, localcontext
from unittest.mock import patch

from failroom_sandbox import docker_profile
from failroom_sandbox.docker_profile import (
    DockerBinding,
    ProfileConfigurationError,
    StrictDockerProfile,
    compile_create_argv,
    profile_fingerprint,
)
from failroom_sandbox.fingerprints import configuration_digest

_IMAGE_DIGEST = "sha256:" + "a" * 64
_SECCOMP_DIGEST = "sha256:" + "b" * 64


class DockerProfileTests(unittest.TestCase):
    def _profile_values(self):
        return {
            "image": ("registry.example.com:5000/failroom/diagnostic@" + _IMAGE_DIGEST),
            "uid": 10001,
            "gid": 10001,
            "seccomp_path": "/etc/failroom/seccomp.json",
            "seccomp_digest": _SECCOMP_DIGEST,
            "cpu_limit": Decimal("0.5"),
            "memory_limit_bytes": 134_217_728,
            "memory_swap_limit_bytes": 134_217_728,
            "pids_limit": 64,
            "workspace_tmpfs_bytes": 67_108_864,
            "temp_tmpfs_bytes": 16_777_216,
            "shm_size_bytes": 16_777_216,
            "fd_limit": 256,
            "io_device_path": "/dev/loop0",
            "io_read_bps": 1_048_576,
            "io_write_bps": 1_048_576,
            "terminal_output_limit_bytes": 1_048_576,
            "connection_limit": 1,
            "session_limit": 1,
            "absolute_ttl_seconds": 300,
        }

    def _profile(self):
        return StrictDockerProfile(**self._profile_values())

    def _binding(self):
        return DockerBinding(
            attempt_id="attempt-123",
            sandbox_id="sandbox-456",
            generation=1,
        )

    def test_compiles_an_immutable_profile_with_all_explicit_fields(self):
        profile = self._profile()

        self.assertEqual(profile.image, self._profile_values()["image"])
        with self.assertRaises(FrozenInstanceError):
            profile.uid = 10002

        incomplete = self._profile_values()
        del incomplete["absolute_ttl_seconds"]
        with self.assertRaises(TypeError):
            StrictDockerProfile(**incomplete)

    def test_declares_only_the_contract_api_and_has_no_field_defaults(self):
        self.assertEqual(
            tuple(getattr(docker_profile, "__all__", ())),
            (
                "StrictDockerProfile",
                "DockerBinding",
                "ProfileConfigurationError",
                "compile_create_argv",
                "profile_fingerprint",
            ),
        )
        for model in (StrictDockerProfile, DockerBinding):
            with self.subTest(model=model.__name__):
                for field in fields(model):
                    self.assertIs(field.default, MISSING)
                    self.assertIs(field.default_factory, MISSING)

    def test_never_imports_or_calls_a_docker_client_or_subprocess(self):
        module_tree = ast.parse(inspect.getsource(docker_profile))
        imported_roots = {
            alias.name.split(".", maxsplit=1)[0]
            for node in ast.walk(module_tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".", maxsplit=1)[0]
            for node in ast.walk(module_tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        )
        self.assertTrue({"docker", "subprocess"}.isdisjoint(imported_roots))

        with patch("subprocess.run") as subprocess_run:
            compile_create_argv(self._profile(), self._binding(), "operation-789")
        subprocess_run.assert_not_called()

    def test_rejects_missing_or_mutable_image_references(self):
        unsafe_images = (
            None,
            "",
            "registry.example.com/failroom/diagnostic",
            "registry.example.com/failroom/diagnostic:latest",
            "registry.example.com/failroom/diagnostic@sha256:" + "A" * 64,
            "registry.example.com/failroom/diagnostic@sha256:" + "a" * 63,
        )

        for image in unsafe_images:
            with self.subTest(image=image):
                values = self._profile_values()
                values["image"] = image
                with self.assertRaisesRegex(
                    ProfileConfigurationError,
                    "^INVALID_DOCKER_PROFILE$",
                ):
                    StrictDockerProfile(**values)

    def test_accepts_a_local_immutable_image_id(self):
        values = self._profile_values()
        values["image"] = "sha256:" + "c" * 64

        profile = StrictDockerProfile(**values)

        self.assertEqual(
            compile_create_argv(profile, self._binding(), "operation-789")[-2],
            values["image"],
        )

    def test_rejects_root_identity_and_unequal_memory_swap(self):
        profile = self._profile()

        for field in ("uid", "gid"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    ProfileConfigurationError,
                    "^INVALID_DOCKER_PROFILE$",
                ):
                    replace(profile, **{field: 0})

        with self.assertRaisesRegex(
            ProfileConfigurationError,
            "^INVALID_DOCKER_PROFILE$",
        ):
            replace(profile, memory_swap_limit_bytes=profile.memory_limit_bytes + 1)

    def test_rejects_relative_seccomp_path(self):
        with self.assertRaisesRegex(
            ProfileConfigurationError,
            "^INVALID_DOCKER_PROFILE$",
        ):
            replace(self._profile(), seccomp_path="etc/failroom/seccomp.json")

    def test_rejects_invalid_security_field_boundaries(self):
        profile = self._profile()
        positive_fields = (
            "uid",
            "gid",
            "memory_limit_bytes",
            "memory_swap_limit_bytes",
            "pids_limit",
            "workspace_tmpfs_bytes",
            "temp_tmpfs_bytes",
            "shm_size_bytes",
            "fd_limit",
            "io_read_bps",
            "io_write_bps",
            "terminal_output_limit_bytes",
            "connection_limit",
            "session_limit",
            "absolute_ttl_seconds",
        )
        for field in positive_fields:
            for value in (0, -1, True):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(
                        ProfileConfigurationError,
                        "^INVALID_DOCKER_PROFILE$",
                    ):
                        replace(profile, **{field: value})

        for value in (
            1,
            "0.5",
            Decimal(0),
            Decimal("-0.1"),
            Decimal("NaN"),
            Decimal("Infinity"),
        ):
            with self.subTest(cpu_limit=value):
                with self.assertRaisesRegex(
                    ProfileConfigurationError,
                    "^INVALID_DOCKER_PROFILE$",
                ):
                    replace(profile, cpu_limit=value)

        invalid_text_values = (
            ("seccomp_path", "relative/seccomp.json"),
            ("seccomp_path", "/../etc/failroom/seccomp.json"),
            ("seccomp_digest", None),
            ("seccomp_digest", "sha256:" + "A" * 64),
            ("seccomp_digest", "sha256:" + "a" * 63),
            ("io_device_path", None),
            ("io_device_path", "dev/loop0"),
            ("io_device_path", "/../dev/loop0"),
        )
        for field, value in invalid_text_values:
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(
                    ProfileConfigurationError,
                    "^INVALID_DOCKER_PROFILE$",
                ):
                    replace(profile, **{field: value})

    def test_rejects_unsafe_binding_and_operation_identifiers(self):
        profile = self._profile()
        unsafe_bindings = (
            (None, "sandbox-456", 1),
            ("", "sandbox-456", 1),
            ("attempt/123", "sandbox-456", 1),
            ("attempt-123", None, 1),
            ("attempt-123", "sandbox 456", 1),
            ("attempt-123", "sandbox-456", 0),
            ("attempt-123", "sandbox-456", -1),
            ("attempt-123", "sandbox-456", True),
            ("attempt-123", "sandbox-456", 1.0),
        )

        for attempt_id, sandbox_id, generation in unsafe_bindings:
            with self.subTest(
                attempt_id=attempt_id,
                sandbox_id=sandbox_id,
                generation=generation,
            ):
                with self.assertRaisesRegex(
                    ProfileConfigurationError,
                    "^INVALID_DOCKER_BINDING$",
                ):
                    DockerBinding(attempt_id, sandbox_id, generation)

        unsafe_operation_ids = (None, "", "operation/789", "operation 789", "x" * 64)
        for operation_id in unsafe_operation_ids:
            with self.subTest(operation_id=operation_id):
                with self.assertRaisesRegex(
                    ProfileConfigurationError,
                    "^INVALID_DOCKER_OPERATION$",
                ):
                    compile_create_argv(profile, self._binding(), operation_id)

    def test_cpu_requires_docker_minimum_exact_nanocpus_and_signed_int64(self):
        for value in (
            "0.009999999",
            "0.0000000001",
            "0.0100000001",
            "9223372036.854775808",
            "1e100000000",
            "1e-100000000",
        ):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ProfileConfigurationError, "^INVALID_DOCKER_PROFILE$"
                ):
                    replace(self._profile(), cpu_limit=Decimal(value))

    def test_cpu_argv_is_fixed_exact_and_independent_of_decimal_context(self):
        values = {
            "0.0100000000": "0.01",
            "1E+3": "1000",
            "1.234567891": "1.234567891",
            "9223372036.854775807": "9223372036.854775807",
        }
        with localcontext() as context:
            context.prec = 2
            for raw, expected in values.items():
                with self.subTest(value=raw):
                    argv = compile_create_argv(
                        replace(self._profile(), cpu_limit=Decimal(raw)),
                        self._binding(),
                        "operation-789",
                    )
                    self.assertEqual(argv[argv.index("--cpus") + 1], expected)

    def test_numerically_equal_cpu_limits_share_one_fingerprint(self):
        self.assertEqual(
            profile_fingerprint(replace(self._profile(), cpu_limit=Decimal("0.50"))),
            profile_fingerprint(replace(self._profile(), cpu_limit=Decimal("0.5"))),
        )

    def test_fingerprint_is_deterministic_and_covers_every_profile_field(self):
        profile = self._profile()
        fingerprint = profile_fingerprint(profile)
        changes = (
            {"image": "registry.example.com/failroom/diagnostic@sha256:" + "c" * 64},
            {"uid": 10002},
            {"gid": 10002},
            {"seccomp_path": "/etc/failroom/alternate-seccomp.json"},
            {"seccomp_digest": "sha256:" + "c" * 64},
            {"cpu_limit": Decimal("0.6")},
            {
                "memory_limit_bytes": 268_435_456,
                "memory_swap_limit_bytes": 268_435_456,
            },
            {"pids_limit": 65},
            {"workspace_tmpfs_bytes": 67_108_865},
            {"temp_tmpfs_bytes": 16_777_217},
            {"shm_size_bytes": 16_777_217},
            {"fd_limit": 257},
            {"io_device_path": "/dev/loop1"},
            {"io_read_bps": 1_048_577},
            {"io_write_bps": 1_048_577},
            {"terminal_output_limit_bytes": 1_048_577},
            {"connection_limit": 2},
            {"session_limit": 2},
            {"absolute_ttl_seconds": 301},
        )

        self.assertRegex(fingerprint, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(fingerprint, profile_fingerprint(profile))
        for change in changes:
            with self.subTest(change=change):
                self.assertNotEqual(
                    fingerprint,
                    profile_fingerprint(replace(profile, **change)),
                )

    def test_fingerprint_uses_shared_configuration_for_memory_swap_and_hardening(self):
        profile = self._profile()
        configuration = docker_profile._profile_configuration(profile)
        docker_configuration = configuration["docker"]

        self.assertEqual(
            profile_fingerprint(profile), configuration_digest(configuration)
        )
        self.assertEqual(docker_configuration["memory_limit_bytes"], 134_217_728)
        self.assertEqual(docker_configuration["memory_swap_limit_bytes"], 134_217_728)
        self.assertEqual(docker_configuration["network"], "none")
        self.assertIs(docker_configuration["read_only"], True)
        self.assertEqual(docker_configuration["cap_drop"], ["ALL"])
        self.assertEqual(
            docker_configuration["security_options"],
            ["no-new-privileges", "seccomp=/etc/failroom/seccomp.json"],
        )
        self.assertEqual(docker_configuration["pid_namespace"], "")
        self.assertEqual(docker_configuration["ipc_namespace"], "private")
        self.assertEqual(docker_configuration["cgroup_namespace"], "private")
        self.assertEqual(docker_configuration["restart"], "no")
        self.assertEqual(docker_configuration["log_driver"], "none")
        self.assertEqual(docker_configuration["runtime"], "runc")
        self.assertEqual(docker_configuration["entrypoint"], "/bin/sleep")
        self.assertIs(docker_configuration["healthcheck_disabled"], True)
        self.assertEqual(docker_configuration["pull_policy"], "never")
        self.assertEqual(docker_configuration["command"], ["60"])

    def test_container_name_is_deterministic_and_binding_unambiguous(self):
        profile = self._profile()
        first = compile_create_argv(profile, DockerBinding("a-b", "c", 1), "x")
        second = compile_create_argv(profile, DockerBinding("a", "b-c", 1), "x")
        first_name = first[first.index("--name") + 1]

        self.assertNotEqual(first_name, second[second.index("--name") + 1])
        self.assertEqual(
            first_name,
            "failroom-diagnostic-"
            "03f4f4366379bb434ad847021fa58113bd9bc64e7487e3d8e8b0037d406a89a3",
        )

    def test_builds_deterministic_hardened_docker_create_argv(self):
        argv = compile_create_argv(self._profile(), self._binding(), "operation-789")

        self.assertIsInstance(argv, tuple)
        self.assertEqual(
            argv,
            (
                "docker",
                "container",
                "create",
                "--name",
                "failroom-diagnostic-"
                "ab9b7db26fa8e8c02a4195e4c87ac3db2e3357c95d867f93aa27ca95cd719114",
                "--label",
                "failroom.kind=diagnostic",
                "--label",
                "failroom.attempt_id=attempt-123",
                "--label",
                "failroom.sandbox_id=sandbox-456",
                "--label",
                "failroom.generation=1",
                "--label",
                "failroom.operation_id=operation-789",
                "--network",
                "none",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--security-opt",
                "seccomp=/etc/failroom/seccomp.json",
                "--pid",
                "",
                "--ipc",
                "private",
                "--cgroupns",
                "private",
                "--restart",
                "no",
                "--log-driver",
                "none",
                "--runtime",
                "runc",
                "--entrypoint",
                "/bin/sleep",
                "--no-healthcheck",
                "--pull",
                "never",
                "--user",
                "10001:10001",
                "--memory",
                "134217728",
                "--memory-swap",
                "134217728",
                "--pids-limit",
                "64",
                "--cpus",
                "0.5",
                "--tmpfs",
                "/workspace:rw,size=67108864,nosuid,nodev,noexec",
                "--tmpfs",
                "/tmp:rw,size=16777216,nosuid,nodev,noexec",
                "--shm-size",
                "16777216",
                "--ulimit",
                "nofile=256:256",
                "--ulimit",
                "core=0:0",
                "--device-read-bps",
                "/dev/loop0:1048576",
                "--device-write-bps",
                "/dev/loop0:1048576",
                self._profile_values()["image"],
                "60",
            ),
        )
        self.assertEqual(
            argv, compile_create_argv(self._profile(), self._binding(), "operation-789")
        )

        prohibited = {
            "--bind",
            "--cap-add",
            "--device",
            "--mount",
            "--privileged",
            "--publish",
            "--volume",
            "-p",
            "-v",
        }
        self.assertTrue(prohibited.isdisjoint(argv))


if __name__ == "__main__":
    unittest.main()
