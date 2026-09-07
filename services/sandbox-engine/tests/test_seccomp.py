import hashlib
import importlib
import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class SeccompContractTests(unittest.TestCase):
    def test_snapshot_store_api_exists(self):
        self.assertIsNotNone(importlib.util.find_spec("failroom_sandbox.seccomp"))

    @unittest.skipIf(sys.platform == "linux", "unsupported-platform rejection")
    def test_unsupported_platform_fails_closed_before_filesystem_access(self):
        module = importlib.import_module("failroom_sandbox.seccomp")
        with self.assertRaisesRegex(
            module.SeccompError, "^SECCOMP_PLATFORM_UNSUPPORTED$"
        ):
            module.SeccompPolicyStore(Path(tempfile.gettempdir()), max_bytes=1024)


@unittest.skipUnless(
    sys.platform == "linux", "requires Linux no-follow dirfd semantics"
)
class SeccompFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.module = importlib.import_module("failroom_sandbox.seccomp")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / "policies"
        self.directory.mkdir(mode=0o700)
        self.source = self.root / "source.json"
        self.content = b'{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}'
        self.source.write_bytes(self.content)
        self.digest = "sha256:" + hashlib.sha256(self.content).hexdigest()
        self.store = self.module.SeccompPolicyStore(self.directory, max_bytes=1024)

    def pin(self, source=None, digest=None):
        return self.store.pin(str(source or self.source), digest or self.digest)

    def test_snapshot_contains_verified_bytes_readonly_content_address_and_cleans_up(
        self,
    ):
        with self.pin() as result:
            path = Path(result)
            self.assertTrue(path.is_absolute())
            self.assertEqual(path.name, self.digest.removeprefix("sha256:") + ".json")
            self.assertEqual(path.parent.parent, self.directory)
            self.assertEqual(path.read_bytes(), self.content)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertFalse(path.exists())
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_source_path_swap_after_open_cannot_change_the_verified_snapshot(self):
        original_open = os.open

        def open_then_swap(path, flags, *args, **kwargs):
            descriptor = original_open(path, flags, *args, **kwargs)
            if path == self.source.name:
                self.source.rename(self.root / "original.json")
                self.source.write_bytes(b"untrusted replacement")
            return descriptor

        with patch.object(self.module.os, "open", side_effect=open_then_swap):
            with self.pin() as result:
                self.assertEqual(Path(result).read_bytes(), self.content)
                self.assertNotEqual(self.source.read_bytes(), self.content)

    def test_source_changes_after_verification_do_not_change_pinned_bytes(self):
        with self.pin() as result:
            self.source.write_bytes(b"changed")
            self.assertEqual(Path(result).read_bytes(), self.content)

    def test_rejects_source_symlink_and_symlinked_parent(self):
        link = self.root / "linked.json"
        link.symlink_to(self.source)
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "source.json").write_bytes(self.content)
        linked_parent = self.root / "linked-parent"
        linked_parent.symlink_to(nested, target_is_directory=True)
        for source in (link, linked_parent / "source.json"):
            with self.subTest(source=source):
                with self.assertRaisesRegex(
                    self.module.SeccompError, "^SECCOMP_POLICY_INVALID$"
                ):
                    with self.pin(source=source):
                        self.fail("unsafe policy was accepted")

    def test_rejects_digest_mismatch_and_malformed_digest_without_snapshot(self):
        for digest in ("sha256:" + "0" * 64, "invalid", "sha256:" + "A" * 64):
            with self.subTest(digest=digest):
                with self.assertRaisesRegex(
                    self.module.SeccompError, "^SECCOMP_POLICY_INVALID$"
                ):
                    with self.pin(digest=digest):
                        self.fail("incorrect digest was accepted")
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_rejects_directory_fifo_and_oversized_policy_without_blocking(self):
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        oversized = self.root / "oversized.json"
        oversized.write_bytes(b"x" * 1025)
        for source in (self.root, fifo, oversized):
            with self.subTest(source=source):
                with self.assertRaisesRegex(
                    self.module.SeccompError, "^SECCOMP_POLICY_INVALID$"
                ):
                    with self.pin(source=source):
                        self.fail("nonregular or oversized source was accepted")

    def test_limits_actual_read_when_source_grows_after_fstat(self):
        original_read = os.read
        grew = False

        def grow_then_read(descriptor, count):
            nonlocal grew
            if not grew:
                grew = True
                self.source.write_bytes(b"x" * 2048)
            self.assertLessEqual(count, 1025)
            return original_read(descriptor, count)

        with patch.object(self.module.os, "read", side_effect=grow_then_read):
            with self.assertRaisesRegex(
                self.module.SeccompError, "^SECCOMP_POLICY_INVALID$"
            ):
                with self.pin():
                    self.fail("growing source was accepted")

    def test_rejects_nonprivate_or_symlinked_store(self):
        for mode in (0o755, 0o770, 0o707):
            self.directory.chmod(mode)
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(
                    self.module.SeccompError, "^SECCOMP_STORE_UNSAFE$"
                ):
                    with self.pin():
                        self.fail("nonprivate directory was accepted")
        self.directory.chmod(0o700)
        linked = self.root / "linked-store"
        linked.symlink_to(self.directory, target_is_directory=True)
        store = self.module.SeccompPolicyStore(linked, max_bytes=1024)
        with self.assertRaisesRegex(self.module.SeccompError, "^SECCOMP_STORE_UNSAFE$"):
            with store.pin(str(self.source), self.digest):
                self.fail("symlinked store was accepted")

    def test_rejects_writable_ancestor_even_when_store_is_private(self):
        self.root.chmod(0o777)
        self.addCleanup(self.root.chmod, 0o700)
        with self.assertRaisesRegex(self.module.SeccompError, "^SECCOMP_STORE_UNSAFE$"):
            with self.pin():
                self.fail("unsafe ancestor was accepted")

    def test_nested_pins_remain_independent_and_cleanup_on_caller_error(self):
        with self.pin() as first:
            with self.assertRaisesRegex(RuntimeError, "caller failure"):
                with self.pin() as second:
                    self.assertNotEqual(first, second)
                    self.assertEqual(
                        Path(first).read_bytes(), Path(second).read_bytes()
                    )
                    raise RuntimeError("caller failure")
            self.assertFalse(Path(second).exists())
            self.assertEqual(Path(first).read_bytes(), self.content)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_rejects_invalid_explicit_configuration_and_source_paths(self):
        for limit in (0, -1, True, "1024"):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(
                    self.module.SeccompError, "^INVALID_SECCOMP_CONFIGURATION$"
                ):
                    self.module.SeccompPolicyStore(self.directory, max_bytes=limit)
        for path in ("relative.json", str(self.root / ".." / "source.json"), ""):
            with self.subTest(path=path):
                with self.assertRaisesRegex(
                    self.module.SeccompError, "^SECCOMP_POLICY_INVALID$"
                ):
                    with self.store.pin(path, self.digest):
                        self.fail("unsafe source path was accepted")


if __name__ == "__main__":
    unittest.main()
