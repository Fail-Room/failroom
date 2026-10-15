import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from failroom_control_plane.qualification_workspace import (
    ID_NAME,
    LOCK_NAME,
    WORKSPACE_NAME,
    LockedWorkspace,
    WorkspaceError,
    workspace_id,
)


class WorkspaceConfigurationTests(unittest.TestCase):
    def test_parent_must_be_an_absolute_path(self) -> None:
        for parent in (Path("relative"), "/tmp", None):
            with (
                self.subTest(parent=parent),
                self.assertRaises(WorkspaceError) as raised,
            ):
                LockedWorkspace(parent)  # type: ignore[arg-type]
            self.assertEqual(raised.exception.code, "WORKSPACE_UNSAFE")

    def test_unknown_codes_are_reduced_to_a_fixed_code(self) -> None:
        self.assertEqual(WorkspaceError("/home/user").code, "WORKSPACE_UNAVAILABLE")

    @unittest.skipIf(sys.platform == "linux", "non-Linux behavior")
    def test_workspace_needs_linux(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            workspace = LockedWorkspace(Path(name))
            with self.assertRaises(WorkspaceError) as raised, workspace.hold():
                pass
            self.assertEqual(raised.exception.code, "WORKSPACE_UNAVAILABLE")
            self.assertEqual(list(Path(name).iterdir()), [])


class WorkspaceIdTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)

    def test_id_is_created_once_and_then_kept(self) -> None:
        first = workspace_id(self.path)

        self.assertRegex(first, r"^[0-9a-f]{32}$")
        self.assertEqual(workspace_id(self.path), first)
        self.assertEqual(
            (self.path / ID_NAME).read_bytes(), (first + "\n").encode("ascii")
        )
        self.assertEqual([entry.name for entry in self.path.iterdir()], [ID_NAME])

    def test_an_id_that_is_not_one_is_refused(self) -> None:
        for content in (b"", b"a" * 32, b"A" * 32 + b"\n", b"a" * 31 + b"\n"):
            with self.subTest(content=content):
                (self.path / ID_NAME).write_bytes(content)
                with self.assertRaises(WorkspaceError) as raised:
                    workspace_id(self.path)
                self.assertEqual(raised.exception.code, "WORKSPACE_UNSAFE")

    @unittest.skipUnless(sys.platform == "linux", "Linux ownership evidence required")
    def test_id_is_private_and_never_read_through_a_link(self) -> None:
        workspace_id(self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path / ID_NAME).st_mode), 0o600)

        elsewhere = self.path / "elsewhere"
        (self.path / ID_NAME).rename(elsewhere)
        (self.path / ID_NAME).symlink_to(elsewhere)
        with self.assertRaises(WorkspaceError) as raised:
            workspace_id(self.path)
        self.assertEqual(raised.exception.code, "WORKSPACE_UNSAFE")


@unittest.skipUnless(sys.platform == "linux", "Linux ownership evidence required")
class LockedWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.parent = Path(temp.name)
        self.path = self.parent / WORKSPACE_NAME

    def hold_code(self, workspace: LockedWorkspace) -> str:
        with self.assertRaises(WorkspaceError) as raised, workspace.hold():
            pass
        return raised.exception.code

    def test_creates_a_private_workspace_and_keeps_its_lock_file(self) -> None:
        with LockedWorkspace(self.parent).hold() as path:
            self.assertEqual(path, self.path)
            info = os.stat(path)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual(info.st_uid, os.geteuid())
            self.assertTrue((path / LOCK_NAME).is_file())

        self.assertEqual([entry.name for entry in self.path.iterdir()], [LOCK_NAME])
        with LockedWorkspace(self.parent).hold():
            pass

    def test_second_collection_is_refused_until_the_first_ends(self) -> None:
        first = LockedWorkspace(self.parent)
        with first.hold():
            self.assertEqual(
                self.hold_code(LockedWorkspace(self.parent)), "COLLECTION_IN_PROGRESS"
            )
        with LockedWorkspace(self.parent).hold():
            pass

    def test_a_workspace_others_can_reach_is_refused(self) -> None:
        self.path.mkdir(mode=0o700)
        self.path.chmod(0o750)
        self.assertEqual(
            self.hold_code(LockedWorkspace(self.parent)), "WORKSPACE_UNSAFE"
        )

    def test_a_symlinked_workspace_or_lock_is_refused(self) -> None:
        target = self.parent / "elsewhere"
        target.mkdir(mode=0o700)
        self.path.symlink_to(target)
        self.assertEqual(
            self.hold_code(LockedWorkspace(self.parent)), "WORKSPACE_UNSAFE"
        )

        self.path.unlink()
        self.path.mkdir(mode=0o700)
        (self.path / LOCK_NAME).symlink_to(target / "lock")
        self.assertEqual(
            self.hold_code(LockedWorkspace(self.parent)), "WORKSPACE_UNSAFE"
        )
        self.assertFalse((target / "lock").exists())

    def test_a_lock_that_is_not_a_file_is_refused(self) -> None:
        self.path.mkdir(mode=0o700)
        (self.path / LOCK_NAME).mkdir()
        self.assertEqual(
            self.hold_code(LockedWorkspace(self.parent)), "WORKSPACE_UNSAFE"
        )


if __name__ == "__main__":
    unittest.main()
