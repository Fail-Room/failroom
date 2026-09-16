import os
import sys
import tempfile
import unittest
from pathlib import Path

from failroom_control_plane.local_environment import (
    LocalEnvironmentError,
    load_operator_environment,
)


@unittest.skipUnless(sys.platform == "linux", "Linux ownership evidence required")
class LocalOperatorEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write_environment(self, content: str, *, mode: int = 0o600) -> Path:
        path = self.root / "operator.env"
        path.write_text(content)
        os.chmod(path, mode)
        return path

    def test_loads_explicit_ascii_key_value_pairs(self) -> None:
        path = self.write_environment(
            "# trusted local operator input\n"
            "FAILROOM_LOCAL_BIND_HOST=127.0.0.1\n"
            "FAILROOM_DOCKER_CONTEXT=desktop-wsl\n"
        )

        loaded = load_operator_environment(str(path))

        self.assertEqual(
            loaded,
            {
                "FAILROOM_LOCAL_BIND_HOST": "127.0.0.1",
                "FAILROOM_DOCKER_CONTEXT": "desktop-wsl",
            },
        )

    def test_rejects_group_readable_environment_file(self) -> None:
        path = self.write_environment(
            "FAILROOM_LOCAL_BIND_HOST=127.0.0.1\n", mode=0o640
        )

        with self.assertRaises(LocalEnvironmentError):
            load_operator_environment(str(path))

    def test_rejects_symbolic_link_environment_file(self) -> None:
        source = self.write_environment("FAILROOM_LOCAL_BIND_HOST=127.0.0.1\n")
        link = self.root / "operator-link.env"
        link.symlink_to(source)

        with self.assertRaises(LocalEnvironmentError):
            load_operator_environment(str(link))

    def test_rejects_duplicate_environment_keys(self) -> None:
        path = self.write_environment(
            "FAILROOM_LOCAL_BIND_HOST=127.0.0.1\nFAILROOM_LOCAL_BIND_HOST=::1\n"
        )

        with self.assertRaises(LocalEnvironmentError):
            load_operator_environment(str(path))
