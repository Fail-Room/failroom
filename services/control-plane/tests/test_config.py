import hashlib
import unittest
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from failroom_sandbox.docker_profile import StrictDockerProfile

from failroom_control_plane.config import ConfigurationError, ControllerConfig

_POLICY = '{"defaultAction":"SCMP_ACT_ERRNO"}'


def profile() -> StrictDockerProfile:
    return StrictDockerProfile(
        image="registry.example.com:5000/failroom/diagnostic@sha256:" + "a" * 64,
        uid=10001,
        gid=10001,
        seccomp_path="/etc/failroom/seccomp.json",
        seccomp_digest="sha256:" + hashlib.sha256(_POLICY.encode()).hexdigest(),
        cpu_limit=Decimal("0.5"),
        memory_limit_bytes=134_217_728,
        memory_swap_limit_bytes=134_217_728,
        pids_limit=64,
        workspace_tmpfs_bytes=67_108_864,
        temp_tmpfs_bytes=16_777_216,
        target_supervisor_tmpfs_bytes=1_048_576,
        shm_size_bytes=16_777_216,
        fd_limit=256,
        io_device_path="/dev/loop0",
        io_read_bps=1_048_576,
        io_write_bps=1_048_576,
        terminal_output_limit_bytes=1_048_576,
        connection_limit=1,
        session_limit=1,
        absolute_ttl_seconds=300,
    )


class ControllerConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = profile()
        self.database_path = Path.cwd() / "private-state" / "failroom.sqlite3"
        self.seccomp_store = Path.cwd() / "private-state" / "seccomp"

    def config(self, **changes: object) -> ControllerConfig:
        values: dict[str, object] = {
            "database_path": self.database_path,
            "docker_context": "desktop-linux",
            "docker_timeout_seconds": 5.0,
            "docker_max_output_bytes": 65_536,
            "seccomp_store": self.seccomp_store,
            "seccomp_max_bytes": 65_536,
            "profile": self.profile,
            "cleanup_retry_delay": timedelta(seconds=1),
        }
        values.update(changes)
        return ControllerConfig(**values)  # type: ignore[arg-type]

    def test_controller_config_requires_absolute_private_paths_and_no_defaults(
        self,
    ) -> None:
        with self.assertRaises(ConfigurationError) as caught:
            self.config(database_path=Path("state.sqlite3"))
        self.assertEqual(caught.exception.code, "INVALID_CONFIGURATION")

        with self.assertRaises(ConfigurationError):
            self.config(seccomp_store=Path("relative/policies"))
        with self.assertRaises(TypeError):
            ControllerConfig(  # type: ignore[call-arg]
                database_path=self.database_path,
                docker_context="desktop-linux",
                docker_timeout_seconds=5.0,
                docker_max_output_bytes=65_536,
                seccomp_store=self.seccomp_store,
                seccomp_max_bytes=65_536,
                profile=self.profile,
            )

    def test_controller_config_keeps_explicit_profile_and_database_separate(
        self,
    ) -> None:
        config = self.config()
        self.assertIs(config.profile, self.profile)
        self.assertEqual(config.database_path, self.database_path)
        self.assertEqual(config.seccomp_store, self.seccomp_store)

    def test_adapter_constructors_map_rejections_to_fixed_configuration_error(
        self,
    ) -> None:
        with self.assertRaises(ConfigurationError) as caught:
            self.config(docker_context="bad context").docker_cli()
        self.assertEqual(caught.exception.code, "INVALID_CONFIGURATION")

        with self.assertRaises(ConfigurationError) as caught:
            self.config(seccomp_max_bytes=0).seccomp_policy_store()
        self.assertEqual(caught.exception.code, "INVALID_CONFIGURATION")

    def test_valid_docker_constructor_is_explicit_and_does_not_execute_commands(
        self,
    ) -> None:
        cli = self.config().docker_cli()
        self.assertEqual(cli.context, "desktop-linux")

    def test_profile_must_be_the_immutable_strict_profile_type(self) -> None:
        with self.assertRaises(ConfigurationError):
            self.config(profile=object())
        with self.assertRaises(ConfigurationError):
            self.config(cleanup_retry_delay=timedelta(0))
        with self.assertRaises(ConfigurationError):
            self.config(docker_timeout_seconds=float("nan"))

        self.assertIsInstance(self.profile, StrictDockerProfile)


if __name__ == "__main__":
    unittest.main()
