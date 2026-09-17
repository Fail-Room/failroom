import unittest
from pathlib import Path

IMAGE_DIR = Path(__file__).resolve().parents[3] / "scenarios" / "disk-full" / "image"


class DiskFullTargetArtifactTests(unittest.TestCase):
    def test_target_artifact_is_non_root_and_pinned(self) -> None:
        dockerfile = (IMAGE_DIR / "Dockerfile").read_text(encoding="ascii")
        target = (IMAGE_DIR / "failroom-disk-target").read_text(encoding="ascii")

        self.assertIn(
            "FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517",
            dockerfile,
        )
        self.assertIn("COPY --chmod=0555", dockerfile)
        self.assertIn("USER 1000:1000", dockerfile)
        self.assertIn("WORKING_SET_BYTES=8000000", target)
        self.assertIn('case "${1:-}" in', target)

    def test_target_status_requires_a_live_process_and_exact_working_set(self) -> None:
        target = (IMAGE_DIR / "failroom-disk-target").read_text(encoding="ascii")

        self.assertIn("/proc/$pid", target)
        self.assertIn("STATE_DIR=/workspace/.failroom-target", target)
        self.assertIn("READY=$STATE_DIR/ready", target)
        self.assertIn("WORK=$STATE_DIR/working-set", target)
        self.assertIn('wc -c <"$WORK"', target)


if __name__ == "__main__":
    unittest.main()
