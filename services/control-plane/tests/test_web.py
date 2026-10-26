import hashlib
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from failroom_api import (
    BackendCapabilityAuthority,
    BearerCredential,
    BearerIdentityVerifier,
    CapabilityCodec,
)
from failroom_state import BackendStore, Database, UserIdentity
from fastapi.testclient import TestClient

from failroom_control_plane.browser import LoopbackOrigin
from failroom_control_plane.http import create_app
from failroom_control_plane.web import PAGE_POLICY, WebInterface

API_POLICY = "default-src 'none'; frame-ancestors 'none'"


class WebInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        base = Path(temp.name)
        self.root = base / "out"
        (self.root / "room").mkdir(parents=True)
        (self.root / "_next" / "static").mkdir(parents=True)
        for name, text in (
            ("index.html", "<!doctype html><title>Sign in</title>"),
            ("room/index.html", "<!doctype html><title>Room</title>"),
            ("404.html", "<!doctype html><title>Missing</title>"),
            ("_next/static/page.js", "window.page = 1;"),
            ("_next/static/page.css", "main { margin: 0; }"),
        ):
            (self.root / name).write_text(text, encoding="utf-8")
        (base / "secret.txt").write_text("outside the export", encoding="utf-8")
        now = datetime(2026, 10, 26, tzinfo=UTC)
        database = Database(base / "state.sqlite3", busy_timeout_ms=5000)
        database.initialize()
        token = "local-token-with-at-least-32-bytes-0001"
        self.authority = BackendCapabilityAuthority(
            BackendStore(database),
            CapabilityCodec(b"k" * 32, max_lifetime=timedelta(seconds=60)),
        )
        self.verifier = BearerIdentityVerifier(
            {
                hashlib.sha256(token.encode("ascii")).hexdigest(): BearerCredential(
                    UserIdentity("alice", frozenset({"disk-full"})),
                    now + timedelta(minutes=10),
                )
            },
            now=lambda: now,
        )
        self.origin = LoopbackOrigin(
            frozenset({"testserver"}), frozenset({"http://testserver"})
        )
        self.now = now
        self.client = TestClient(self._app(web_root=self.root))

    def _app(self, **arguments):
        return create_app(
            authority=self.authority,
            verifier=self.verifier,
            origin=self.origin,
            now=lambda: self.now,
            **arguments,
        )

    def test_a_page_is_served_with_the_page_policy(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("<title>Sign in</title>", response.text)
        self.assertEqual(response.headers["content-security-policy"], PAGE_POLICY)
        self.assertEqual(response.headers["content-type"], "text/html; charset=utf-8")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn("script-src 'self'", PAGE_POLICY)
        self.assertNotIn("unsafe-inline", PAGE_POLICY.split("style-src-elem")[0])

    def test_a_page_path_redirects_to_its_trailing_slash(self) -> None:
        redirect = self.client.get("/room", follow_redirects=False)
        page = self.client.get("/room/")

        self.assertEqual(redirect.status_code, 307)
        self.assertTrue(redirect.headers["location"].endswith("/room/"))
        self.assertEqual(page.status_code, 200)
        self.assertIn("<title>Room</title>", page.text)

    def test_assets_get_fixed_media_types(self) -> None:
        for path, media_type in (
            ("/_next/static/page.js", "text/javascript; charset=utf-8"),
            ("/_next/static/page.css", "text/css; charset=utf-8"),
        ):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["content-type"], media_type)

    def test_an_unknown_page_gets_the_export_404_page(self) -> None:
        response = self.client.get("/missing")

        self.assertEqual(response.status_code, 404)
        self.assertIn("<title>Missing</title>", response.text)
        self.assertEqual(response.headers["content-security-policy"], PAGE_POLICY)

    def test_api_paths_never_get_a_page(self) -> None:
        unknown = self.client.get("/v1/unknown")
        capability = self.client.post("/v1/attempts/attempt-1/terminal-capability")

        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(unknown.json(), {"detail": "Not Found"})
        self.assertEqual(unknown.headers["content-security-policy"], API_POLICY)
        self.assertEqual(capability.status_code, 401)
        self.assertEqual(capability.json(), {"code": "AUTHENTICATION_REQUIRED"})
        self.assertEqual(capability.headers["content-security-policy"], API_POLICY)

    def test_files_outside_the_export_are_not_served(self) -> None:
        for path in ("/%2e%2e/secret.txt", "/..%2fsecret.txt", "/%2e%2e%2fsecret.txt"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 404)
                self.assertNotIn("outside the export", response.text)

    def test_only_reads_are_served(self) -> None:
        head = self.client.head("/")
        post = self.client.post("/")

        self.assertEqual(head.status_code, 200)
        self.assertEqual(head.content, b"")
        self.assertEqual(post.status_code, 405)

    def test_a_host_that_does_not_name_the_runtime_is_refused(self) -> None:
        response = self.client.get("/", headers={"host": "attacker.example"})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"code": "HOST_NOT_ALLOWED"})

    def test_without_a_web_root_no_page_is_served(self) -> None:
        response = TestClient(self._app()).get("/")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-security-policy"], API_POLICY)

    def test_the_web_root_must_be_a_directory_path(self) -> None:
        for root in ("out", self.root / "index.html"):
            with self.subTest(root=root), self.assertRaises((ValueError, RuntimeError)):
                WebInterface(root)


if __name__ == "__main__":
    unittest.main()
