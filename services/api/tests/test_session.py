import unittest
from datetime import UTC, datetime, timedelta

from failroom_state import UserIdentity

from failroom_api.authentication import AuthenticationError
from failroom_api.session import BrowserSessionAuthority


class BrowserSessionAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 10, 19, 12, tzinfo=UTC)
        self.identity = UserIdentity("user-1", frozenset({"disk-full"}))
        self.credential_expires_at = self.now + timedelta(hours=2)
        self.sessions = BrowserSessionAuthority(
            lifetime=timedelta(minutes=30), max_sessions=2, now=lambda: self.now
        )

    def open(self):
        return self.sessions.open(
            self.identity, credential_expires_at=self.credential_expires_at
        )

    def assertCode(self, code: str, call, *args) -> None:
        with self.assertRaises(AuthenticationError) as raised:
            call(*args)
        self.assertEqual(raised.exception.code, code)

    def test_an_open_session_verifies_as_its_identity(self) -> None:
        issued = self.open()

        self.assertRegex(issued.token, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(issued.expires_at, self.now + timedelta(minutes=30))
        self.assertEqual(issued.lifetime_seconds, 1800)
        self.assertEqual(self.sessions.verify(issued.token), self.identity)
        self.assertNotEqual(self.open().token, issued.token)

    def test_a_session_never_outlives_its_credential(self) -> None:
        self.credential_expires_at = self.now + timedelta(minutes=5)
        issued = self.open()

        self.assertEqual(issued.expires_at, self.credential_expires_at)
        self.assertEqual(issued.lifetime_seconds, 300)
        self.credential_expires_at = self.now
        self.assertCode("AUTHENTICATION_EXPIRED", self.open)

    def test_an_expired_session_ends(self) -> None:
        issued = self.open()
        self.now += timedelta(minutes=30)

        self.assertCode("AUTHENTICATION_EXPIRED", self.sessions.verify, issued.token)
        self.assertCode("AUTHENTICATION_REQUIRED", self.sessions.verify, issued.token)

    def test_close_ends_a_session_and_repeats_safely(self) -> None:
        issued = self.open()

        self.sessions.close(issued.token)
        self.sessions.close(issued.token)
        self.sessions.close("not a token")

        self.assertCode("AUTHENTICATION_REQUIRED", self.sessions.verify, issued.token)

    def test_only_token_digests_are_kept(self) -> None:
        issued = self.open()

        self.assertNotIn(issued.token, repr(vars(self.sessions)))

    def test_opening_beyond_the_bound_ends_the_session_that_expires_first(
        self,
    ) -> None:
        first = self.open()
        self.now += timedelta(minutes=1)
        second = self.open()
        self.now += timedelta(minutes=1)
        third = self.open()

        self.assertCode("AUTHENTICATION_REQUIRED", self.sessions.verify, first.token)
        self.assertEqual(self.sessions.verify(second.token), self.identity)
        self.assertEqual(self.sessions.verify(third.token), self.identity)

    def test_unknown_or_malformed_tokens_are_refused(self) -> None:
        self.open()
        for token in ("", "a" * 42, "a" * 44, "a" * 42 + "=", "a" * 43, None):
            with self.subTest(token=token):
                self.assertCode("AUTHENTICATION_REQUIRED", self.sessions.verify, token)

    def test_configuration_is_explicit_and_bounded(self) -> None:
        for lifetime, bound, clock in (
            (timedelta(seconds=59), 2, lambda: self.now),
            (timedelta(hours=12, seconds=1), 2, lambda: self.now),
            (1800, 2, lambda: self.now),
            (timedelta(minutes=30), 0, lambda: self.now),
            (timedelta(minutes=30), 65, lambda: self.now),
            (timedelta(minutes=30), 2, None),
        ):
            with (
                self.subTest(lifetime=lifetime, bound=bound),
                self.assertRaises(AuthenticationError) as raised,
            ):
                BrowserSessionAuthority(
                    lifetime=lifetime, max_sessions=bound, now=clock
                )
            self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")
        self.assertCode(
            "INVALID_CONFIGURATION",
            lambda: self.sessions.open(
                self.identity, credential_expires_at=datetime(2026, 10, 19, 13)
            ),
        )

    def test_an_untrusted_clock_refuses(self) -> None:
        sessions = BrowserSessionAuthority(
            lifetime=timedelta(minutes=30),
            max_sessions=2,
            now=lambda: datetime(2026, 10, 19, 12),
        )
        self.assertCode(
            "AUTHENTICATION_REQUIRED",
            lambda: sessions.open(
                self.identity, credential_expires_at=self.credential_expires_at
            ),
        )


if __name__ == "__main__":
    unittest.main()
