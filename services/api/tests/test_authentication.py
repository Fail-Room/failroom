import hashlib
import unittest
from datetime import UTC, datetime

from failroom_state import UserIdentity

from failroom_api.authentication import (
    AuthenticationError,
    BearerCredential,
    BearerIdentityVerifier,
)


class BearerIdentityVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = UserIdentity("user-1", frozenset({"room-1"}))
        self.now = datetime(2026, 9, 9, tzinfo=UTC)
        self.token = "local-token-with-at-least-32-bytes-0001"
        self.verifier = BearerIdentityVerifier(
            {
                hashlib.sha256(
                    self.token.encode("ascii")
                ).hexdigest(): BearerCredential(
                    self.identity,
                    self.now.replace(hour=1),
                )
            },
            now=lambda: self.now,
        )

    def test_verifies_bearer_token(self) -> None:
        self.assertEqual(self.verifier.verify("Bearer " + self.token), self.identity)

    def test_rejects_malformed_or_unknown_header(self) -> None:
        for header in ("", "Basic value", "Bearer", "Bearer wrong"):
            with self.assertRaises(AuthenticationError) as raised:
                self.verifier.verify(header)
            self.assertEqual(raised.exception.code, "AUTHENTICATION_REQUIRED")

    def test_rejects_empty_configuration(self) -> None:
        with self.assertRaises(AuthenticationError) as raised:
            BearerIdentityVerifier({}, now=lambda: self.now)
        self.assertEqual(raised.exception.code, "INVALID_CONFIGURATION")

    def test_rejects_expired_identity_token(self) -> None:
        verifier = BearerIdentityVerifier(
            {
                hashlib.sha256(
                    self.token.encode("ascii")
                ).hexdigest(): BearerCredential(
                    self.identity,
                    datetime(2026, 9, 9, 12, 0, 30, tzinfo=UTC),
                )
            },
            now=lambda: datetime(2026, 9, 9, 12, 1, tzinfo=UTC),
        )
        with self.assertRaises(AuthenticationError) as raised:
            verifier.verify("Bearer " + self.token)
        self.assertEqual(raised.exception.code, "AUTHENTICATION_EXPIRED")


if __name__ == "__main__":
    unittest.main()
