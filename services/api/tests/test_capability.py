import hashlib
import unittest
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from failroom_state import CapabilityClaims, ResourceRef

from failroom_api.capability import CapabilityCodec, CapabilityError


class CapabilityCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 9, 12, tzinfo=UTC)
        self.claims = CapabilityClaims(
            uuid4().hex,
            "alice",
            ResourceRef("attempt-1", "sandbox-1", 2),
            4,
            self.now + timedelta(seconds=30),
            "terminal:attach",
        )
        self.codec = CapabilityCodec(
            b"k" * 32,
            max_lifetime=timedelta(seconds=60),
        )

    def test_issue_and_verify_round_trip_returns_verified_claims(self):
        token = self.codec.issue(self.claims, now=lambda: self.now)

        verified = self.codec.verify(token, now=lambda: self.now)

        self.assertEqual(verified, self.claims)

    def test_tampered_signature_is_rejected_without_claim_parsing(self):
        token = self.codec.issue(self.claims, now=lambda: self.now)
        parts = token.split(".")
        signature = ("a" if parts[2][0] != "a" else "b") + parts[2][1:]
        tampered = ".".join((parts[0], parts[1], signature))

        with self.assertRaises(CapabilityError) as caught:
            self.codec.verify(tampered, now=lambda: self.now)
        self.assertEqual(caught.exception.code, "CAPABILITY_INVALID")

    def test_expired_or_overlong_claims_are_rejected(self):
        expired = CapabilityClaims(
            self.claims.jti,
            self.claims.user_id,
            self.claims.ref,
            self.claims.session_epoch,
            self.now,
            self.claims.scope,
        )
        with self.assertRaises(CapabilityError) as caught:
            self.codec.issue(expired, now=lambda: self.now)
        self.assertEqual(caught.exception.code, "CAPABILITY_EXPIRED")

        overlong = CapabilityClaims(
            uuid4().hex,
            self.claims.user_id,
            self.claims.ref,
            self.claims.session_epoch,
            self.now + timedelta(seconds=61),
            self.claims.scope,
        )
        with self.assertRaises(CapabilityError) as caught:
            self.codec.issue(overlong, now=lambda: self.now)
        self.assertEqual(caught.exception.code, "CAPABILITY_LIFETIME")

    def test_codec_requires_a_private_key_and_rejects_wrong_scope(self):
        with self.assertRaises(CapabilityError) as caught:
            CapabilityCodec(b"short", max_lifetime=timedelta(seconds=60))
        self.assertEqual(caught.exception.code, "INVALID_CONFIGURATION")

        wrong_scope = CapabilityClaims(
            uuid4().hex,
            self.claims.user_id,
            self.claims.ref,
            self.claims.session_epoch,
            self.claims.expires_at,
            "room:inspect",
        )
        with self.assertRaises(CapabilityError) as caught:
            self.codec.issue(wrong_scope, now=lambda: self.now)
        self.assertEqual(caught.exception.code, "CAPABILITY_SCOPE")

    def test_signature_is_not_a_raw_claim_or_secret(self):
        token = self.codec.issue(self.claims, now=lambda: self.now)

        self.assertNotIn(self.claims.user_id, token.split(".")[2])
        self.assertNotIn(hashlib.sha256(b"k" * 32).hexdigest(), token)
        self.assertLessEqual(len(token), 4096)


if __name__ == "__main__":
    unittest.main()
