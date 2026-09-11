"""Rotation must be boring, and every failure must be closed."""

from __future__ import annotations

import unittest

from src.chaos import CATALOGUE, TTL, run_scenario
from src.identity import (
    AuthorizationPolicy, CertificateAuthority, Failure, TrustBundle, Workload,
)


def scenario(name: str):
    return next(s for s in CATALOGUE if s.name == name)


class TestSteadyState(unittest.TestCase):
    def test_50000_rotations_with_zero_failed_requests(self):
        """The headline. Short TTLs are only safe if rotation is boring."""
        result = run_scenario(scenario("steady_state"), requests=50_000)
        self.assertEqual(result.denied, 0,
                         f"denials under steady state: {result.denial_reasons}")
        self.assertEqual(result.allowed, 50_000)
        self.assertGreater(result.rotations, 1_000,
                           "the rotation path must actually be exercised")
        self.assertEqual(result.rotation_failures, 0)

    def test_rotation_happens_well_before_expiry(self):
        ca = CertificateAuthority("ca-root", b"s", ttl_seconds=TTL)
        w = Workload("spiffe://acme/api")
        w.rotate(ca, 0)
        self.assertFalse(w.needs_rotation(1, TTL))
        self.assertTrue(w.needs_rotation(TTL // 2, TTL),
                        "waiting until expiry leaves no margin for a CA blip")


class TestEveryScenarioFailsClosed(unittest.TestCase):
    """The assertion that separates this from an availability test."""

    def test_all_failure_scenarios_deny(self):
        for s in CATALOGUE:
            if not s.must_fail_closed:
                continue
            with self.subTest(scenario=s.name):
                result = run_scenario(s, requests=500)
                self.assertFalse(
                    result.failed_open,
                    f"{s.name} FAILED OPEN: {result.allowed} requests were "
                    f"allowed that should have been denied",
                )
                self.assertIsNotNone(
                    result.first_denial_at,
                    f"{s.name} never denied anything - the failure was not "
                    f"actually injected")

    def test_each_scenario_produces_the_documented_reason(self):
        for s in CATALOGUE:
            if s.expected is None:
                continue
            with self.subTest(scenario=s.name):
                result = run_scenario(s, requests=500)
                self.assertIn(
                    s.expected.value, result.denial_reasons,
                    f"{s.name} denied for the wrong reason: "
                    f"{result.denial_reasons}",
                )

    def test_CA_OUTAGE_IS_THE_ONE_THAT_MATTERS(self):
        """A naive implementation fails open here and passes every uptime test."""
        result = run_scenario(scenario("ca_outage"), requests=1_000)
        self.assertFalse(result.failed_open)
        self.assertGreater(result.rotation_failures, 0,
                           "the CA outage must actually have blocked rotation")
        self.assertIn(Failure.EXPIRED.value, result.denial_reasons)


class TestValidation(unittest.TestCase):
    def setUp(self):
        self.ca = CertificateAuthority("ca-root", b"secret", ttl_seconds=TTL)
        self.bundle = TrustBundle({"ca-root": self.ca})

    def test_a_good_svid_validates(self):
        svid = self.ca.issue("spiffe://acme/api", 100)
        self.assertIsNone(self.bundle.validate(svid, 110))

    def test_expiry_is_exclusive_at_the_boundary(self):
        svid = self.ca.issue("spiffe://acme/api", 100)
        assert svid is not None
        self.assertIsNone(self.bundle.validate(svid, svid.not_after - 1))
        self.assertEqual(
            self.bundle.validate(svid, svid.not_after), Failure.EXPIRED)

    def test_not_yet_valid_is_distinguished_from_expired(self):
        svid = self.ca.issue("spiffe://acme/api", 100)
        assert svid is not None
        self.assertEqual(
            self.bundle.validate(svid, 100, clock_skew=-600),
            Failure.NOT_YET_VALID,
            "reporting a clock-skew failure as EXPIRED sends the on-call "
            "engineer to the wrong system",
        )

    def test_missing_identity_is_a_named_failure_not_a_crash(self):
        self.assertEqual(self.bundle.validate(None, 100), Failure.NO_IDENTITY)

    def test_a_foreign_ca_is_rejected_before_signature_checking(self):
        foreign = CertificateAuthority("ca-foreign", b"other", ttl_seconds=TTL)
        svid = foreign.issue("spiffe://acme/api", 100)
        self.assertEqual(self.bundle.validate(svid, 110), Failure.UNTRUSTED_CA)

    def test_revocation_takes_effect_immediately(self):
        svid = self.ca.issue("spiffe://acme/api", 100)
        assert svid is not None
        self.assertIsNone(self.bundle.validate(svid, 110))
        self.ca.revoke(svid.serial)
        self.assertEqual(self.bundle.validate(svid, 110), Failure.REVOKED)


class TestRotationRobustness(unittest.TestCase):
    def test_a_failed_rotation_keeps_the_current_identity(self):
        """Discarding the old SVID before the new one arrives turns a blip
        into a guaranteed outage."""
        ca = CertificateAuthority("ca-root", b"s", ttl_seconds=TTL)
        w = Workload("spiffe://acme/api")
        w.rotate(ca, 0)
        original = w.svid

        ca.available = False
        self.assertFalse(w.rotate(ca, 10))
        self.assertIs(w.svid, original, "the existing identity must survive")

    def test_identity_recovers_once_the_ca_returns(self):
        ca = CertificateAuthority("ca-root", b"s", ttl_seconds=TTL)
        bundle = TrustBundle({"ca-root": ca})
        w = Workload("spiffe://acme/api")
        w.rotate(ca, 0)

        ca.available = False
        self.assertFalse(w.rotate(ca, 40))
        self.assertEqual(bundle.validate(w.svid, 120), Failure.EXPIRED)

        ca.available = True
        self.assertTrue(w.rotate(ca, 120))
        self.assertIsNone(bundle.validate(w.svid, 130),
                          "recovery must be automatic, not a page")


class TestAuthorization(unittest.TestCase):
    def test_authorization_is_keyed_on_identity_not_network_position(self):
        policy = AuthorizationPolicy(
            {"spiffe://acme/payments": {"spiffe://acme/api"}})
        self.assertTrue(policy.permits("spiffe://acme/api", "spiffe://acme/payments"))
        self.assertFalse(
            policy.permits("spiffe://acme/batch", "spiffe://acme/payments"))

    def test_an_unlisted_callee_denies_by_default(self):
        policy = AuthorizationPolicy({})
        self.assertFalse(policy.permits("spiffe://acme/api", "spiffe://acme/anything"))


if __name__ == "__main__":
    unittest.main()
