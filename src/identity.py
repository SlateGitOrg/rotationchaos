"""Workload identity with sub-minute certificate lifetimes.

THE DIFFERENTIATOR LIVES HERE.

Teams adopt mTLS, everything works, and fourteen months later a certificate
expires at 3am and half the estate cannot talk to the other half. The rotation
path was never exercised, because certificates were long-lived and nobody waited
a year to test them. The outage is the first integration test.

So this lab runs SVIDs with a 60-second TTL and injects failures mid-request.
Rotation is exercised thousands of times an hour rather than once a year, and
every failure mode is asserted to FAIL CLOSED.

Fail-closed is the whole safety argument. A mesh that fails open under CA
outage stays available, passes every availability test, and has silently
removed your authentication for the duration of the incident - which is exactly
when someone is most likely to be inside your network.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum


class Failure(str, Enum):
    EXPIRED = "svid expired"
    NOT_YET_VALID = "svid not yet valid"
    UNTRUSTED_CA = "issuing CA is not in the trust bundle"
    REVOKED = "svid revoked"
    BAD_SIGNATURE = "svid signature invalid"
    NO_IDENTITY = "workload has no svid"
    POLICY_DENIED = "spiffe id not permitted by policy"


@dataclass(frozen=True)
class SVID:
    """A SPIFFE Verifiable Identity Document."""

    spiffe_id: str
    ca_id: str
    not_before: int
    not_after: int
    serial: int
    signature: str

    def ttl_at(self, now: int) -> int:
        return self.not_after - now


class CertificateAuthority:
    def __init__(self, ca_id: str, secret: bytes, ttl_seconds: int = 60) -> None:
        self.ca_id = ca_id
        self._secret = secret
        self.ttl = ttl_seconds
        self._serial = 0
        self.available = True
        self.revoked: set[int] = set()
        self.issued_count = 0

    def _sign(self, spiffe_id: str, nb: int, na: int, serial: int) -> str:
        msg = f"{spiffe_id}|{nb}|{na}|{serial}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()[:32]

    def issue(self, spiffe_id: str, now: int) -> SVID | None:
        """Issue an SVID, or None when the CA is unavailable.

        Returning None rather than raising is deliberate: the caller must make
        an explicit decision about what to do with no identity, and the
        temptation in that branch is exactly where fail-open creeps in.
        """
        if not self.available:
            return None
        self._serial += 1
        self.issued_count += 1
        nb, na = now, now + self.ttl
        return SVID(
            spiffe_id=spiffe_id, ca_id=self.ca_id, not_before=nb, not_after=na,
            serial=self._serial,
            signature=self._sign(spiffe_id, nb, na, self._serial),
        )

    def verify_signature(self, svid: SVID) -> bool:
        expected = self._sign(
            svid.spiffe_id, svid.not_before, svid.not_after, svid.serial)
        return hmac.compare_digest(expected, svid.signature)

    def revoke(self, serial: int) -> None:
        self.revoked.add(serial)


class TrustBundle:
    def __init__(self, authorities: dict[str, CertificateAuthority]) -> None:
        self.authorities = authorities

    def validate(self, svid: SVID | None, now: int, *, clock_skew: int = 0) -> (
        Failure | None
    ):
        """Return the failure, or None when the SVID is good.

        `clock_skew` models the verifier's clock being wrong, which is how a
        perfectly valid certificate gets rejected across a fleet at once.
        """
        if svid is None:
            return Failure.NO_IDENTITY

        ca = self.authorities.get(svid.ca_id)
        if ca is None:
            return Failure.UNTRUSTED_CA
        if not ca.verify_signature(svid):
            return Failure.BAD_SIGNATURE
        if svid.serial in ca.revoked:
            return Failure.REVOKED

        observed = now + clock_skew
        if observed < svid.not_before:
            return Failure.NOT_YET_VALID
        if observed >= svid.not_after:
            return Failure.EXPIRED
        return None


@dataclass
class Workload:
    spiffe_id: str
    svid: SVID | None = None
    # Rotate when this fraction of the TTL remains. Too small and every
    # workload rotates simultaneously the moment the CA blinks.
    rotate_at_fraction: float = 0.5

    def needs_rotation(self, now: int, ttl: int) -> bool:
        if self.svid is None:
            return True
        return self.svid.ttl_at(now) <= ttl * self.rotate_at_fraction

    def rotate(self, ca: CertificateAuthority, now: int) -> bool:
        """Attempt rotation. Keeps the existing SVID on failure.

        Discarding the current identity before the new one arrives turns a
        transient CA blip into a guaranteed outage - the bug that makes short
        TTLs feel dangerous when the real problem is the rotation logic.
        """
        fresh = ca.issue(self.spiffe_id, now)
        if fresh is None:
            return False
        self.svid = fresh
        return True


class AuthorizationPolicy:
    """Authorisation keyed on SPIFFE ID, not on network position."""

    def __init__(self, allowed: dict[str, set[str]]) -> None:
        self.allowed = allowed

    def permits(self, caller: str, callee: str) -> bool:
        return caller in self.allowed.get(callee, set())
