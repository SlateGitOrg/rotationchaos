"""The chaos scenario catalogue, with expected outcomes written down first.

Writing the expected outcome before building the injector is what turns
"it handled it" into an assertion. Every scenario below states what the mesh
must do, and every one of them is fail-closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .identity import (
    AuthorizationPolicy, CertificateAuthority, Failure, TrustBundle, Workload,
)


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    expected: Failure | None
    # Fail-closed means: when this scenario bites, the request is DENIED.
    # There is no scenario in this catalogue whose correct answer is "allow".
    must_fail_closed: bool = True


CATALOGUE: tuple[Scenario, ...] = (
    Scenario("steady_state", "no failure injected", None, must_fail_closed=False),
    Scenario("ca_outage", "the CA is unreachable while an SVID expires",
             Failure.EXPIRED),
    Scenario("clock_skew_forward", "verifier clock runs 10 minutes fast",
             Failure.EXPIRED),
    Scenario("clock_skew_backward", "verifier clock runs 10 minutes slow",
             Failure.NOT_YET_VALID),
    Scenario("mid_connection_revocation", "svid revoked during an open connection",
             Failure.REVOKED),
    Scenario("untrusted_ca", "workload presents an svid from a foreign CA",
             Failure.UNTRUSTED_CA),
    Scenario("forged_svid", "svid signature does not verify",
             Failure.BAD_SIGNATURE),
    Scenario("no_identity", "workload never received an svid",
             Failure.NO_IDENTITY),
    Scenario("policy_denied", "valid identity, not permitted to call this service",
             Failure.POLICY_DENIED),
)


@dataclass
class RunResult:
    scenario: str
    requests: int = 0
    allowed: int = 0
    denied: int = 0
    rotations: int = 0
    rotation_failures: int = 0
    denial_reasons: dict[str, int] = field(default_factory=dict)
    # A failure injected mid-run does not necessarily bite immediately: under
    # a CA outage the workload keeps serving on its existing, still-valid
    # certificate, and that is correct. What must never happen is a flip back:
    # once the mesh starts denying, it must not silently start allowing again.
    first_denial_at: int | None = None
    allowed_after_first_denial: int = 0

    @property
    def failed_open(self) -> bool:
        """Did any request succeed after denial had already begun?"""
        return self.allowed_after_first_denial > 0

    def record_denial(self, reason: Failure) -> None:
        self.denied += 1
        self.denial_reasons[reason.value] = self.denial_reasons.get(reason.value, 0) + 1


TTL = 60


def run_scenario(scenario: Scenario, *, requests: int = 5_000) -> RunResult:
    """Drive `requests` calls through the mesh under one injected failure."""
    ca = CertificateAuthority("ca-root", b"root-secret-material", ttl_seconds=TTL)
    foreign = CertificateAuthority("ca-foreign", b"someone-elses-ca", ttl_seconds=TTL)
    bundle = TrustBundle({"ca-root": ca})
    policy = AuthorizationPolicy({"spiffe://acme/payments": {"spiffe://acme/api"}})

    caller = Workload("spiffe://acme/api")
    # Scenarios that need a live connection first inject at request 10;
    # everything else is broken from the start.
    inject_at = 10 if scenario.name in {
        "ca_outage", "mid_connection_revocation"} else 0
    result = RunResult(scenario.name)
    skew = 0
    now = 0

    if scenario.name != "no_identity":
        caller.rotate(ca, now)
    if scenario.name == "untrusted_ca":
        caller.svid = foreign.issue(caller.spiffe_id, now)
    if scenario.name == "forged_svid":
        good = ca.issue(caller.spiffe_id, now)
        assert good is not None
        caller.svid = type(good)(
            spiffe_id=good.spiffe_id, ca_id=good.ca_id,
            not_before=good.not_before, not_after=good.not_after,
            serial=good.serial, signature="0" * 32,
        )
    if scenario.name == "clock_skew_forward":
        skew = 600
    if scenario.name == "clock_skew_backward":
        skew = -600

    for i in range(requests):
        now += 1

        if scenario.name == "ca_outage" and i == inject_at:
            ca.available = False
        if scenario.name == "mid_connection_revocation" and i == inject_at:
            if caller.svid is not None:
                ca.revoke(caller.svid.serial)

        # Rotation happens on the normal schedule, independently of the request.
        frozen_identity = scenario.name in {
            "untrusted_ca", "forged_svid", "mid_connection_revocation",
        }
        if not frozen_identity and scenario.name != "no_identity":
            if caller.needs_rotation(now, TTL):
                if caller.rotate(ca, now):
                    result.rotations += 1
                else:
                    result.rotation_failures += 1

        result.requests += 1
        failure = bundle.validate(caller.svid, now, clock_skew=skew)
        if failure is not None:
            if result.first_denial_at is None:
                result.first_denial_at = i
            result.record_denial(failure)
            continue

        callee = "spiffe://acme/payments"
        caller_id = (
            "spiffe://acme/unknown" if scenario.name == "policy_denied"
            else caller.spiffe_id
        )
        if not policy.permits(caller_id, callee):
            if result.first_denial_at is None:
                result.first_denial_at = i
            result.record_denial(Failure.POLICY_DENIED)
            continue

        result.allowed += 1
        if result.first_denial_at is not None:
            result.allowed_after_first_denial += 1

    return result
