"""The 60-second artefact: nine scenarios, every one fails closed.

Run: python -m src.demo
"""

from __future__ import annotations

from .chaos import CATALOGUE, run_scenario


def main() -> None:
    print("\n  ROTATIONCHAOS - 60-second certificates, exercised on purpose")
    print("  " + "-" * 72)

    steady = run_scenario(CATALOGUE[0], requests=50_000)
    print(f"  Steady state: {steady.requests:,} requests, "
          f"{steady.rotations:,} rotations, {steady.denied} failures.")
    print("  Rotation is exercised thousands of times an hour rather than once")
    print("  a year, so the path is boring by the time it matters.\n")

    print(f"  {'scenario':<28}{'requests':>9}{'allowed':>9}{'denied':>8}"
          f"{'first deny':>12}  verdict")
    print("  " + "-" * 72)

    all_closed = True
    for scenario in CATALOGUE:
        result = run_scenario(scenario, requests=500)
        if scenario.must_fail_closed:
            ok = not result.failed_open and result.first_denial_at is not None
            verdict = "FAIL-CLOSED" if ok else "FAILED OPEN"
            all_closed = all_closed and ok
        else:
            verdict = "healthy"
        first = "-" if result.first_denial_at is None else f"#{result.first_denial_at}"
        print(f"  {scenario.name:<28}{result.requests:>9}{result.allowed:>9}"
              f"{result.denied:>8}{first:>12}  {verdict}")

    print()
    for scenario in CATALOGUE:
        if scenario.expected is None:
            continue
        result = run_scenario(scenario, requests=500)
        reasons = ", ".join(f"{k} x{v}" for k, v in result.denial_reasons.items())
        print(f"    {scenario.name:<28} {reasons}")

    print("\n  Note ca_outage: the workload keeps serving for 60 seconds on its")
    print("  existing certificate, then denies. That is correct - and the")
    print("  property under test is that it never flips back to allowing.")
    print("\n  A mesh that fails OPEN under CA outage stays green on every")
    print("  availability dashboard while having silently switched off")
    print("  authentication, which is precisely when someone is inside.\n")
    print(f"  All fail-closed scenarios held: {all_closed}\n")


if __name__ == "__main__":
    main()
