# rotationchaos

> Workload identity with 60-second certificates and injected rotation failures - so the rotation path is exercised thousands of times, not once a year.

`FLAGSHIP` · **Cybersecurity** · Expert · ~5 weeks · Energy - SCADA-adjacent microservice estate

**Primary language:** Go
**Tags:** `mtls`, `spiffe`, `workload-identity`, `chaos-engineering`, `kubernetes`, `zero-trust`

---

> **Implementation note.** The catalogue specifies **Go** for this
> project and that remains the target. This repository ships a runnable
> **Python** reference implementation of the core differentiator so the
> behaviour is executable and tested today; port it to Go as step one
> of your own build.

## The problem

Teams adopt mTLS and workload identity, everything works, and then fourteen months later a certificate expires at three in the morning and half the estate cannot talk to the other half. The rotation logic was never exercised, because certificates were long-lived and nobody waited a year to test them. The outage is the first integration test.

## ⭐ The differentiator

Deliberately runs **sub-60-second certificate lifetimes and injects rotation failures mid-request** - clock skew, CA unavailability, revocation during an open connection, partial rollout - so the rotation path is exercised thousands of times per hour instead of once a year. A generic mTLS lab issues year-long certificates and proves only that the happy path works, which was never in doubt.

This is the sentence to lead with when someone asks you to walk through the
project. Everything else in this repo exists to make it true and to prove it.

## Data

A self-contained lab: SPIRE (open source) issuing SVIDs to containerised workloads on kind, plus a **documented chaos scenario catalogue** with the expected outcome for each scenario - so 'it handled it' is a specific assertion, not an impression.

> No paid API key is required to run or demo this project. Where a paid
> service would add value it is wired as an optional enhancement behind an
> interface with an offline mock as the default implementation.

## Stack

- Go
- SPIFFE / SPIRE for workload identity
- Envoy as the sidecar
- Kubernetes via kind (runs on a laptop)
- Prometheus, Docker, CI

## Core capabilities

- Workload identity issuance with node and workload attestation, sub-minute SVID TTLs
- Chaos injector: CA outage, clock skew, mid-connection revocation, partial rollout, expired bundle
- Connection-level observability that distinguishes a rotation failure from an application error
- Authorisation policy keyed on SPIFFE ID with a negative test matrix
- Automated rotation-failure blast-radius report

## Repository layout

```
lab/kind/
cmd/chaos/
internal/identity/
internal/policy/
test/
docs/
```

## Build plan

1. Get SPIRE issuing to two workloads on kind. Then immediately drop the TTL to 60 seconds.
2. Write the scenario catalogue with expected outcomes before building the injector.
3. Injector, then observability that tells rotation failure apart from app error - that distinction is the operability story.
4. Blast-radius reporting last.

## Testing strategy

Assert **zero failed requests across 50,000 rotations** under normal conditions. Then assert each chaos scenario produces the documented, *graceful* outcome - specifically that every failure is **fail-closed**. A rotation system that fails open under CA outage passes a naive availability test and has silently removed your authentication.

Tests assert **correctness**, not merely that the code runs. A green suite on
this repo is a claim about behaviour under adversarial conditions; treat any
test that would pass against a deliberately broken implementation as a bug in
the test.

## Quality & safety layer

Every failure mode is asserted to fail closed. docs/threat-model.md records what an attacker gains from each injected condition and why fail-closed is the correct trade here.

## Measurable outcome

> 50,000 certificate rotations with zero request failures, and all nine chaos scenarios fail closed - including CA outage, which a naive implementation fails open on.

State it in these terms — business units, not technical ones — in your CV
bullet and in the first thirty seconds of describing the project.

## Interview questions this project answers

- **What happens to your service mesh when the CA is unavailable?**
- **Fail-open or fail-closed, and who decides?**
- **How does workload attestation differ from a shared secret?**

## What this deliberately is *not*

- Not a production mesh. It is a lab that answers one question honestly.
- Not a SPIRE tutorial - the chaos catalogue is the contribution.


## Run it now

```bash
python -m unittest discover -s tests -v   # the suite
python -m src.demo                        # the 60-second artefact
```

Requires Python 3.11+. The runnable core uses **only the standard
library** (including `sqlite3`), so there is nothing to install.

## Getting started

```bash
git clone <your-fork-url> rotationchaos
cd rotationchaos
make kind-up                  # local cluster + SPIRE
make deploy-workloads
make chaos SCENARIO=ca-outage
make test                     # 50k rotations + 9 scenarios
```

Docker is supported but optional — every path above works on a plain
Windows/macOS/Linux laptop without a cloud account.

## Definition of done

- [ ] The differentiator above is implemented, and a test proves it
- [ ] The measurable outcome is produced by a command anyone can run
- [ ] `README` explains the one decision a generic version gets wrong
- [ ] CI runs the full suite on every push and is green on `main`
- [ ] A recruiter can see the headline artefact in under 60 seconds

## Licence

MIT — see [LICENSE](LICENSE).
