# Release Sentinel

Release Sentinel is a standalone GenLayer Intelligent Contract that notarizes public web releases from independently fetched evidence. It binds a release to a public route chart, authenticates baseline capsules, compares live candidate pages under validator consensus, provides a bounded dispute window, and creates a freshness seal only after re-fetching every committed byte.

## Verified StudioNet deployment

| Field | Verified value |
|---|---|
| Network | GenLayer StudioNet |
| Chain ID | `61999` |
| Contract | `0x409818F02f75e8FC7E69620DcFC2669BAE59774b` |
| Deployment transaction | `0xca71fd4f26c00ac33f829435e30e39685c3fafd0d588d5f9d7c7d508bc25978e` |
| Deployment consensus | `MAJORITY_AGREE` |
| Protocol | `release-sentinel.release-notary.v1` |
| Manifest schema | `release-sentinel.manifest.v1` |
| Source SHA-256 | `2357c54602e146398d9eb6540ec7857bb86dd0bfa279c2de05c933431e7cf6c9` |
| Deployment date | 2026-10-07 |

The deployment record is stored in [`proof/deployment.json`](proof/deployment.json). Three completed live scenarios and their transaction evidence are documented in [`docs/LIVE_TEST_REPORT.md`](docs/LIVE_TEST_REPORT.md).

## What the contract verifies

- Route indexes, manifests, baseline capsules, response bodies, observations, and final seals use SHA-256 commitments.
- The manifest is origin-bound and must enumerate exactly the registered route set.
- Candidate response bytes must match the manifest before an LLM can produce semantic findings.
- Every nondeterministic leader result is independently recomputed by validators.
- Only closed finding statuses affect readiness: `PRESERVED`, `ALLOWED_CHANGE`, `MATERIAL_CHANGE`, `MISSING`, `BROKEN`, `CONFLICTING`, or `UNREADABLE`.
- Incomplete or off-schema model output fails closed as `UNCERTAIN`.
- A final notarization is impossible until the public review window has elapsed and a fresh fetch confirms the manifest, route bytes, and prior clear observations still agree.

## Mandatory release policy

| Rule | Requirement |
|---|---|
| `rs-security` | No newly introduced credential collection, unsafe form destination, mixed-origin identity, or deceptive security claim. |
| `rs-function` | Primary actions, forms, and destination links remain available and semantically equivalent. |
| `rs-claims` | Material promises, eligibility terms, prices, and obligations remain preserved or are clearly disclosed as changed. |
| `rs-access` | Headings, labels, and navigation preserve a usable and understandable journey. |

Up to ten additional rules can be supplied to `add_route` as a native list of `{id, question, allowed_changes}` objects.

## Lifecycle

1. `open_voyage` fixes the baseline origin, route-index URL, title, owner, and a review window between 600 and 604,800 seconds.
2. `discover_chart` fetches the public index and requires its canonical JSON digest to match the caller’s commitment.
3. `add_route` registers discovered routes and combines mandatory rules with optional project-specific rules.
4. `anchor_baseline` fetches the baseline capsule and live route, then asks validators whether the capsule faithfully represents what was observed.
5. `seal_chart` closes registration only after every critical route is covered and every registered baseline is frozen.
6. `bind_candidate` fetches `/.well-known/release-sentinel.json`, validates its identity and route coverage, and starts a new observation generation.
7. `observe_route` verifies manifest and body identity before producing bounded semantic findings. Attempts are capped at five per route and generation.
8. `derive_readiness` deterministically aggregates route results into `CLEAR`, `HELD`, or `UNCERTAIN`.
9. During a `CLEAR` review window, a non-owner can call `open_dispute` with public counter-evidence. Disputes are capped at four per generation and must be resolved by a fresh observation.
10. `notarize` runs only after the review deadline, re-fetches every route, verifies all commitments again, and stores a final freshness root and notarization digest.

```text
DRAFT → CHARTED → OBSERVING → CLEAR → NOTARIZED
                         ├──→ HELD
                         ├──→ UNCERTAIN
                         └──→ DISPUTED → OBSERVING
```

`HELD` and `UNCERTAIN` never receive a review deadline and cannot be notarized. Binding a corrected candidate starts a new generation and returns the voyage to `OBSERVING`.

## Candidate manifest

The candidate origin must serve `/.well-known/release-sentinel.json`:

```json
{
  "schema": "release-sentinel.manifest.v1",
  "protocol_id": "release-sentinel.release-notary.v1",
  "candidate_origin": "https://release.example",
  "release_ref": "release-2026-10-07.1",
  "route_index_digest": "3d69b859ee289812ab9223d8a3d014a0beaf16efec9f07871243f328f95b84a0",
  "routes": [
    {
      "path": "/service/release",
      "body_sha256": "e26988055742b8c274fc3394c61eea932cf86d60ca353251db370fc9ed228e46"
    }
  ]
}
```

JSON commitments use UTF-8 encoding, lexicographically sorted keys, and compact `,` / `:` separators. Route body commitments hash the exact HTTP response bytes.

## Public API

Write methods: `open_voyage`, `discover_chart`, `add_route`, `anchor_baseline`, `seal_chart`, `bind_candidate`, `observe_route`, `derive_readiness`, `open_dispute`, and `notarize`.

Read methods: `get_protocol_identity`, `get_voyage`, `get_route`, `get_observation`, `get_dispute`, `get_notarization`, `list_voyages`, and `get_events`.

## Confirmed live outcomes

| Voyage | Candidate | Result | Evidence |
|---|---|---|---|
| 1 | Preserved security, accessibility, navigation, and public commitments | `NOTARIZED` | All four rules `PRESERVED`; notarization digest `1a27ba70…b617df` |
| 2 | Password and recovery-phrase collection sent to an unsafe form target | `UNCERTAIN` | Strict output validation rejected incomplete findings; release failed closed |
| 3 | Available detailed page whose bytes contradicted its manifest commitment | `UNCERTAIN` | `identity_ok=false`; actual SHA-256 `76baa5f0…0b36a4` |

Voyage 1’s freshness root is `ff4cf377b500b83b6af6dba71d41272190ba04b5ee124fc2c8e8926b5896e1a8`. Complete observations and full transaction hashes are in the live report.

## Repository layout

```text
contracts/release_sentinel.py       Intelligent Contract source
tests/static/test_release_sentinel.py
fixtures/api/fixture.js             Public live-test fixture implementation
fixtures/vercel.json                Fixture deployment routing
docs/TESTING.md                     Reproduction and verification commands
docs/LIVE_TEST_REPORT.md            StudioNet evidence and outcomes
proof/deployment.json               Deployment identity record
gltest.config.yaml                  StudioNet project configuration
```

## Local verification

```bash
python3 -m py_compile contracts/release_sentinel.py
python3 -m pytest -q
genvm-lint lint contracts/release_sentinel.py --json
```

Confirmed on 2026-10-07: 6 tests passed and all 3 GenVM AST checks passed.
