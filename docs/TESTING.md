# Testing Release Sentinel

## Current verified target

```text
Network:              GenLayer StudioNet
Chain ID:             61999
Contract:             0x409818F02f75e8FC7E69620DcFC2669BAE59774b
Deployment tx:        0xca71fd4f26c00ac33f829435e30e39685c3fafd0d588d5f9d7c7d508bc25978e
Source SHA-256:       2357c54602e146398d9eb6540ec7857bb86dd0bfa279c2de05c933431e7cf6c9
Protocol:             release-sentinel.release-notary.v1
Manifest schema:      release-sentinel.manifest.v1
```

## Local checks

```bash
python3 -m py_compile contracts/release_sentinel.py
python3 -m pytest -q
genvm-lint lint contracts/release_sentinel.py --json
shasum -a 256 contracts/release_sentinel.py
```

Confirmed on 2026-10-07: Python compilation succeeded, Pytest reported `6 passed`, GenVM AST lint reported `{"ok":true,"passed":3}`, and the source digest matched the deployment record.

The installed `genvm-lint check` can complete AST lint, but its SDK semantic phase references a missing SDK archive in the local linter cache. The same cache failure occurs for established contracts using this dependency header. StudioNet successfully loaded, deployed, and executed the final source under validator consensus, providing the runtime semantic verification used here.

## Read-only live verification

```bash
ADDRESS=0x409818F02f75e8FC7E69620DcFC2669BAE59774b

genlayer call "$ADDRESS" get_protocol_identity
genlayer call "$ADDRESS" get_voyage --args 1
genlayer call "$ADDRESS" get_observation --args 1 1 release-home
genlayer call "$ADDRESS" get_notarization --args 1
genlayer call "$ADDRESS" get_voyage --args 2
genlayer call "$ADDRESS" get_observation --args 2 1 release-home
genlayer call "$ADDRESS" get_voyage --args 3
genlayer call "$ADDRESS" get_observation --args 3 1 release-home
```

Expected states: Voyage 1 is `NOTARIZED`, generation 1, with no open dispute. Voyages 2 and 3 are `UNCERTAIN` with no review deadline. Voyage 3 has `identity_ok=false` in its observation.

## Real public evidence

Baseline resources:

- Route: `https://harbor-light-app.vercel.app/demo/release`
- Route index: `https://harbor-light-app.vercel.app/.well-known/harborlight-routes.json`
- Capsule: `https://harbor-light-app.vercel.app/demo/baseline-capsule.json`
- Route-index digest: `3d69b859ee289812ab9223d8a3d014a0beaf16efec9f07871243f328f95b84a0`
- Capsule digest: `90e45abe631be2222e2685854eeafe865cc2c16fdeb377f66b7e7496f5eb37bf`

Candidate resources:

- `https://release-sentinel-clear-20261007.vercel.app/demo/release`
- `https://release-sentinel-held-20261007.vercel.app/demo/release`
- `https://release-sentinel-uncertain-20261007.vercel.app/demo/release`

Each candidate exposes `/.well-known/release-sentinel.json` on the same origin. The fixtures were deployed as independent Vercel projects with fixed production aliases.

The baseline hostname reflects the provenance of the pre-existing evidence page used for the live test. It is external evidence only; it is not the contract name, protocol, schema, class, candidate identity, or manifest endpoint.

## E2E coverage

Every scenario executed `open_voyage` → `discover_chart` → `add_route` → `anchor_baseline` → `seal_chart` → `bind_candidate` → `observe_route` → `derive_readiness`.

Voyage 1 additionally waited the full 600-second review period and executed `notarize`, causing another manifest and route fetch. Voyage 2 exercised a second bounded observation after strict-schema rejection. Voyage 3 exercised the pre-semantic identity gate with an incorrect body commitment.

No mock web server, local chain, `.test` hostname, placeholder body, forced model response, or fabricated receipt was used. Full results are in [`LIVE_TEST_REPORT.md`](LIVE_TEST_REPORT.md).

## Creating a new live voyage

Host immutable baseline evidence and a candidate manifest, compute canonical JSON digests locally, and keep the served bytes stable throughout consensus. `add_route` accepts custom rules as a native array:

```bash
genlayer write "$ADDRESS" add_route --args \
  4 release-home /service/release \
  '[{"id":"service-sla","question":"Does the release retain the published availability and response-time obligations?","allowed_changes":"Formatting may change; numerical obligations may not be weakened."}]'
```

Do not serialize that array inside another string. Live testing found that client-integration mismatch in the initial draft; the final deployed API uses a native `list` and was successfully exercised in all three voyages.
