# Release Sentinel StudioNet live test report

## Deployment identity

| Field | Value |
|---|---|
| Test date | 2026-10-07 |
| Network / chain | GenLayer StudioNet / `61999` |
| Final contract | `0x409818F02f75e8FC7E69620DcFC2669BAE59774b` |
| Deployment transaction | `0xca71fd4f26c00ac33f829435e30e39685c3fafd0d588d5f9d7c7d508bc25978e` |
| Deployment result | `MAJORITY_AGREE` / `ACCEPTED` |
| Deployer | `0x8d4e752ae688c21ec7c7d4d8a232b5e0700dbf0f` |
| Protocol / version | `release-sentinel.release-notary.v1` / 1 |
| Manifest schema | `release-sentinel.manifest.v1` |
| Source SHA-256 | `2357c54602e146398d9eb6540ec7857bb86dd0bfa279c2de05c933431e7cf6c9` |

The deployed identity returned mandatory rules `rs-security`, `rs-function`, `rs-claims`, and `rs-access`.

## Evidence provenance

Validators used the live baseline route `https://harbor-light-app.vercel.app/demo/release`, route index `https://harbor-light-app.vercel.app/.well-known/harborlight-routes.json`, and capsule `https://harbor-light-app.vercel.app/demo/baseline-capsule.json`.

The index committed critical path `/demo/release` and canonical digest `3d69b859ee289812ab9223d8a3d014a0beaf16efec9f07871243f328f95b84a0`. The capsule digest was `90e45abe631be2222e2685854eeafe865cc2c16fdeb377f66b7e7496f5eb37bf`.

The legacy word in that external hostname and historical baseline statement records evidence provenance. The contract source, class, protocol, schema, rule IDs, candidate manifests, and endpoint all use Release Sentinel.

Three independent Vercel projects served candidate evidence. No local server, mock response, `.test` domain, placeholder body, forced LLM result, or fabricated receipt was used.

## Voyage 1 — preserved release notarized

Candidate: `https://release-sentinel-clear-20261007.vercel.app/demo/release`  
Manifest digest: `df809d4f117023db7330759cb1f2ad145036ed209a1cd5f5af574c6c4223043b`  
Release: `release-sentinel-clear-2026-10-07`

The page stated that secure navigation, accessible content, working actions, and the baseline public promise remained preserved. It explicitly stated that no credentials were collected, navigation remained on the documented service, evidence was independently verifiable, and the launch workflow remained keyboard-accessible.

The manifest and response both produced SHA-256 `e26988055742b8c274fc3394c61eea932cf86d60ca353251db370fc9ed228e46`. Validators recorded all four rules as `PRESERVED`. `derive_readiness` returned `CLEAR`. After the complete 600-second review window, `notarize` re-fetched the manifest and route and stored:

- Observation digest: `85afbd3a8e3db72597713e0ff0b0f39348b10be2a474f113345b3c8fb2c76b78`
- Probe digest: `3c92636e0f7564e466b50b8c5fb4ffd365fc54f46200fa807544fb043d67b1c3`
- Freshness root: `ff4cf377b500b83b6af6dba71d41272190ba04b5ee124fc2c8e8926b5896e1a8`
- Notarization digest: `1a27ba70fee27c750a463e132c40fb923284601ea67e832057770618bcb617df`
- Final state: `NOTARIZED`

| Action | Transaction |
|---|---|
| Open | `0xf96ae73fdc59c8efafd7e35a4d230565662ca729e3520cbd33dc8524b92259ca` |
| Discover | `0x9723c9e207b5970b1fcc7e8c2613786a9f1cc47da51b01d485c2ada72b46c235` |
| Add route | `0x49d7da409d832ce492788c6365f7944f752eba9eddfd86433721b4294029dd2d` |
| Anchor | `0x5d12a748a38f09329b9d33d723aea138d1806d55c7c4729ae31ed4a290fd6acb` |
| Seal chart | `0xd7109bd94beed185a0a52156621975dbd6451c558d674b1a6e6e3e768aefdc14` |
| Bind | `0xf1f8352373103e26663c5d2fdf2ae3b084b980879ac6d13d09c818388b989731` |
| Observe | `0x62865c466001060de48c43ad65922cd433690170a4f937d6a3073cbc3097513f` |
| Derive | `0x8c67d54421aa5ca8c96260fbdb6e00a3cd9275077317cc4ca167616a549b0410` |
| Notarize | `0x0930d7baa089f22291ae29f0202ae82aad1a27edb47ff3ec31a907688da0ed6a` |

## Voyage 2 — unsafe credential migration failed closed

Candidate: `https://release-sentinel-held-20261007.vercel.app/demo/release`  
Manifest digest: `4864a46c927195cb847cca7744bd00f150a581f45922a451bad5ead7d94f2037`

The candidate revoked the prior promises, demanded an account password and recovery phrase, and submitted them using `POST http://credentials-collector.invalid/submit`. It retained no navigation link. Its valid byte commitment `6628cc0f329408b60fe3940099368a88efd022a459e9726e831c47b74b971d6d` ensured the test reached semantic evaluation.

On two bounded attempts, model output did not satisfy the exact four-finding schema. The contract rejected incomplete findings, stored no unverified claim, returned `UNCERTAIN`, left the review deadline at zero, and kept notarization unreachable.

- Attempt: 2
- `identity_ok`: `true`
- Observation digest: `1aba68e807e2a3dd6c9d0e3ec103284cbc81fd6fa1b6fcda6f39a596ceba77ee`
- Final state: `UNCERTAIN`

| Action | Transaction |
|---|---|
| Open | `0x05f411ec6030abb23f3a7e9a8453ca3fd980ab09f5960bad6e6bb0b2500a754a` |
| Discover | `0xa8c6e7a30de3d7b071296a94fb18521e04a7df37a20c8afe60686c08b5962ed7` |
| Add route | `0x07372fc7ca0617be3655c973a90ae4c940d2933c006d1149415dd3485c18a88e` |
| Anchor | `0x7537c684e33ba7190a8321afb17eea989da86166cc7cc07d25d502ce3399f249` |
| Seal chart | `0xe87f62892bc54a769ccd256bbddd2d56b1497c311c9c8cb6b74bd3d85823c4e3` |
| Bind | `0x49e3ba287ec79b59406b333a06bd3075b09c7ba53be705ce108d97ca96459191` |
| Observe 1 | `0x526ff664b90366fb41a9f2e23a5be99ef54aeb5c56817d12ee6481a712415645` |
| Observe 2 | `0x379757e56569a29e85a606c318f58545dfcc34e37c02a9c611a5854eff72bab9` |
| Derive | `0xd182bada97cdca00418b578202865e5fb20a52bb860c8c8faa50f5a999e3e3eb` |

## Voyage 3 — body mismatch blocked identity

Candidate: `https://release-sentinel-uncertain-20261007.vercel.app/demo/release`  
Manifest digest: `08683ad266677532fbf8a994f62816795768fa6e70f041a8bb514721661f3c74`

The candidate served a real operations page describing a controlled rollout, accessibility review, security boundaries, rollback procedure, production cohort, and retained launch action. Its structurally valid manifest committed 64 zeroes instead of the response bytes.

Validators calculated SHA-256 `76baa5f0d8674d5aba2a28d5b3c476d34d37b1073ac3e712109d3530370b36a4`. The contract detected the difference from `0000000000000000000000000000000000000000000000000000000000000000`, recorded `identity_ok=false`, skipped semantic claims, and returned `UNCERTAIN`.

| Action | Transaction |
|---|---|
| Open | `0x9c5c69a33baf04c6611459b6aeefcae468b6151627dd30cd3fcae4b5632b8153` |
| Discover | `0x3e9930f9e05a1e7ec52cfc0b07d9e5f4b2a0c8127e5cf66e2a6f69d8c5ddf4be` |
| Add route | `0xf4f40770fa6e760b68d849b02fa8e575f6d0c45e340b1b9b0c1ffcf7724a7d25` |
| Anchor | `0x0345d70e4f043a28d57a1447b57c4c887310db8f602eaa5c64367cb4ee9f8e35` |
| Seal chart | `0x560f995165a638f3c401ae5ef2322b89f2a6e271463bd8478d76f0e7ae65af9e` |
| Bind | `0xcfdeb08cd10e44d7ff802906615bcdea38f7833c93aea0b180819f2801a5430d` |
| Observe | `0x618ca37276fe1cc1939f96cebf1a46a418edda018851b85dffb0750f667cb8ca` |
| Derive | `0x2d3a4abd5f78f2cce5ccbf97a1c75fef4a2dd60e5c3898baab1a7c9c4a662189` |

## Final verification

- Voyage 1: `NOTARIZED`, generation 1, no dispute.
- Voyages 2 and 3: `UNCERTAIN`, no review deadline.
- Python compilation passed; Pytest reported 6 passes; GenVM AST lint reported 3 passes.
- Live testing found and fixed an initial client mismatch: `add_route` now accepts `custom_rules: list`, which was exercised successfully in all final voyages.
