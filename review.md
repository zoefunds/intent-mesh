# IntentMesh remediation and live verification

**Verified:** 2026-10-05  
**Network:** GenLayer Studionet (`61999`)  
**Contract:** [`0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041`](https://explorer-studio.genlayer.com/address/0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041)

## Findings resolved

The model no longer supplies the evidence digest. Validators return only verdict, score, and reason codes. The contract applies deterministic policy and computes SHA-256 over a length-delimited canonical representation of the request, policy, manifest evidence, and final result.

Policy enforcement occurs inside each validator's comparative callback. Under strict policy, score 79 becomes `review` and score 84 remains `accept` before comparison, so exact-verdict comparison rejects them as equivalent. The principle also explicitly says that crossing `review_band` or `min_score` is never equivalent, even within five points.

Seven direct regression tests pass, including the exact 79-versus-84 case. Explorer and CLI source read-back both show this implementation.

## Deployment

| Item | Value |
| --- | --- |
| Contract | [`0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041`](https://explorer-studio.genlayer.com/address/0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041) |
| Deployment transaction | [`0x29d0e54f…c55b3b`](https://explorer-studio.genlayer.com/tx/0x29d0e54f546360223951a96dd97f6a5319ae7b907d15b0f2a7cb791a77c55b3b) |
| Owner | `0x8d4e752ae688c21ec7c7d4d8a232b5e0700dbf0f` |
| Result | `FINALIZED` / `MAJORITY_AGREE` |

## Successful write-method verification

| Method | Transaction | Verified effect |
| --- | --- | --- |
| `pause` | [`0x653de660…00290a`](https://explorer-studio.genlayer.com/tx/0x653de660f76a1458ea03ef179e246f648f1202f0e0045fec3f40a7998800290a) | Owner paused the contract. |
| `unpause` | [`0xaed97bd2…e0266`](https://explorer-studio.genlayer.com/tx/0xaed97bd2dece31bb37034aad224bd047e38ee97e4d36c804fc586140251e0266) | Restored operation; final `is_paused=false`. |
| `set_policy` | [`0x25b7b975…473e9`](https://explorer-studio.genlayer.com/tx/0x25b7b97583979b9fbe11974b2a28de1432864df655327af0c9be89d9118473e9) | Created `studionet_audit_2026`: minimum 82, review band 68, inputs and outputs required. |
| `disable_policy` | [`0xc1a0d6a8…6c9e7`](https://explorer-studio.genlayer.com/tx/0xc1a0d6a8bbde7e85837e5ff44b544851d3d21a295465577a076a4ac3a146c9e7) | Disabled the temporary audit policy. |
| `publish_manifest` | [`0x3308ce5e…ffb9c`](https://explorer-studio.genlayer.com/tx/0x3308ce5ea928f1c7b27a8fd36da6e9f226b613370ffa9b2c48b6ea67aa9ffb9c) | Published active source-verification manifest 1. |
| `publish_manifest` | [`0xa3fd1469…da830`](https://explorer-studio.genlayer.com/tx/0xa3fd14696bd88cf47df91476fe85396bce8217657835e4f5887e1474f23da830) | Published revocation-lifecycle manifest 2. |
| `publish_manifest` | [`0xde4e0959…328bc`](https://explorer-studio.genlayer.com/tx/0xde4e09599caec394e54f37d4a6ae720e1fe0a58d8efe2439e2325ca5893328bc) | Published time-bounded expiry manifest 3. |
| `revoke_manifest` | [`0x168aa2a1…65e3b`](https://explorer-studio.genlayer.com/tx/0x168aa2a133f7f03de82cf6ba954a1b0e84e673319f8d19fc517bf3f15e265e3b) | Revoked manifest 2 with a concrete supersession reason. |
| `expire_manifest` | [`0x74330d2f…f28ba`](https://explorer-studio.genlayer.com/tx/0x74330d2f99f4fadaf9ddb302ce663320c2132bbf813f51504e85dbcf9cff28ba) | Expired manifest 3 after deadline `1791212636`. |
| `request_match` | [`0x2ccf6fd3…78c2b`](https://explorer-studio.genlayer.com/tx/0x2ccf6fd385df21965d034c078c02b34ecde535ce10ee47eba8a73130b8a78c2b) | Created deployment-verification request 1. |
| `resolve_match` | [`0xff23df8d…ead04`](https://explorer-studio.genlayer.com/tx/0xff23df8d2b7643b6574f91b9271b8b0b8f21c6d293836727b10f3246e18ead04) | Resolved request 1 through validator consensus. |
| `request_match` | [`0x2d6cae50…5d6b2`](https://explorer-studio.genlayer.com/tx/0x2d6cae5001a89009ba63a8b38aeb37992d23bb98ade11c030b1a68a84195d6b2) | Created cancellation-path request 2. |
| `cancel_request` | [`0xa2813e11…8f953`](https://explorer-studio.genlayer.com/tx/0xa2813e11e3c8bfa40980c27003f3abee765dd3721f4345f5fe4e9464aa38f953) | Cancelled request 2 as its consumer. |
| `request_match` | [`0x8c177723…fe6fc`](https://explorer-studio.genlayer.com/tx/0x8c177723820563831dbd1e18e7b236119233353a6409a0c548bb43f6ca8fe6fc) | Created request 3 with deadline `1791213023`. |
| `expire_request` | [`0x0f28a7de…01e27`](https://explorer-studio.genlayer.com/tx/0x0f28a7de75f3f83b07537689b8199f75530cf7f9177d7edff31fbdfbaa001e27) | Expired request 3 after its deadline. |

## Detailed records

Manifest 1, `intentmesh-studionet-source-verification-v1`, requires the contract address, deployment transaction, chain ID, expected source rule, and verification timestamp. It returns source-match and policy-boundary results, the evidence digest, and Explorer URL. Its constraints require chain 61999, pre-comparison policy enforcement, no threshold-crossing equivalence, and contract-derived SHA-256. It is active with digest `52eeed185b6a2f8548fff358282affd00408dd1c4ad156082fd5d68b0b9395d1`.

Manifest 2 is revoked with reason “Superseded lifecycle-only capability retired after successful replacement deployment and on-chain source verification on 2026-10-05.” Its digest is `7be63c130d65e786c1b0052e4428a76c095b229a4c9cd09a10e75cf9a1eb6cec`; `revoked_at=1791212647`.

Manifest 3 is expired. It was created at `1791212607`, had deadline `1791212636`, and has digest `d1c36e11393b3a7d17cb9154ec00fd41a279e9971f933a563284479817bebeec`.

Request 1 contains the exact contract, deployment transaction, chain ID, source-read-back facts, and 79/84 regression evidence. Validators resolved it fail-closed as `review`, score `0`, reason `UNPARSEABLE`. The contract produced deterministic digest `e2a8b374b8eb0eca678df8af56272c204b61c6ad7b97b82751adde6e2d4f54c0`. Request 2 is `cancelled`. Request 3 is `expired`, with deadline `1791213023` and transition time `1791213048`.

## Failed attempts retained transparently

Transaction `0xaf862e21eef98ee1308aee972c5fea9957cb51f115d97ddade8a06604ed511d2` attempted request creation after its proposed deadline had elapsed, so no state was created. Transaction `0x4f7d19809e1b86306ab2de8907cd055ec5ed64135645ba2b5e82fb199d6427ba` consequently failed with `unknown request`. The successful request/expiry pair above replaced them; they are not counted as method verification.

## Superseded deployment

Contract `0x9b9136318D7D6aDe227D7B2C8ae7912C20ee3537` is historical only. It is excluded from current evidence because its source predates consequential-threshold comparative validation.
