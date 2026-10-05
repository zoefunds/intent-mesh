# Studionet deployment

The current IntentMesh contract is deployed on GenLayer Studionet, chain ID `61999`.

| Item | Value |
| --- | --- |
| Contract | [`0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041`](https://explorer-studio.genlayer.com/address/0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041) |
| Deployment transaction | [`0x29d0e54f546360223951a96dd97f6a5319ae7b907d15b0f2a7cb791a77c55b3b`](https://explorer-studio.genlayer.com/tx/0x29d0e54f546360223951a96dd97f6a5319ae7b907d15b0f2a7cb791a77c55b3b) |
| Owner/deployer | `0x8d4e752ae688c21ec7c7d4d8a232b5e0700dbf0f` |
| Status | `FINALIZED` / `MAJORITY_AGREE` |
| RPC | `https://studio.genlayer.com/api` |

Explorer and `genlayer code` both show deterministic policy enforcement inside the comparative callback and the explicit rule that score disagreements crossing `review_band` or `min_score` are never equivalent.

Every public write method has a successful real Studionet transaction. Transaction links and final read-back state are recorded in [`artifacts/studionet-deployment.json`](artifacts/studionet-deployment.json) and [`review.md`](review.md).

Final state: the contract is unpaused; manifest 1 is active, manifest 2 revoked, and manifest 3 expired; request 1 is resolved, request 2 cancelled, and request 3 expired. The temporary audit policy is disabled after its lifecycle verification.

The older contract `0x9b9136318D7D6aDe227D7B2C8ae7912C20ee3537` is superseded and must not be used in submissions or Explorer links.
