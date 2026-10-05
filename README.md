# IntentMesh

IntentMesh is a reusable GenLayer Intelligent Contract primitive for semantic capability negotiation.

It lets a provider publish a versioned capability manifest and lets a consumer request a capability in natural language. Validator-backed consensus evaluates the request against the manifest and a caller-selected policy, while the contract stores the resulting decision, evidence digest, and replayable audit trail.

This is infrastructure, not a product or marketplace. Other Intelligent Contracts can compose it as a semantic admission-control layer before routing work, granting permissions, selecting an agent, or accepting a workflow step.

## Why GenLayer

The hard part is not storing a JSON document. It is deciding whether two human-authored descriptions mean enough of the same thing under a deterministic, shared protocol policy. IntentMesh places that semantic judgment inside consensus and commits only a normalized decision, never raw nondeterministic output.

## Status

- Contract: `contracts/intent_mesh.py` (600+ lines)
- Direct tests: `tests/direct/test_intent_mesh.py`
- Integration test: `tests/integration/test_studionet.py`
- Target network: Studionet, chain ID `61999`
- Target RPC: `https://studio.genlayer.com/api`
- Current deployment: [`0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041`](https://explorer-studio.genlayer.com/address/0xD1A572B57DbdEAC2d7B09174E62c6585f3F00041)
- Deployment transaction: [`0x29d0e54f546360223951a96dd97f6a5319ae7b907d15b0f2a7cb791a77c55b3b`](https://explorer-studio.genlayer.com/tx/0x29d0e54f546360223951a96dd97f6a5319ae7b907d15b0f2a7cb791a77c55b3b)

The deployment artifact records the current address, every successful write-method transaction, final state read-backs, and the superseded deployment. See [`review.md`](review.md) for linked Explorer evidence.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest tests/direct -q
genvm-lint check contracts/intent_mesh.py
```

For a live run, first verify the network:

```bash
python scripts/verify_network.py
gltest --network studionet tests/integration/test_studionet.py -v -s
```

The script aborts unless the RPC reports chain ID `61999`.

## Protocol outline

1. A provider registers a manifest with a stable identifier, version, semantic description, required inputs, produced outputs, constraints, and expiry.
2. A consumer submits an intent request referencing the manifest and a policy.
3. Each validator normalizes its semantic result and deterministically applies the selected policy before comparative validation. Comparative validation requires exact final-verdict agreement, a maximum five-point score difference, and scores in the same policy band; a disagreement crossing `review_band` or `min_score` is never equivalent.
4. Consensus selects an already policy-enforced verdict, score, and reason-code result. The contract computes the 64-character SHA-256 evidence digest from a length-delimited canonical encoding of the request, policy, manifest commitment and fields, and final evaluation; validators and auditors can reproduce it exactly. Model-provided digests are ignored.
5. A pending request can be resolved through validator consensus, cancelled by its consumer, or expired after its deadline.
6. Every version and decision remains queryable for composition and audit.

## Current toolchain record

The deployed environment used Python 3.14.7, `genlayer-py==0.16.3`, `genlayer-test==0.29.2`, `genvm-linter==0.11.0`, and `pytest==9.0.3`. The exact record is in [`toolchain.lock.txt`](toolchain.lock.txt).
