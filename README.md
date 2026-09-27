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

The final GitHub repository and live deployment address are intentionally not fabricated. They must be filled by the deployment helper after a real account and target repository are supplied.

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
3. Validators semantically compare the request and manifest inside an equivalence-principle block.
4. Only the normalized verdict, score, reason codes, and evidence digest enter shared state.
5. The consumer can accept, reject, or expire a request according to the committed verdict.
6. Every version and decision remains queryable for composition and audit.

## Current toolchain record

The repository follows the current official Studionet guidance: Python >= 3.12, `genlayer-py`, `genlayer-test`, and `genvm-linter`. Exact resolved versions should be written to `toolchain.lock.txt` by `scripts/record_toolchain.py` in the environment used for deployment.

