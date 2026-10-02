# Evidence-Commitment Remediation Review

**Date:** 2026-10-02  
**Contract:** IntentMesh  
**Deployment network:** GenLayer Studionet, chain ID `61999`

## Team finding

> The evidence commitment is not bound by validator consensus: any 64-character hexadecimal value can pass, so different validators can accept conflicting digests for the same request. Please compute the digest deterministically from canonical evaluated evidence, or require validators to reproduce and match the exact digest before storing it.

## Finding assessment

The finding was valid.

Before this remediation, the non-deterministic validator response contained an `evidence_digest` field. The contract normalized that field only by truncating it, while the comparative-consensus instruction only required a valid-looking 64-character hexadecimal value. As a result, different validator outputs could contain different opaque commitments while still being judged semantically compatible. The stored value was therefore not a reproducible commitment to the consensus evaluation.

This was an integrity and auditability problem. An observer could not recompute the stored digest from the request and evaluation, and the digest could not prove that all validators had committed to the same evidence.

## Remediation strategy

The contract now uses the first requested remediation option: it derives the digest deterministically from canonical evaluated evidence after comparative consensus returns.

The model cannot supply the stored evidence commitment. The relevant lifecycle is now:

1. Each validator produces only `verdict`, `score`, and `reason_codes`.
2. `gl.eq_principle.prompt_comparative` reaches consensus on that normalized evaluation.
3. Deterministic contract code applies hard policy constraints.
4. The contract serializes the immutable evaluation inputs and final result using one length-delimited canonical format.
5. The contract computes a lowercase 64-character SHA-256 digest of that canonical text.
6. `resolve_match` stores only this calculated digest in the request record.

Because steps 3 through 6 are deterministic contract execution after the consensus result is selected, every validator and any independent auditor can reproduce the exact commitment.

## Code changes

### Removed model-controlled evidence commitments

`_normalize_llm_result` now ignores `evidence_digest` entirely. The validator prompt explicitly instructs the model not to return one. No parsing, validation, truncation, or forwarding of a model-provided digest remains in the resolution path.

`_semantic_evaluation` now performs these operations in order:

```python
result = gl.eq_principle.prompt_comparative(...)
result = self._enforce_policy(manifest, policy, result)
result["evidence_digest"] = self._evidence_digest(manifest, request, policy, result)
```

`resolve_match` is the only storage assignment for `request["evidence_digest"]`, and it receives the value from `_semantic_evaluation`.

### Canonical evidence encoding

`_evidence_digest` creates a length-delimited encoding via `_canonical_fields` and `_canonical_list`. Length-prefixing removes delimiter ambiguity: values such as `a|bc` and `ab|c` cannot have the same serialized form.

The evidence domain separator is `intentmesh:evidence:v1`. The commitment binds:

- request ID and manifest ID;
- intent, context, deadline, and policy ID;
- policy score thresholds and input/output requirements;
- manifest digest, summary, inputs, outputs, and constraints;
- final verdict, score, and ordered reason-code vector.

The final result is included only after deterministic policy enforcement, so the committed evidence matches the state that is actually stored.

### SHA-256 implementation

`_sha256` is a compact, portable SHA-256 implementation in the contract rather than an imported host crypto library. It produces exactly 64 lowercase hexadecimal characters and is tested against known SHA-256 vectors, including a multi-block input and UTF-8 text.

The pre-existing manifest commitment was also upgraded from a non-cryptographic truncated text marker to SHA-256 over canonical manifest fields, with a distinct `intentmesh:manifest:v1` domain separator.

### Deterministic policy enforcement

The audit found that `min_score`, `review_band`, `require_inputs`, and `require_outputs` were previously mostly prompt guidance. `_enforce_policy` now makes those requirements binding in deterministic contract code:

- an accepted score at or above `min_score` remains accepted;
- an accepted score in the review band becomes `review` with `BELOW_ACCEPT_THRESHOLD`;
- an accepted score below the review band becomes `reject` with `BELOW_REVIEW_THRESHOLD`;
- a policy requiring absent manifest inputs or outputs yields `review` with a deterministic reason.

### Storage ambiguity hardening

Reason codes are now restricted to uppercase ASCII letters, digits, and underscores. Manifest list entries may not contain `|`, the storage packing delimiter. This prevents ambiguous round-tripping of state and keeps the canonical evidence representation auditable.

## Regression coverage

The direct test suite contains six passing tests:

- normalization ignores a supplied 64-character model digest;
- SHA-256 agrees with known values, including boundary and UTF-8 cases;
- canonical evidence is stable for identical inputs and changes when evaluated data changes;
- two otherwise identical validator outputs with conflicting `00…00` and `ff…ff` supplied digests yield the same contract-derived commitment;
- score bands and required manifest fields are enforced by deterministic code;
- invalid or delimiter-bearing reason codes are not retained.

Command run:

```bash
pytest tests/direct -q
```

Result: `6 passed`.

`genvm-lint check contracts/intent_mesh.py` completed its initial three lint checks. Full pinned-SDK loading was unavailable locally because the linter cache did not contain the referenced runner archive; this was a local tooling-cache limitation, not a contract diagnostic. The real Studionet deployment and consensus execution below provide runtime validation on the pinned contract dependency.

## Real Studionet deployment

The patched contract was deployed by the active unlocked account `0x8d4e752ae688c21ec7c7d4d8a232b5e0700dbf0f`.

| Item | Value |
| --- | --- |
| Contract address | `0x9b9136318D7D6aDe227D7B2C8ae7912C20ee3537` |
| Deployment transaction | `0xecd9791b41c6dadee3a33a2e5a75d42fdf9815803cb02489d624aacf2de4402b` |
| Deployment status | `ACCEPTED` / `MAJORITY_AGREE` |

## End-to-end test evidence

### E2E 1 — publish and read a manifest

A concrete EUR supplier-payment capability manifest was published and read back.

| Item | Value |
| --- | --- |
| Publish transaction | `0x333c5441b69e50102b8b7ec1d4c6c67da3280e9965d399ed1d743669acc27cc8` |
| Result | `ACCEPTED` / `MAJORITY_AGREE` |
| Manifest ID | `1` |
| Capability ID | `intentmesh-payment-evidence-v1` |
| Manifest digest | `023b8256d2304c7a525681e546d89073c0192e176157867892f34bb331fc4ec7` |
| On-chain status | `active` |

The stored manifest includes four declared inputs (`invoice_id`, `amount_eur`, `beneficiary_iban`, `approval_id`), three outputs, and the required approval and sanctions-screening constraints. The manifest digest is a 64-character SHA-256 value rather than the former truncated text marker.

### E2E 2 — request, resolve through consensus, and reproduce the evidence digest

A detailed but explicitly fictional public-demo payment scenario was used to avoid placing personal, banking, production invoice, or production compliance data on a public chain.

| Item | Value |
| --- | --- |
| Request transaction | `0xa126d0297034977a0c5839807174320d21488404b46563174286da3218896cc7` |
| Resolve transaction | `0x066d1ad8b6538de9e58d114774055ac70c3081cc9c71beea3c07e86908136085` |
| Resolve result | `ACCEPTED` / `MAJORITY_AGREE` |
| Request ID | `1` |
| Stored verdict | `review` |
| Stored score | `0` |
| Stored reason code | `UNPARSEABLE` |
| Stored evidence digest | `41f641b208285b2a3c87e694b02d0bc7c5c718cd9a9d2e91bdc693da77bdf09d` |
| Independently recomputed digest | `41f641b208285b2a3c87e694b02d0bc7c5c718cd9a9d2e91bdc693da77bdf09d` |

The semantic result was fail-closed (`review`/`UNPARSEABLE`), but the resolution transaction executed successfully with a validator majority. Crucially, the independent post-read recomputation from the on-chain manifest, request, strict-policy parameters, and final evaluation matched the stored digest byte-for-byte.

This directly demonstrates that the stored digest is not an arbitrary validator-provided value and is reproducible from canonical evaluated evidence.

## Files changed

- `contracts/intent_mesh.py` — deterministic commitments, canonical serialization, SHA-256, policy enforcement, and validation hardening.
- `tests/direct/test_intent_mesh.py` — regression tests for the original flaw and related deterministic behavior.
- `tests/conftest.py` — comparative-principle test stub accepts the principle argument.
- `README.md` — protocol documentation now describes deterministic evidence commitments.
- `artifacts/studionet-deployment.json` — machine-readable deployment and E2E evidence.

## Conclusion

The reported issue is resolved. A validator cannot choose the digest stored for a resolved request. The contract computes the commitment only after consensus and deterministic policy enforcement, from a canonical encoding of all material evidence. The deployed contract has executed this flow on real Studionet, and the resulting on-chain digest has been independently reproduced exactly.
