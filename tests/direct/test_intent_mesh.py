from contracts.intent_mesh import IntentMesh
from genlayer import gl


def test_protocol_constants_and_normalization():
    contract = IntentMesh()
    assert contract._bounded_int(200, 0, 100) == 100
    assert contract._bounded_int(-1, 0, 100) == 0
    result = contract._normalize_llm_result({"verdict": "garbage", "score": 44, "reason_codes": ["scope"], "evidence_digest": "f" * 64})
    assert result["verdict"] == "review"
    assert result["score"] == 44
    assert result["reason_codes"] == ["SCOPE"]
    assert "evidence_digest" not in result


def test_digest_is_bounded_and_stable():
    contract = IntentMesh()
    value = contract._stable_digest("abc")
    assert value == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert contract._stable_digest("a" * 56) == "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    assert contract._stable_digest("evidence: café") == "274a0ddae381502e3bd9495e3d25a321105aa16e28c3c34ad7afd75b636f37a9"


def test_evidence_digest_is_canonical_and_binds_every_evaluated_field():
    contract = IntentMesh()
    manifest = {
        "manifest_digest": contract._manifest_digest("payments", 1, "Send money", ["amount"], ["receipt"], ["kyc"]),
        "summary": "Send money",
        "inputs": "amount",
        "outputs": "receipt",
        "constraints": "kyc",
    }
    request = {"request_id": 7, "manifest_id": 3, "intent": "pay an invoice", "context": "approved", "deadline": 99, "policy_id": "strict"}
    policy = {"min_score": 80, "review_band": 65, "require_inputs": True, "require_outputs": True}
    result = {"verdict": "accept", "score": 91, "reason_codes": ["SCOPE", "INPUTS"]}

    digest = contract._evidence_digest(manifest, request, policy, result)
    assert len(digest) == 64
    assert digest == contract._evidence_digest(manifest, request, policy, result)
    assert digest != contract._evidence_digest(manifest, request, policy, {"verdict": "accept", "score": 90, "reason_codes": ["SCOPE", "INPUTS"]})
    assert digest != contract._evidence_digest(manifest, request, policy, {"verdict": "accept", "score": 91, "reason_codes": ["INPUTS", "SCOPE"]})


def test_semantic_evaluation_ignores_model_digest_and_derives_its_own():
    contract = IntentMesh()
    manifest = {"manifest_digest": "a" * 64, "summary": "Send money", "inputs": "amount", "outputs": "receipt", "constraints": "kyc"}
    request = {"request_id": 7, "manifest_id": 3, "intent": "pay an invoice", "context": "approved", "deadline": 99, "policy_id": "strict"}
    policy = {"min_score": 80, "review_band": 65, "require_inputs": True, "require_outputs": True}
    original_prompt = gl.nondet.exec_prompt if hasattr(gl, "nondet") else None
    original_comparative = gl.eq_principle.prompt_comparative
    model_response = {"verdict": "accept", "score": 91, "reason_codes": ["scope"], "evidence_digest": "0" * 64}
    gl.nondet = type("Nondet", (), {"exec_prompt": staticmethod(lambda prompt: model_response)})()
    gl.eq_principle.prompt_comparative = lambda evaluate, **kwargs: evaluate()
    try:
        result = contract._semantic_evaluation(manifest, request, policy)
        model_response["evidence_digest"] = "f" * 64
        conflicting_model_digest_result = contract._semantic_evaluation(manifest, request, policy)
    finally:
        gl.eq_principle.prompt_comparative = original_comparative
        if original_prompt is not None:
            gl.nondet.exec_prompt = original_prompt

    expected = contract._evidence_digest(manifest, request, policy, {"verdict": "accept", "score": 91, "reason_codes": ["SCOPE"]})
    assert result == {"verdict": "accept", "score": 91, "reason_codes": ["SCOPE"], "evidence_digest": expected}
    assert conflicting_model_digest_result == result


def test_policy_thresholds_and_required_manifest_fields_are_contract_enforced():
    contract = IntentMesh()
    policy = {"min_score": 80, "review_band": 65, "require_inputs": True, "require_outputs": True}
    complete_manifest = {"inputs": "amount", "outputs": "receipt"}

    assert contract._enforce_policy(complete_manifest, policy, {"verdict": "accept", "score": 80, "reason_codes": ["MATCH"]})["verdict"] == "accept"
    review = contract._enforce_policy(complete_manifest, policy, {"verdict": "accept", "score": 70, "reason_codes": ["MATCH"]})
    assert review == {"verdict": "review", "score": 70, "reason_codes": ["BELOW_ACCEPT_THRESHOLD"]}
    rejected = contract._enforce_policy(complete_manifest, policy, {"verdict": "accept", "score": 64, "reason_codes": ["MATCH"]})
    assert rejected == {"verdict": "reject", "score": 64, "reason_codes": ["BELOW_REVIEW_THRESHOLD"]}
    missing = contract._enforce_policy({"inputs": "", "outputs": "receipt"}, policy, {"verdict": "accept", "score": 99, "reason_codes": ["MATCH"]})
    assert missing == {"verdict": "review", "score": 99, "reason_codes": ["MISSING_REQUIRED_INPUTS"]}


def test_reason_codes_are_unambiguous_storage_values():
    contract = IntentMesh()
    assert contract._bounded_reasons(["safe_code", "bad|code", "space code"]) == ["SAFE_CODE"]
