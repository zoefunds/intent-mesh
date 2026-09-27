from contracts.intent_mesh import IntentMesh


def test_protocol_constants_and_normalization():
    contract = IntentMesh()
    assert contract._bounded_int(200, 0, 100) == 100
    assert contract._bounded_int(-1, 0, 100) == 0
    result = contract._normalize_llm_result({"verdict": "garbage", "score": 44, "reason_codes": ["scope"], "evidence_digest": "x"})
    assert result["verdict"] == "review"
    assert result["score"] == 44
    assert result["reason_codes"] == ["SCOPE"]


def test_digest_is_bounded_and_stable():
    contract = IntentMesh()
    value = contract._stable_digest("abc")
    assert value == "3:abc"
    assert len(contract._bounded_digest("x" * 500)) == 128
