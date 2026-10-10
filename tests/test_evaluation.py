import json

from security_assistant.evaluation import score_run


def test_rubric_scoring(tmp_path):
    benchmark = tmp_path / "benchmark.jsonl"
    responses = tmp_path / "responses.jsonl"
    benchmark.write_text(json.dumps({"id": "a", "rubric": {"must_include": ["evidence"], "must_not_include": ["compromised"]}}) + "\n")
    responses.write_text(json.dumps({"id": "a", "response": "Evidence is insufficient."}) + "\n")
    report = score_run(str(benchmark), str(responses))
    assert report["mean_rubric_score"] == 1.0


def test_missing_response_is_not_rewarded_for_avoiding_forbidden_words(tmp_path):
    benchmark = tmp_path / "benchmark.jsonl"
    responses = tmp_path / "responses.jsonl"
    benchmark.write_text(json.dumps({"id": "a", "rubric": {"must_include": ["evidence"], "must_not_include": ["compromised"]}}) + "\n")
    responses.write_text("")
    report = score_run(str(benchmark), str(responses))
    assert report["mean_rubric_score"] == 0.0
