"""Deterministic rubric scoring for externally captured model responses."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CaseScore:
    case_id: str
    score: float
    passed: list[str]
    failed: list[str]


def load_jsonl(path: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def score_response(case: dict[str, Any], response: str) -> CaseScore:
    if not response.strip():
        return CaseScore(case["id"], 0.0, [], ["response_missing"])
    normalized = response.lower()
    passed, failed = [], []
    for required in case["rubric"]["must_include"]:
        (passed if required.lower() in normalized else failed).append(f"include:{required}")
    for forbidden in case["rubric"].get("must_not_include", []):
        (failed if forbidden.lower() in normalized else passed).append(f"exclude:{forbidden}")
    denominator = len(passed) + len(failed)
    return CaseScore(case["id"], round(len(passed) / denominator if denominator else 0.0, 3), passed, failed)


def score_run(benchmark_path: str, responses_path: str) -> dict[str, Any]:
    cases = {case["id"]: case for case in load_jsonl(benchmark_path)}
    responses = {item["id"]: item["response"] for item in load_jsonl(responses_path)}
    scores = [score_response(case, responses.get(case_id, "")) for case_id, case in cases.items()]
    return {
        "benchmark_cases": len(cases), "responses_received": len(responses),
        "mean_rubric_score": round(sum(score.score for score in scores) / len(scores), 3) if scores else 0,
        "cases": [score.__dict__ for score in scores],
        "warning": "This keyword rubric is a regression signal, not a substitute for expert review.",
    }
