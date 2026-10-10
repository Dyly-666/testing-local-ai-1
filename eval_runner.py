#!/usr/bin/env python3
"""
eval_runner.py — Run benchmark questions through run.py on the Mac via SSH,
                 capture responses, score with keyword rubric, and report.

Usage:
    python3 eval_runner.py --mode baseline   # uses run_baseline.py on Mac
    python3 eval_runner.py --mode improved   # uses run_improved.py on Mac
    python3 eval_runner.py --compare         # print side-by-side diff of saved results

Output: data/eval_results_<mode>.jsonl + data/eval_report_<mode>.txt
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

# ── Config ────────────────────────────────────────────────────────────────────

MAC_HOST   = "mongsamnang@192.168.1.8"
MAC_DIR    = "~/Desktop/security-assistant-mac"
ADAPTER    = "mlx_adapter_v18"           # rank-32 trained adapter
MAX_TOKENS = 512                          # shorter for eval speed
TEMP       = 0.0                          # greedy for reproducibility

BENCHMARK_PATH = Path("data/eval_benchmark.jsonl")
RESULTS_DIR    = Path("data")

# ── Scoring ───────────────────────────────────────────────────────────────────

@dataclass
class CaseResult:
    id: str
    domain: str
    question: str
    response: str
    score: float
    passed: list[str]
    failed: list[str]
    duration_s: float


def score_response(case: dict[str, Any], response: str) -> tuple[float, list[str], list[str]]:
    if not response.strip():
        return 0.0, [], ["response_missing"]
    norm = response.lower()
    passed, failed = [], []
    for req in case["rubric"].get("must_include", []):
        (passed if req.lower() in norm else failed).append(f"MUST_INCLUDE:{req}")
    for forb in case["rubric"].get("must_not_include", []):
        (failed if forb.lower() in norm else passed).append(f"MUST_NOT_INCLUDE:{forb}")
    denom = len(passed) + len(failed)
    score = round(len(passed) / denom, 3) if denom else 0.0
    return score, passed, failed


# ── Remote execution ──────────────────────────────────────────────────────────

def build_ssh_cmd(script_name: str, domain: str, question: str) -> list[str]:
    """Return an ssh argv that runs one question on the Mac."""
    escaped_q = question.replace("'", "'\\''")
    remote = (
        f"cd {MAC_DIR} && "
        f"source venv/bin/activate 2>/dev/null; "
        f"python3 {script_name} "
        f"--domain {domain} "
        f"--adapter {ADAPTER} "
        f"--max-tokens {MAX_TOKENS} "
        f"--temp {TEMP} "
        f"--prompt '{escaped_q}' 2>&1"
    )
    return ["ssh", "-o", "ConnectTimeout=30", MAC_HOST, remote]


_THINK_RE = re.compile(r"<think>.*?</think>\s*", re.DOTALL)
_FENCE_RE  = re.compile(r"^={5,}.*$", re.MULTILINE)


def extract_answer(raw: str) -> str:
    """Strip mlx-lm verbose header/footer and Qwen3 <think> blocks."""
    # Remove <think>
    text = _THINK_RE.sub("", raw)
    # Remove ====... lines from mlx-lm verbose
    text = _FENCE_RE.sub("", text)
    # Remove "Loading model..." header lines
    lines = text.splitlines()
    clean: list[str] = []
    skip_header = True
    for line in lines:
        if skip_header and (
            line.startswith("Loading") or
            line.startswith("✅") or
            line.startswith("Fetching") or
            line.startswith("[AD") or
            line.startswith("[WEB") or
            line.startswith("Prompt:") or
            line.startswith("Generation:") or
            line.startswith("Peak memory:") or
            "mode | RAG" in line
        ):
            continue
        skip_header = False
        clean.append(line)
    # Drop trailing separator lines
    result = "\n".join(clean).strip(" \n─=")
    return result


def run_question(script_name: str, case: dict[str, Any], timeout: int = 180) -> CaseResult:
    domain = case.get("domain", "ad")
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            build_ssh_cmd(script_name, domain, case["question"]),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        raw = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        raw = "[TIMEOUT]"
    duration = round(time.monotonic() - t0, 1)
    answer = extract_answer(raw) if raw != "[TIMEOUT]" else "[TIMEOUT]"
    score, passed, failed = score_response(case, answer)
    return CaseResult(
        id=case["id"],
        domain=domain,
        question=case["question"],
        response=answer,
        score=score,
        passed=passed,
        failed=failed,
        duration_s=duration,
    )


# ── Report ────────────────────────────────────────────────────────────────────

def make_report(results: list[CaseResult], mode: str) -> str:
    total = len(results)
    mean  = round(sum(r.score for r in results) / total, 3) if total else 0.0
    perfect = sum(1 for r in results if r.score == 1.0)
    zero    = sum(1 for r in results if r.score == 0.0)
    lines = [
        f"{'='*70}",
        f"  EVAL REPORT — mode: {mode}",
        f"  Benchmark cases : {total}",
        f"  Mean rubric score: {mean:.3f}",
        f"  Perfect (1.0)    : {perfect}/{total}",
        f"  Zero (0.0)       : {zero}/{total}",
        f"{'='*70}",
        "",
    ]
    sorted_results = sorted(results, key=lambda r: r.score)
    for r in sorted_results:
        bar = "█" * int(r.score * 20) + "░" * (20 - int(r.score * 20))
        lines.append(f"  {r.score:.2f} [{bar}] {r.id}")
        if r.failed:
            for f in r.failed:
                lines.append(f"           ✗ {f}")
    lines += [
        "",
        "─" * 70,
        "Full responses saved to eval_results_{mode}.jsonl".format(mode=mode),
    ]
    return "\n".join(lines)


def compare_reports(baseline_path: Path, improved_path: Path) -> str:
    b = {r["id"]: r for r in [json.loads(l) for l in baseline_path.read_text().splitlines() if l.strip()]}
    i = {r["id"]: r for r in [json.loads(l) for l in improved_path.read_text().splitlines() if l.strip()]}
    ids = sorted(set(b) | set(i))
    lines = [f"{'='*70}", "  COMPARISON: baseline vs improved", f"{'='*70}", ""]
    improved_count = regressed_count = same_count = 0
    for qid in ids:
        bs = b.get(qid, {}).get("score", 0.0)
        im = i.get(qid, {}).get("score", 0.0)
        delta = round(im - bs, 3)
        if delta > 0:
            tag = f"▲ +{delta:.3f}"
            improved_count += 1
        elif delta < 0:
            tag = f"▼ {delta:.3f}"
            regressed_count += 1
        else:
            tag = "  ±0.000"
            same_count += 1
        lines.append(f"  {tag}  {qid:<35}  baseline={bs:.2f} → improved={im:.2f}")
    lines += [
        "",
        f"  Improved : {improved_count}",
        f"  Regressed: {regressed_count}",
        f"  Same     : {same_count}",
        f"  Net Δ mean: {round(sum(i.get(qid,{}).get('score',0)-b.get(qid,{}).get('score',0) for qid in ids)/len(ids), 3)}",
    ]
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["baseline", "improved"], default=None)
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--limit", type=int, default=None,
                        help="Run only first N cases (for quick smoke test)")
    args = parser.parse_args()

    if args.compare:
        bp = RESULTS_DIR / "eval_results_baseline.jsonl"
        ip = RESULTS_DIR / "eval_results_improved.jsonl"
        if not bp.exists() or not ip.exists():
            print("Both baseline and improved results needed for comparison.")
            sys.exit(1)
        print(compare_reports(bp, ip))
        return

    if args.mode is None:
        print("Specify --mode baseline or --mode improved, or --compare")
        sys.exit(1)

    # Script name on Mac
    if args.mode == "baseline":
        script_name = "run_baseline.py"   # backed-up original
    else:
        script_name = "run_improved.py"

    # Verify the script exists on Mac
    check = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", MAC_HOST,
         f"test -f {MAC_DIR}/{script_name} && echo OK || echo MISSING"],
        capture_output=True, text=True, timeout=15,
    )
    if "MISSING" in check.stdout:
        print(f"ERROR: {script_name} not found on Mac at {MAC_DIR}/")
        sys.exit(1)

    cases = [json.loads(l) for l in BENCHMARK_PATH.read_text().splitlines() if l.strip()]
    if args.limit:
        cases = cases[:args.limit]

    results_path = RESULTS_DIR / f"eval_results_{args.mode}.jsonl"
    report_path  = RESULTS_DIR / f"eval_report_{args.mode}.txt"

    # Resume: skip already-done cases
    done_ids: set[str] = set()
    if results_path.exists():
        for line in results_path.read_text().splitlines():
            if line.strip():
                done_ids.add(json.loads(line)["id"])
    remaining = [c for c in cases if c["id"] not in done_ids]

    print(f"Mode: {args.mode}  |  Total: {len(cases)}  |  Done: {len(done_ids)}  |  Remaining: {len(remaining)}")

    results: list[CaseResult] = []
    # Load already-done results for final report
    if results_path.exists():
        for line in results_path.read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                results.append(CaseResult(**d))

    with results_path.open("a") as fout:
        for idx, case in enumerate(remaining, 1):
            print(f"\n[{idx}/{len(remaining)}] {case['id']} ...", flush=True)
            result = run_question(script_name, case, timeout=180)
            results.append(result)
            fout.write(json.dumps(asdict(result)) + "\n")
            fout.flush()
            score_bar = "█" * int(result.score * 20)
            print(f"  score={result.score:.2f}  [{score_bar:<20}]  {result.duration_s}s")
            if result.failed:
                for f in result.failed:
                    print(f"  ✗ {f}")

    report = make_report(results, args.mode)
    report_path.write_text(report)
    print("\n" + report)
    print(f"\nReport saved to {report_path}")


if __name__ == "__main__":
    main()
