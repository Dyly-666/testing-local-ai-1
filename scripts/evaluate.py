#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

from security_assistant.evaluation import score_run


parser = argparse.ArgumentParser()
parser.add_argument("--benchmark", default="data/benchmarks/held_out.jsonl")
parser.add_argument("--responses", required=True, help="JSONL: {id, response}; capture one file per model condition")
parser.add_argument("--report", default="reports/evaluations/latest.json")
args = parser.parse_args()
result = score_run(args.benchmark, args.responses)
Path(args.report).parent.mkdir(parents=True, exist_ok=True)
Path(args.report).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
