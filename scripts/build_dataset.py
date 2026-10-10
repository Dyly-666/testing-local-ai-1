#!/usr/bin/env python3
"""Build canonical, leakage-aware splits from the audited raw seed corpus."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_assistant.dataset import canonicalize, quality_report, read_jsonl, review_markdown, split_for_group, stable_hash, write_jsonl


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="merged_dataset.jsonl")
    parser.add_argument("--extra-source", action="append", default=[], help="Additional JSONL files appended before canonicalization (e.g. uncensored_examples.jsonl)")
    parser.add_argument("--raw-source", action="append", default=[], help="Optional raw source used for per-record provenance")
    parser.add_argument("--output-dir", default="data/canonical")
    parser.add_argument("--report", default="reports/dataset_quality.json")
    parser.add_argument("--review-queue", default="reports/seed_dataset_review.md")
    args = parser.parse_args()

    source = Path(args.source)
    raw = read_jsonl(source)
    extra_names = args.extra_source or (["uncensored_examples.jsonl"] if Path("uncensored_examples.jsonl").exists() else [])
    for extra in extra_names:
        raw.extend(read_jsonl(Path(extra)))
    all_sources = [source.name] + [Path(e).name for e in extra_names]
    records = canonicalize(raw, all_sources)
    default_raw_sources = [
        "security_audit_dataset.jsonl", "web_security_dataset_local.jsonl",
        "web_security_dataset_batch2.jsonl", "web_security_dataset_batch3.jsonl",
    ]
    source_names = args.raw_source or [name for name in default_raw_sources if Path(name).exists()]
    membership: dict[str, list[str]] = {}
    for name in source_names:
        for row in read_jsonl(Path(name)):
            membership.setdefault(stable_hash(row["messages"]), []).append(Path(name).name)
    for record in records:
        digest = record["metadata"]["provenance"]["raw_content_sha256"]
        record["metadata"]["provenance"]["source_files"] = membership.get(digest, [source.name])
    output = Path(args.output_dir)
    splits = {"train": [], "validation": [], "test": []}
    for record in records:
        splits[split_for_group(record["metadata"]["split_group"])].append(record)
    for split, rows in splits.items():
        write_jsonl(output / f"{split}.jsonl", rows)

    report = quality_report(records)
    report["split_records"] = {name: len(rows) for name, rows in splits.items()}
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    Path(args.review_queue).parent.mkdir(parents=True, exist_ok=True)
    Path(args.review_queue).write_text(review_markdown(records), encoding="utf-8")
    print(json.dumps({"records": len(records), "splits": report["split_records"], "gate": report["quality_gate"]}))


if __name__ == "__main__":
    main()
