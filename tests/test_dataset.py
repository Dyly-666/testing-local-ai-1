import json
from pathlib import Path

from security_assistant.dataset import canonicalize, quality_report, read_jsonl, scenario_family


def test_merged_seed_has_expected_unique_records():
    records = canonicalize(read_jsonl(Path("merged_dataset.jsonl")), ["merged_dataset.jsonl"])
    assert len(records) == 34
    assert {record["metadata"]["review_status"] for record in records} == {"needs_expert_review"}
    assert scenario_family("How do I assess AD CS ESC1?") == "active_directory"


def test_quality_report_is_honest_about_review_gate():
    records = canonicalize(read_jsonl(Path("merged_dataset.jsonl")), ["merged_dataset.jsonl"])
    report = quality_report(records)
    assert report["quality_gate"] == "blocked_pending_expert_review"
    assert report["domain_counts"]["active_directory"] >= 2


def test_split_groups_do_not_leak():
    records = canonicalize(read_jsonl(Path("merged_dataset.jsonl")), ["merged_dataset.jsonl"])
    from security_assistant.dataset import split_for_group
    seen = {}
    for record in records:
        group = record["metadata"]["split_group"]
        split = split_for_group(group)
        assert seen.setdefault(group, split) == split
