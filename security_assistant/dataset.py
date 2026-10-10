"""Canonical dataset construction and conservative quality checks."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from security_assistant.prompts import SYSTEM_PROMPT

REQUIRED_ROLES = ("system", "user", "assistant")


@dataclass(frozen=True)
class QualityIssue:
    record_id: str
    severity: str
    message: str


def stable_hash(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{number}: invalid JSON: {error.msg}") from error
    return records


def message_text(record: dict[str, Any], role: str) -> str:
    for message in record.get("messages", []):
        if message.get("role") == role:
            return str(message.get("content", ""))
    return ""


def scenario_family(question: str) -> str:
    q = question.lower()
    families = {
        "sql_injection": ("sql injection", "sqli"),
        "xss": ("xss", "cross-site scripting", "cross site scripting"),
        "idor_bola": ("idor", "bola", "object reference"),
        "ssrf": ("ssrf", "server-side request forgery"),
        "active_directory": ("active directory", "kerberoast", "ad cs", "certipy", "bloodhound"),
        "authentication": ("jwt", "oauth", "session", "password reset"),
        "access_control": ("bfla", "mass assignment", "authorization"),
        "file_handling": ("file upload", "path traversal", "xxe", "deserialization", "ssti"),
        "web_configuration": ("cors", "security headers", "clickjacking", "rate limit", "open redirect"),
    }
    for family, markers in families.items():
        if any(marker in q for marker in markers):
            return family
    return "general_assessment"


def domain_for(question: str) -> str:
    family = scenario_family(question)
    return "active_directory" if family == "active_directory" else "web_application_security"


def task_type_for(question: str) -> str:
    q = question.lower()
    if "report" in q or "finding" in q:
        return "security_reporting"
    if "remediation" in q or "fix" in q:
        return "remediation_guidance"
    if "analy" in q or "attack-path" in q or "attack path" in q:
        return "evidence_analysis"
    return "validation_planning"


def quality_issues(record: dict[str, Any]) -> list[QualityIssue]:
    record_id = str(record.get("id", "unknown"))
    messages = record.get("messages")
    issues: list[QualityIssue] = []
    if not isinstance(messages, list) or len(messages) != 3:
        return [QualityIssue(record_id, "error", "must contain exactly three messages")]
    roles = tuple(item.get("role") for item in messages)
    if roles != REQUIRED_ROLES:
        issues.append(QualityIssue(record_id, "error", f"roles must be {REQUIRED_ROLES}, got {roles}"))
    for role in REQUIRED_ROLES:
        text = message_text(record, role).strip()
        if not text:
            issues.append(QualityIssue(record_id, "error", f"{role} content is empty"))
    answer = message_text(record, "assistant")
    if len(answer) < 300:
        issues.append(QualityIssue(record_id, "warning", "assistant answer is unusually short"))
    if re.search(r"(?:password|api[_ -]?key|token)\s*[:=]\s*['\"][^'\"]{8,}", answer, re.I):
        issues.append(QualityIssue(record_id, "warning", "possible secret-like literal in answer"))
    if "confirmed" in answer.lower() and "evidence" not in answer.lower():
        issues.append(QualityIssue(record_id, "warning", "confirmation language has no evidence qualifier"))
    return issues


def split_for_group(group: str) -> str:
    # Group assignment prevents a technique family from appearing in both train and test.
    bucket = int(stable_hash(group)[:8], 16) % 100
    return "test" if bucket < 20 else "validation" if bucket < 35 else "train"


def canonicalize(records: Iterable[dict[str, Any]], source_paths: list[str]) -> list[dict[str, Any]]:
    canonical = []
    seen: set[str] = set()
    for source_index, record in enumerate(records, start=1):
        raw_messages = record.get("messages", [])
        content_hash = stable_hash(raw_messages)
        if content_hash in seen:
            continue
        seen.add(content_hash)
        if [message.get("role") for message in raw_messages] != list(REQUIRED_ROLES):
            # Preserve invalid records for the quality report without attempting
            # to coerce unknown conversational formats into training data.
            messages = raw_messages
        else:
            # One canonical prompt is used by both trainer and CLI inference.
            messages = [{"role": "system", "content": SYSTEM_PROMPT}, raw_messages[1], raw_messages[2]]
        question = message_text({"messages": messages}, "user")
        family = scenario_family(question)
        record_id = f"seed-{source_index:03d}-{content_hash[:10]}"
        canonical.append(
            {
                "id": record_id,
                "messages": messages,
                "metadata": {
                    "schema_version": "1.0",
                    "dataset_version": "seed-0.1.0",
                    "provenance": {
                        "source_files": source_paths,
                        "raw_content_sha256": content_hash,
                        "original_system_prompt_sha256": stable_hash(raw_messages[0].get("content", "")) if raw_messages else None,
                    },
                    "domain": domain_for(question),
                    "scenario_family": family,
                    "task_type": task_type_for(question),
                    "split_group": family,
                    "review_status": "needs_expert_review",
                    "license_status": "internal_seed_content_unverified",
                    "evidence_policy": "never_claim_unprovided_evidence",
                },
            }
        )
    return canonical


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def quality_report(records: list[dict[str, Any]]) -> dict[str, Any]:
    issues = [issue for record in records for issue in quality_issues(record)]
    domains = Counter(record["metadata"]["domain"] for record in records)
    families = Counter(record["metadata"]["scenario_family"] for record in records)
    splits = Counter(split_for_group(record["metadata"]["split_group"]) for record in records)
    return {
        "record_count": len(records),
        "domain_counts": dict(domains),
        "scenario_family_counts": dict(families),
        "record_split_counts": dict(splits),
        "review_status_counts": Counter(record["metadata"]["review_status"] for record in records),
        "issues": [asdict(issue) for issue in issues],
        "quality_gate": "blocked_pending_expert_review" if records else "blocked_empty_dataset",
    }


def review_markdown(records: list[dict[str, Any]]) -> str:
    """Human-review queue. This inventory is deliberately not an approval."""
    lines = [
        "# Seed dataset review queue", "",
        "All records below were structurally checked and deduplicated, but **none are expert-approved**. "
        "Review factual accuracy, operational safety, provenance/licensing, and answer quality before changing "
        "`review_status` to `approved`.", "",
        "| ID | Domain | Scenario family | Task | Status | Question |", "|---|---|---|---|---|---|",
    ]
    for record in records:
        metadata = record["metadata"]
        question = " ".join(message_text(record, "user").split())[:140].replace("|", "\\|")
        lines.append(
            f"| `{record['id']}` | {metadata['domain']} | {metadata['scenario_family']} | "
            f"{metadata['task_type']} | {metadata['review_status']} | {question} |"
        )
    lines.extend(["", "## Automated warnings", ""])
    issues = [issue for record in records for issue in quality_issues(record)]
    if not issues:
        lines.append("No structural warnings.")
    else:
        for issue in issues:
            lines.append(f"- `{issue.record_id}` — {issue.severity}: {issue.message}")
    return "\n".join(lines) + "\n"
