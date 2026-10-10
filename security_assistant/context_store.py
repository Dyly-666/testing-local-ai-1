"""Persistent local assessment context; no credentials or tool output is executed."""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


class AssessmentStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                mode TEXT NOT NULL, name TEXT NOT NULL, scope_json TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def create(self, name: str, mode: str, scope: dict) -> str:
        if not scope.get("authorized_targets"):
            raise ValueError("scope.authorized_targets must be a non-empty list")
        assessment_id = uuid.uuid4().hex[:12]
        with self.connection:
            self.connection.execute(
                "INSERT INTO assessments VALUES (?, ?, ?, ?, ?)",
                (assessment_id, datetime.now(timezone.utc).isoformat(), mode, name, json.dumps(scope, sort_keys=True)),
            )
        return assessment_id

    def get(self, assessment_id: str) -> dict:
        row = self.connection.execute("SELECT * FROM assessments WHERE assessment_id = ?", (assessment_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown assessment id: {assessment_id}")
        result = dict(row)
        result["scope"] = json.loads(result.pop("scope_json"))
        return result
