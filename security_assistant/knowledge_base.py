"""Small local, attributable knowledge base using SQLite FTS5.

This is intentionally lexical and dependency-light. It provides a reviewable
baseline before adding an embedding model or external vector service.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SearchResult:
    document_id: str
    title: str
    source_url: str
    version: str
    trust_level: str
    confidence: str
    excerpt: str


class KnowledgeBase:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._initialize()

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source_url TEXT NOT NULL,
                source_version TEXT NOT NULL,
                retrieved_at TEXT NOT NULL,
                trust_level TEXT NOT NULL CHECK(trust_level IN ('raw', 'reviewed')),
                content_sha256 TEXT NOT NULL UNIQUE,
                content TEXT NOT NULL
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS documents_fts USING fts5(
                document_id UNINDEXED, title, content, tokenize='unicode61'
            );
            """
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def ingest(
        self, *, title: str, source_url: str, source_version: str, retrieved_at: str,
        trust_level: str, content: str,
    ) -> str:
        if trust_level not in {"raw", "reviewed"}:
            raise ValueError("trust_level must be raw or reviewed")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        document_id = digest[:16]
        with self.connection:
            existing = self.connection.execute(
                "SELECT document_id FROM documents WHERE content_sha256 = ?", (digest,)
            ).fetchone()
            if existing:
                return str(existing["document_id"])
            self.connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (document_id, title, source_url, source_version, retrieved_at, trust_level, digest, content),
            )
            self.connection.execute(
                "INSERT INTO documents_fts VALUES (?, ?, ?)", (document_id, title, content)
            )
        return document_id

    def search(self, query: str, limit: int = 5, reviewed_only: bool = False) -> list[SearchResult]:
        if not query.strip():
            return []
        filters = "AND d.trust_level = 'reviewed'" if reviewed_only else ""
        rows = self.connection.execute(
            f"""
            SELECT d.*, snippet(documents_fts, 2, '[', ']', '…', 32) AS excerpt,
                   bm25(documents_fts) AS rank
            FROM documents_fts
            JOIN documents d ON d.document_id = documents_fts.document_id
            WHERE documents_fts MATCH ? {filters}
            ORDER BY rank LIMIT ?
            """,
            (query, limit),
        ).fetchall()
        results = []
        for index, row in enumerate(rows):
            confidence = "high" if row["trust_level"] == "reviewed" and index == 0 else "medium"
            if row["trust_level"] == "raw":
                confidence = "low"
            results.append(
                SearchResult(
                    document_id=row["document_id"], title=row["title"], source_url=row["source_url"],
                    version=row["source_version"], trust_level=row["trust_level"], confidence=confidence,
                    excerpt=row["excerpt"],
                )
            )
        return results
