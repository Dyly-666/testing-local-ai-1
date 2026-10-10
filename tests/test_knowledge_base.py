from security_assistant.knowledge_base import KnowledgeBase


def test_ingest_deduplicates_and_labels_raw_sources(tmp_path):
    kb = KnowledgeBase(tmp_path / "kb.sqlite3")
    try:
        first = kb.ingest(title="Test", source_url="https://example.test/ref", source_version="1", retrieved_at="2026-10-10", trust_level="raw", content="LDAP signing protects directory queries")
        second = kb.ingest(title="Duplicate", source_url="https://example.test/ref", source_version="1", retrieved_at="2026-10-10", trust_level="raw", content="LDAP signing protects directory queries")
        assert first == second
        result = kb.search("LDAP signing")
        assert len(result) == 1
        assert result[0].trust_level == "raw"
        assert result[0].confidence == "low"
    finally:
        kb.close()
