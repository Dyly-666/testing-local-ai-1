from security_assistant.context_store import AssessmentStore


def test_assessment_context_requires_explicit_targets(tmp_path):
    store = AssessmentStore(tmp_path / "assessments.sqlite3")
    try:
        try:
            store.create("bad", "web", {})
        except ValueError:
            pass
        else:
            raise AssertionError("scope without targets was accepted")
        assessment_id = store.create("good", "web", {"authorized_targets": ["https://lab.test"]})
        assert store.get(assessment_id)["scope"]["authorized_targets"] == ["https://lab.test"]
    finally:
        store.close()
