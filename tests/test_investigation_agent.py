from app.investigator import run_investigation


def test_agent_recommends_evidence_linked_actions():
    events = []

    for minute in range(3):
        events.append({
            "timestamp": f"2026-10-09T10:0{minute}:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": minute + 1,
            "details": {"status": "failed"},
        })

    events.append({
        "timestamp": "2026-10-09T10:04:00Z",
        "event": "successful_login",
        "user": "alice",
        "source_ip": "192.0.2.10",
        "evidence_id": "auth-001",
        "line": 4,
        "details": {"status": "success"},
    })

    report = run_investigation(events)

    assert report["agent"]["mode"] == "deterministic"

    lead = next(
        item for item in report["next_actions"]
        if item["rule_id"] == "FAILED_LOGINS_THEN_SUCCESS"
    )

    assert lead["priority"] == "high"
    assert lead["supporting_evidence"]
    assert lead["recommended_actions"]
    assert len(lead["supporting_evidence"]) == 4
