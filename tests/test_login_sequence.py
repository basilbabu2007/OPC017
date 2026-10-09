from app.investigator import build_investigation

def test_failed_logins_followed_by_success():
    events = []

    for i, minute in enumerate([0, 1, 2], start=1):
        events.append({
            "timestamp": f"2026-10-09T10:0{minute}:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": i,
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

    report = build_investigation(events)
    matches = [
        item for item in report["observations"]
        if item["rule_id"] == "FAILED_LOGINS_THEN_SUCCESS"
    ]

    assert len(matches) == 1
    assert matches[0]["failed_attempt_count"] == 3
    assert len(matches[0]["supporting_events"]) == 4
