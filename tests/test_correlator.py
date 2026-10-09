
from app.correlator import correlate_artifacts


def test_correlates_events_from_different_sources():
    artifacts = [
        {
            "type": "timestamp",
            "value": "2026-10-09T10:30:00Z",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "type": "timestamp",
            "value": "2026-10-09T10:32:00Z",
            "evidence_id": "browser-001",
            "line": 2,
        },
    ]

    findings = correlate_artifacts(artifacts)

    assert len(findings) == 1
    assert findings[0]["type"] == "temporal_proximity"
    assert findings[0]["time_difference_seconds"] == 120
    assert findings[0]["confidence"] == "low"


def test_does_not_correlate_same_evidence_source():
    artifacts = [
        {
            "type": "timestamp",
            "value": "2026-10-09T10:30:00Z",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "type": "timestamp",
            "value": "2026-10-09T10:31:00Z",
            "evidence_id": "auth-001",
            "line": 2,
        },
    ]

    findings = correlate_artifacts(artifacts)

    assert findings == []


def test_ignores_events_outside_time_window():
    artifacts = [
        {
            "type": "timestamp",
            "value": "2026-10-09T10:00:00Z",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "type": "timestamp",
            "value": "2026-10-09T11:00:00Z",
            "evidence_id": "browser-001",
            "line": 2,
        },
    ]

    findings = correlate_artifacts(artifacts)

    assert findings == []


def test_different_users_are_only_temporal_leads():
    from app.correlator import correlate_events

    events = [
        {
            "timestamp": "2026-10-09T10:30:00Z",
            "user": "Alice",
            "event": "successful_login",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "timestamp": "2026-10-09T10:32:00Z",
            "user": "Bob",
            "event": "failed_login",
            "evidence_id": "auth-002",
            "line": 8,
        },
    ]

    findings = correlate_events(events, include_temporal_only=True)

    assert len(findings) == 1
    assert findings[0]["type"] == "temporal_proximity"
    assert findings[0]["signals"] == ["temporal_proximity_only"]


def test_shared_session_is_explicitly_correlated():
    from app.correlator import correlate_events

    events = [
        {
            "timestamp": "2026-10-09T10:30:00Z",
            "session": "sess-123",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "timestamp": "2026-10-09T10:31:00Z",
            "session": "sess-123",
            "evidence_id": "browser-001",
            "line": 4,
        },
    ]

    findings = correlate_events(events)

    assert len(findings) == 1
    assert findings[0]["type"] == "cross_source_event_correlation"
    assert "shared_session" in findings[0]["signals"]
    assert all(event["evidence_id"] for event in findings[0]["events"])


def test_unrelated_events_remain_low_confidence():
    from app.correlator import correlate_events

    events = [
        {
            "timestamp": "2026-10-09T10:30:00Z",
            "user": "Alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "timestamp": "2026-10-09T10:31:00Z",
            "user": "Bob",
            "source_ip": "192.0.2.20",
            "evidence_id": "browser-001",
            "line": 2,
        },
    ]

    findings = correlate_events(events, include_temporal_only=True)

    assert len(findings) == 1
    assert findings[0]["confidence"] == "low"
    assert "temporal_proximity_only" in findings[0]["signals"]
    assert len(findings[0]["events"]) == 2



def test_temporal_only_matches_are_excluded_by_default():
    from app.correlator import correlate_events

    events = [
        {
            "timestamp": "2026-10-09T10:30:00Z",
            "user": "Alice",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "timestamp": "2026-10-09T10:31:00Z",
            "user": "Bob",
            "evidence_id": "browser-001",
            "line": 2,
        },
    ]

    assert correlate_events(events) == []
