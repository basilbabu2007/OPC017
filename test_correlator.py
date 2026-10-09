
from correlator import correlate_artifacts


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
