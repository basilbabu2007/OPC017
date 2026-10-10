from app.investigator import plan_followup_checks
from app.investigator import run_investigation

def test_planner_finds_account_and_ip_activity():
    events = [
        {
            "timestamp": "2026-10-09T10:00:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "timestamp": "2026-10-09T10:05:00Z",
            "event": "file_access",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "system-001",
            "line": 8,
        },
        {
            "timestamp": "2026-10-09T10:06:00Z",
            "event": "login",
            "user": "bob",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-002",
            "line": 3,
        },
    ]

    observations = [{
        "rule_id": "REPEATED_FAILED_LOGINS",
        "title": "Repeated failed logins",
        "account": "alice",
        "supporting_events": [events[0]],
    }]

    plans = plan_followup_checks(events, observations)

    assert len(plans) == 1
    results = {
        result["check"]: result
        for result in plans[0]["results"]
    }

    assert results["ACCOUNT_ACTIVITY"]["match_count"] == 2
    assert results["SOURCE_IP_ACTIVITY"]["match_count"] == 3
    assert results["ACCOUNT_ACTIVITY"]["matches"][1]["evidence_id"] == "system-001"


def test_post_login_check_ignores_other_users():
    events = [
        {
            "timestamp": "2026-10-09T10:00:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": 1,
        },
        {
            "timestamp": "2026-10-09T10:02:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": 2,
        },
        {
            "timestamp": "2026-10-09T10:03:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": 3,
        },
        {
            "timestamp": "2026-10-09T10:04:00Z",
            "event": "successful_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": 4,
        },
        {
            "timestamp": "2026-10-09T10:05:00Z",
            "event": "file_access",
            "user": "bob",
            "source_ip": "192.0.2.20",
            "evidence_id": "system-001",
            "line": 5,
        },
        {
            "timestamp": "2026-10-09T10:06:00Z",
            "event": "file_access",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "system-001",
            "line": 6,
        },
    ]

    observations = [{
        "rule_id": "FAILED_LOGINS_THEN_SUCCESS",
        "title": "Successful login after repeated failures",
        "account": "alice",
        "supporting_events": events[:4],
    }]

    plans = plan_followup_checks(events, observations)

    post_login = next(
        result
        for result in plans[0]["results"]
        if result["check"] == "POST_LOGIN_ACTIVITY"
    )

    assert post_login["match_count"] == 1
    assert post_login["matches"][0]["user"] == "alice"


def test_run_investigation_includes_followup_checks():
    events = [
        {
            "timestamp": f"2026-10-09T10:0{i}:00Z",
            "event": "failed_login",
            "user": "alice",
            "source_ip": "192.0.2.10",
            "evidence_id": "auth-001",
            "line": i + 1,
        }
        for i in range(3)
    ]

    events.append({
        "timestamp": "2026-10-09T10:04:00Z",
        "event": "successful_login",
        "user": "alice",
        "source_ip": "192.0.2.10",
        "evidence_id": "auth-001",
        "line": 4,
    })

    report = run_investigation(events)

    assert "followup_checks" in report
    assert len(report["followup_checks"]) >= 1
    assert report["agent"]["mode"] == "deterministic"
