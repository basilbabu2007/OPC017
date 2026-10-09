from collections import defaultdict


def build_investigation(events):
    """Build a deterministic, evidence-linked investigation report."""
    observations = []
    questions = []
    accounts = defaultdict(list)
    failed_logins = defaultdict(list)
    valid_times = []

    for index, event in enumerate(events, start=1):
        item = {
            "event_number": index,
            "evidence_id": event.get("evidence_id"),
            "source_type": event.get("source_type"),
            "line": event.get("line"),
            "timestamp": event.get("timestamp"),
            "event": event.get("event"),
            "user": event.get("user"),
            "source_ip": event.get("source_ip"),
        }

        timestamp = event.get("timestamp")
        if timestamp:
            valid_times.append(timestamp)

        user = event.get("user")
        ip = event.get("source_ip")
        event_name = str(event.get("event") or "").lower()
        details = event.get("details") or {}
        status = str(details.get("status") or "").lower()

        if user and ip and event_name in {
            "login", "log_in", "authentication", "auth"
        }:
            accounts[user].append((ip, item))

        if (
            user
            and (
                status in {"failed", "failure", "denied"}
                or event_name in {"failed_login", "login_failed", "authentication_failed"}
            )
        ):
            failed_logins[user].append(item)

    for user, entries in accounts.items():
        ips = sorted({ip for ip, _ in entries})
        if len(ips) < 2:
            continue

        observations.append({
            "rule_id": "ACCOUNT_MULTIPLE_IPS",
            "title": "Account observed from multiple IP addresses",
            "category": "authentication",
            "priority": "review",
            "confidence": "low",
            "account": user,
            "ip_addresses": ips,
            "supporting_events": [item for _, item in entries],
            "explanation": (
                f"Account '{user}' appears in login-related events from "
                f"{len(ips)} different IP addresses."
            ),
            "limitations": (
                "Multiple IP addresses can result from mobile networks, VPNs, "
                "proxies, or legitimate travel. This does not prove compromise."
            ),
        })

        questions.append({
            "question": f"Can the IP addresses observed for account '{user}' "
                        "be verified against other evidence sources?",
            "reason": "The same account appears with multiple IP addresses.",
            "supporting_rule": "ACCOUNT_MULTIPLE_IPS",
        })

    for user, entries in failed_logins.items():
        if len(entries) < 3:
            continue

        observations.append({
            "rule_id": "REPEATED_FAILED_LOGINS",
            "title": "Repeated failed logins for one account",
            "category": "authentication",
            "priority": "review",
            "confidence": "low",
            "account": user,
            "failed_attempt_count": len(entries),
            "supporting_events": entries,
            "explanation": (
                f"{len(entries)} failed-login events were found for account "
                f"'{user}' in the analyzed evidence."
            ),
            "limitations": (
                "Repeated failures can have benign causes. The current rule "
                "counts available events and does not establish intent or "
                "whether attempts occurred within a particular time window."
            ),
        })

        questions.append({
            "question": f"Are there successful logins for '{user}' near "
                        "these failed attempts?",
            "reason": "Repeated failed-login events were observed.",
            "supporting_rule": "REPEATED_FAILED_LOGINS",
        })

    # Detect at least 3 failed logins followed by success within 10 minutes.
    from datetime import datetime, timezone

    login_events = defaultdict(list)

    for event in events:
        user = event.get("user")
        timestamp = event.get("timestamp")
        if not user or not timestamp:
            continue

        try:
            parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue

        name = str(event.get("event") or "").lower()
        details = event.get("details") or {}
        status = str(details.get("status") or "").lower()

        failed = (
            status in {"failed", "failure", "denied"}
            or name in {"failed_login", "login_failed", "authentication_failed"}
        )
        success = (
            status in {"success", "successful", "accepted"}
            or name in {
                "successful_login", "login_success",
                "successful_authentication", "login_succeeded",
            }
        )

        if failed or success:
            login_events[user].append((
                parsed, "failed" if failed else "success", event
            ))

    for user, activity in login_events.items():
        activity.sort(key=lambda row: row[0])

        for success_time, outcome, success_event in activity:
            if outcome != "success":
                continue

            failures = [
                row[2] for row in activity
                if row[1] == "failed"
                and 0 <= (success_time - row[0]).total_seconds() <= 600
            ]

            if len(failures) < 3:
                continue

            observations.append({
                "rule_id": "FAILED_LOGINS_THEN_SUCCESS",
                "title": "Successful login after repeated failures",
                "category": "authentication",
                "priority": "review",
                "confidence": "low",
                "account": user,
                "failed_attempt_count": len(failures),
                "window_seconds": 600,
                "supporting_events": failures + [success_event],
                "explanation": (
                    f"Account '{user}' had at least three failed login "
                    "events within 10 minutes before a successful login."
                ),
                "limitations": (
                    "This pattern can have legitimate causes and does not "
                    "prove unauthorized access or account compromise."
                ),
            })
            questions.append({
                "question": f"Was the successful login for '{user}' authorized?",
                "reason": "Repeated login failures preceded a success.",
                "supporting_rule": "FAILED_LOGINS_THEN_SUCCESS",
            })
            break

    if not events:
        summary = "No timestamped events were available for investigation."
    else:
        summary = (
            f"Analyzed {len(events)} timestamped events. "
            f"Generated {len(observations)} rule-based observations."
        )

    if not observations:
        questions.append({
            "question": "Are there additional logs or evidence sources to analyze?",
            "reason": "No configured investigation rules matched the available events.",
            "supporting_rule": None,
        })

    return {
        "summary": summary,
        "time_range": {
            "start": min(valid_times) if valid_times else None,
            "end": max(valid_times) if valid_times else None,
        },
        "observation_count": len(observations),
        "observations": observations,
        "investigative_questions": questions,
        "method": "Deterministic rules; no AI-generated conclusions.",
        "limitations": (
            "Findings depend on the fields extracted from the supplied evidence. "
            "Absence of a finding does not establish that activity was benign."
        ),
    }
