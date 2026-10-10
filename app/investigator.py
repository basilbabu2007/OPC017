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


def run_investigation(events):
    """Run deterministic analysis and recommend evidence-linked next steps."""
    report = build_investigation(events)

    playbook = {
        "FAILED_LOGINS_THEN_SUCCESS": {
            "rank": 1,
            "priority": "high",
            "actions": [
                "Verify whether the successful login was authorized.",
                "Compare the login source IP, timestamp and session with other evidence.",
                "Check for suspicious activity after the successful login.",
            ],
        },
        "REPEATED_FAILED_LOGINS": {
            "rank": 2,
            "priority": "medium",
            "actions": [
                "Check whether successful logins followed the failed attempts.",
                "Compare source IPs and timestamps with other authentication evidence.",
            ],
        },
        "ACCOUNT_MULTIPLE_IPS": {
            "rank": 3,
            "priority": "low",
            "actions": [
                "Compare login times and IP addresses with other evidence sources.",
                "Check whether VPN use, proxies or legitimate travel explain the pattern.",
            ],
        },
    }

    next_actions = []

    for observation in report["observations"]:
        rule_id = observation["rule_id"]
        guidance = playbook.get(rule_id)

        if guidance is None:
            guidance = {
                "rank": 99,
                "priority": "low",
                "actions": [
                    "Review the supporting events and gather corroborating evidence."
                ],
            }

        observation["review_priority"] = guidance["priority"]
        observation["recommended_actions"] = guidance["actions"]

        evidence_refs = []
        seen = set()

        for event in observation.get("supporting_events", []):
            ref = {
                "evidence_id": event.get("evidence_id"),
                "line": event.get("line"),
            }
            key = (ref["evidence_id"], ref["line"])

            if key not in seen:
                seen.add(key)
                evidence_refs.append(ref)

        next_actions.append({
            "rule_id": rule_id,
            "title": observation["title"],
            "priority": guidance["priority"],
            "recommended_actions": guidance["actions"],
            "supporting_evidence": evidence_refs,
        })

    priority_order = {"high": 0, "medium": 1, "low": 2}

    next_actions.sort(
        key=lambda item: priority_order[item["priority"]]
    )

    report["next_actions"] = next_actions
    report["agent"] = {
        "mode": "deterministic",
        "observations_ranked": len(report["observations"]),
        "actions_recommended": len(next_actions),
        "note": (
            "Recommendations are rule-based investigative leads. "
            "An investigator must validate them before drawing conclusions."
        ),
    }

    report["followup_checks"] = plan_followup_checks(
        events,
        report["observations"],
    )

    return report


def plan_followup_checks(events, observations):
    """Select and run bounded follow-up checks against supplied events."""
    plans = []

    for observation in observations:
        rule_id = observation.get("rule_id")
        account = observation.get("account")
        supporting = observation.get("supporting_events", [])

        source_ips = {
            event.get("source_ip")
            for event in supporting
            if event.get("source_ip")
        }

        checks = []

        if rule_id in {
            "FAILED_LOGINS_THEN_SUCCESS",
            "REPEATED_FAILED_LOGINS",
            "ACCOUNT_MULTIPLE_IPS",
        } and account:
            checks.append(("ACCOUNT_ACTIVITY", lambda event:
                event.get("user") == account))

        if source_ips:
            checks.append(("SOURCE_IP_ACTIVITY", lambda event:
                event.get("source_ip") in source_ips))

        if rule_id == "FAILED_LOGINS_THEN_SUCCESS":
            success_events = [
                event for event in supporting
                if (
                    str(event.get("event") or "").lower()
                    in {
                        "successful_login",
                        "login_success",
                        "successful_authentication",
                        "login_succeeded",
                    }
                    or str(
                        (event.get("details") or {}).get("status") or ""
                    ).lower() in {"success", "successful", "accepted"}
                )
            ]

            if success_events:
                from datetime import datetime, timezone

                success_times = []
                for event in success_events:
                    value = event.get("timestamp")
                    if not value:
                        continue
                    try:
                        parsed = datetime.fromisoformat(
                            str(value).replace("Z", "+00:00")
                        )
                        if parsed.tzinfo is not None:
                            parsed = parsed.astimezone(
                                timezone.utc
                            ).replace(tzinfo=None)
                        success_times.append(parsed)
                    except (ValueError, TypeError):
                        continue

                if success_times:
                    latest_success = max(success_times)

                    def after_success(event):
                        if event.get("user") != account:
                            return False
                        value = event.get("timestamp")
                        if not value:
                            return False
                        try:
                            parsed = datetime.fromisoformat(
                                str(value).replace("Z", "+00:00")
                            )
                            if parsed.tzinfo is not None:
                                parsed = parsed.astimezone(
                                    timezone.utc
                                ).replace(tzinfo=None)
                            return parsed > latest_success
                        except (ValueError, TypeError):
                            return False

                    checks.append(("POST_LOGIN_ACTIVITY", after_success))

        check_results = []

        for check_name, predicate in checks:
            matches = [
                {
                    "evidence_id": event.get("evidence_id"),
                    "line": event.get("line"),
                    "timestamp": event.get("timestamp"),
                    "event": event.get("event"),
                    "user": event.get("user"),
                    "source_ip": event.get("source_ip"),
                }
                for event in events
                if predicate(event)
            ]

            check_results.append({
                "check": check_name,
                "match_count": len(matches),
                "matches": matches,
            })

        plans.append({
            "rule_id": rule_id,
            "title": observation.get("title"),
            "checks_executed": len(check_results),
            "results": check_results,
        })

    return plans
