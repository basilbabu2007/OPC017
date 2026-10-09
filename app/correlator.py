
from datetime import datetime


def parse_timestamp(value):
    """Convert a timestamp string into a datetime, if valid."""
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except (ValueError, TypeError):
        return None


def correlate_artifacts(artifacts, window_seconds=300):
    """
    Find timestamped artifacts from different evidence sources
    that occur within the specified time window.

    A temporal match is a lead for investigation, not proof
    that the events are causally related.
    """
    events = []

    for artifact in artifacts:
        timestamp = parse_timestamp(artifact.get("value"))

        if artifact.get("type") != "timestamp" or timestamp is None:
            continue

        events.append({
            "timestamp": timestamp,
            "evidence_id": artifact.get("evidence_id"),
            "line": artifact.get("line"),
            "source_type": artifact.get("source_type", "unknown"),
        })

    findings = []
    seen = set()

    for index, first in enumerate(events):
        for second in events[index + 1:]:
            # Don't correlate an evidence item with itself.
            if first["evidence_id"] == second["evidence_id"]:
                continue

            # Python cannot directly compare naive and timezone-aware
            # datetimes. Skip those pairs until timestamps are normalized.
            if (
                (first["timestamp"].tzinfo is None)
                != (second["timestamp"].tzinfo is None)
            ):
                continue

            difference = abs(
                (first["timestamp"] - second["timestamp"]).total_seconds()
            )

            if difference > window_seconds:
                continue

            pair = tuple(sorted([
                (first["evidence_id"], first["line"]),
                (second["evidence_id"], second["line"]),
            ]))

            if pair in seen:
                continue

            seen.add(pair)

            findings.append({
                "type": "temporal_proximity",
                "confidence": "low",
                "time_difference_seconds": difference,
                "description": (
                    "Events from different evidence sources occurred "
                    "within the configured time window. This is a "
                    "potential lead, not proof of a relationship."
                ),
                "events": [
                    {
                        "timestamp": first["timestamp"].isoformat(),
                        "evidence_id": first["evidence_id"],
                        "line": first["line"],
                    },
                    {
                        "timestamp": second["timestamp"].isoformat(),
                        "evidence_id": second["evidence_id"],
                        "line": second["line"],
                    },
                ],
            })

    return findings


def correlate_events(events, window_seconds=300):
    """Link events across evidence sources using shared identifiers and time."""
    findings = []
    seen = set()
    normalized = []

    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))
        if timestamp is None:
            continue

        # Normalize timezone-aware timestamps to UTC.
        if timestamp.tzinfo is not None:
            from datetime import timezone
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

        item = dict(event)
        item["_parsed_timestamp"] = timestamp
        normalized.append(item)

    for index, first in enumerate(normalized):
        for second in normalized[index + 1:]:
            if first.get("evidence_id") == second.get("evidence_id"):
                continue

            difference = abs(
                (first["_parsed_timestamp"] - second["_parsed_timestamp"])
                .total_seconds()
            )
            if difference > window_seconds:
                continue

            signals = []
            for field, label in (
                ("user", "shared_account"),
                ("session", "shared_session"),
                ("source_ip", "shared_source_ip"),
            ):
                left = first.get(field)
                right = second.get(field)
                if (
                    isinstance(left, str)
                    and isinstance(right, str)
                    and left.strip()
                    and left.strip().casefold() == right.strip().casefold()
                ):
                    signals.append(label)

            # Keep temporal matches even when no identifier is shared.
            # These are weaker leads and must be labeled accordingly.
            has_strong_identifier = any(
                s in signals for s in ("shared_session", "shared_source_ip")
            )
            correlation_type = (
                "cross_source_event_correlation"
                if has_strong_identifier
                else "temporal_proximity"
            )

            ids = sorted([
                (str(first.get("evidence_id")), str(first.get("line"))),
                (str(second.get("evidence_id")), str(second.get("line"))),
            ])
            key = (tuple(ids), tuple(sorted(signals)))
            if key in seen:
                continue
            seen.add(key)

            def public_event(item):
                return {
                    "timestamp": item["timestamp"],
                    "event": item.get("event"),
                    "user": item.get("user"),
                    "source_ip": item.get("source_ip"),
                    "session": item.get("session"),
                    "evidence_id": item.get("evidence_id"),
                    "source_type": item.get("source_type"),
                    "line": item.get("line"),
                    "details": item.get("details", {}),
                }

            if has_strong_identifier:
                description = (
                    "Events from different evidence sources share a session "
                    "or source IP and fall within the selected time window. "
                    "This is an investigative lead, not proof of compromise."
                )
            else:
                description = (
                    "Events from different evidence sources occurred within "
                    "the selected time window, but no shared session or source "
                    "IP was identified. Time proximity alone is weak evidence "
                    "and does not establish a relationship."
                )

            findings.append({
                "type": correlation_type,
                "confidence": "low",
                "signals": signals or ["temporal_proximity_only"],
                "time_difference_seconds": difference,
                "description": description,
                "events": [public_event(first), public_event(second)],
            })
            continue

            ids = sorted([
                (str(first.get("evidence_id")), str(first.get("line"))),
                (str(second.get("evidence_id")), str(second.get("line"))),
            ])
            key = (tuple(ids), tuple(sorted(signals)))
            if key in seen:
                continue
            seen.add(key)

            def public_event(item):
                return {
                    "timestamp": item["timestamp"],
                    "event": item.get("event"),
                    "user": item.get("user"),
                    "source_ip": item.get("source_ip"),
                    "session": item.get("session"),
                    "evidence_id": item.get("evidence_id"),
                    "source_type": item.get("source_type"),
                    "line": item.get("line"),
                    "details": item.get("details", {}),
                }

            findings.append({
                "type": "cross_source_event_correlation",
                "confidence": "low",
                "signals": signals,
                "time_difference_seconds": difference,
                "description": (
                    "Events from different evidence sources share "
                    "a session or source IP and fall within the selected "
                    "time window. This is an investigative lead, not proof "
                    "of compromise or causation."
                ),
                "events": [public_event(first), public_event(second)],
            })

    findings.sort(key=lambda item: item["events"][0]["timestamp"])
    return findings
