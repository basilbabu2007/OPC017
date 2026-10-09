
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
