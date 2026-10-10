
import ipaddress
import re
from datetime import datetime


UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)

IP_PATTERN = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")

TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)


def validate_answer(answer: str, verified_evidence: list[dict]) -> dict:
    """Check whether identifiers in an AI answer exist in verified evidence."""

    valid_ids = set()
    valid_ips = set()
    valid_timestamps = set()

    for finding in verified_evidence:
        for event in finding.get("events", []):
            evidence_id = event.get("evidence_id")
            source_ip = event.get("source_ip")
            timestamp = event.get("timestamp")

            if evidence_id:
                valid_ids.add(evidence_id.lower())

            if source_ip:
                valid_ips.add(source_ip)

            if timestamp:
                valid_timestamps.add(timestamp)

    issues = []

    # Check evidence IDs.
    for evidence_id in UUID_PATTERN.findall(answer):
        if evidence_id.lower() not in valid_ids:
            issues.append({
                "type": "unknown_evidence_id",
                "value": evidence_id,
            })

    # Check IP addresses.
    for ip in IP_PATTERN.findall(answer):
        try:
            normalized_ip = str(ipaddress.ip_address(ip))
        except ValueError:
            continue

        if normalized_ip not in valid_ips:
            issues.append({
                "type": "unverified_ip_address",
                "value": ip,
            })

    # Check timestamps, normalizing equivalent UTC formats.
    for timestamp in TIMESTAMP_PATTERN.findall(answer):
        try:
            parsed = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        except ValueError:
            continue

        if parsed.tzinfo is None:
            issues.append({
                "type": "timestamp_without_timezone",
                "value": timestamp,
            })
            continue

        normalized = parsed.astimezone().isoformat()

        def to_utc(value: str) -> str:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt.astimezone().isoformat()

        valid_normalized = {
            to_utc(value)
            for value in valid_timestamps
            if value.endswith("Z") or "+" in value[10:] or "-" in value[10:]
        }

        if normalized not in valid_normalized:
            issues.append({
                "type": "unverified_timestamp",
                "value": timestamp,
            })

    return {
        "passed": len(issues) == 0,
        "issue_count": len(issues),
        "issues": issues,
        "scope": (
            "Checks evidence IDs, IP addresses, and timestamps against "
            "verified evidence. It does not verify the meaning of prose."
        ),
    }
