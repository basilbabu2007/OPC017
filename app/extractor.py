
import csv
import io
import json
import re
from datetime import datetime


IP_PATTERN = re.compile(
    r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
)

URL_PATTERN = re.compile(r"https?://[^\s,'\"<>]+")

TIME_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)


def valid_timestamp(value):
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        datetime.fromisoformat(normalized)
        return value
    except ValueError:
        return None


def extract_from_text(text):
    artifacts = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        timestamp_match = TIME_PATTERN.search(line)
        timestamp = (
            valid_timestamp(timestamp_match.group())
            if timestamp_match
            else None
        )

        if timestamp:
            artifacts.append({
                "type": "timestamp",
                "value": timestamp,
                "line": line_number,
            })

        for ip in IP_PATTERN.findall(line):
            octets = ip.split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                artifacts.append({
                    "type": "ip_address",
                    "value": ip,
                    "line": line_number,
                })

        for url in URL_PATTERN.findall(line):
            artifacts.append({
                "type": "url",
                "value": url.rstrip(".,);"),
                "line": line_number,
            })

        username_match = re.search(
            r"\buser(?:name)?=([A-Za-z0-9_.@-]+)",
            line,
            re.IGNORECASE,
        )

        if username_match:
            artifacts.append({
                "type": "username",
                "value": username_match.group(1),
                "line": line_number,
            })

    return artifacts


def remove_duplicates(artifacts):
    unique_artifacts = []
    seen = set()

    for artifact in artifacts:
        key = (
            artifact["type"],
            artifact["value"],
            artifact["line"],
        )

        if key not in seen:
            seen.add(key)
            unique_artifacts.append(artifact)

    return unique_artifacts


def extract_artifacts(filename, data):
    extension = filename.lower().rsplit(".", 1)[-1]
    text = data.decode("utf-8-sig", errors="replace")

    if extension in {"txt", "log", "eml"}:
        return remove_duplicates(extract_from_text(text))

    if extension == "csv":
        rows = csv.DictReader(io.StringIO(text))
        artifacts = []

        for row_number, row in enumerate(rows, start=2):
            for column, value in row.items():
                if not value:
                    continue

                column_name = (column or "").strip().lower()

                # Extract timestamp columns exactly once.
                if column_name in {
                    "timestamp", "time", "datetime", "date"
                }:
                    timestamp = valid_timestamp(value.strip())

                    if timestamp:
                        artifacts.append({
                            "type": "timestamp",
                            "value": timestamp,
                            "line": row_number,
                        })

                    continue

                # Scan other fields for artifacts.
                for item in extract_from_text(value):
                    item["line"] = row_number
                    artifacts.append(item)

        return remove_duplicates(artifacts)

    if extension == "json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []

        return remove_duplicates(
            extract_from_text(json.dumps(parsed, ensure_ascii=False))
        )

    return []


def extract_events(filename, data):
    """Extract normalized forensic events from supported evidence formats."""
    extension = filename.lower().rsplit(".", 1)[-1]
    text = data.decode("utf-8-sig", errors="replace")
    events = []

    def add_event(row, line_number):
        if not isinstance(row, dict):
            return

        normalized = {
            str(key).strip().lower(): value
            for key, value in row.items()
            if key is not None and value is not None
        }

        timestamp = None
        for key in ("timestamp_utc", "timestamp", "datetime", "time", "date"):
            value = normalized.get(key)
            if isinstance(value, str):
                timestamp = valid_timestamp(value.strip())
                if timestamp:
                    break

        event_name = next(
            (
                normalized[key]
                for key in ("event", "event_type", "action", "activity")
                if isinstance(normalized.get(key), str)
                and normalized[key].strip()
            ),
            None,
        )

        # Browser history exports often contain only timestamp and URL.
        if not event_name and normalized.get("url"):
            event_name = "browser_visit"

        if not timestamp or not event_name:
            return

        user = next(
            (
                normalized[key]
                for key in ("user", "username", "account", "email")
                if isinstance(normalized.get(key), str)
                and normalized[key].strip()
            ),
            None,
        )
        source_ip = next(
            (
                normalized[key]
                for key in ("source_ip", "src_ip", "ip_address", "ip")
                if isinstance(normalized.get(key), str)
                and normalized[key].strip()
            ),
            None,
        )
        session = next(
            (
                normalized[key]
                for key in ("session_id", "session", "sessionid")
                if isinstance(normalized.get(key), str)
                and normalized[key].strip()
            ),
            None,
        )

        excluded = {
            "timestamp_utc", "timestamp", "datetime", "time", "date",
            "user", "username", "account", "email", "event", "event_type",
            "action", "activity", "source_ip", "src_ip", "ip_address", "ip",
            "session_id", "session", "sessionid",
        }

        events.append({
            "timestamp": timestamp,
            "user": user,
            "event": str(event_name).strip(),
            "source_ip": source_ip,
            "session": session,
            "details": {
                str(key): value
                for key, value in normalized.items()
                if key not in excluded
            },
            "line": line_number,
        })

    if extension == "csv":
        for line_number, row in enumerate(
            csv.DictReader(io.StringIO(text)), start=2
        ):
            add_event(row, line_number)

    elif extension == "json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []

        if isinstance(parsed, dict):
            rows = parsed.get("events", [])
            if not isinstance(rows, list):
                rows = [parsed]
        elif isinstance(parsed, list):
            rows = parsed
        else:
            rows = []

        for line_number, row in enumerate(rows, start=1):
            add_event(row, line_number)

    elif extension in {"log", "txt", "eml", "md"}:
        for line_number, line in enumerate(text.splitlines(), start=1):
            timestamp_match = TIME_PATTERN.search(line)
            if not timestamp_match:
                continue

            fields = {
                key.lower(): value.strip().strip('"')
                for key, value in re.findall(
                    r'([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|[^\s]+)',
                    line,
                )
            }
            fields.setdefault("timestamp", timestamp_match.group())

            # For lines like "2026-10-09T10:30:00Z LOGIN user=alice ...",
            # derive the event name from the text following the timestamp.
            remainder = line[timestamp_match.end():].strip()
            event_match = re.match(r"([A-Za-z_][A-Za-z0-9_-]*)", remainder)
            if event_match:
                fields.setdefault("event", event_match.group(1).lower())

            add_event(fields, line_number)

    return events
