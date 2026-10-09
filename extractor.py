
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
