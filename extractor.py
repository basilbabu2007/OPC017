
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
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)


def valid_timestamp(value):
    if not value:
        return None

    try:
        normalized = value.replace("Z", "+00:00")
        result = datetime.fromisoformat(normalized)

        # Keep the original timestamp; don't invent a timezone.
        return value if result else None
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

        ips = IP_PATTERN.findall(line)
        urls = URL_PATTERN.findall(line)

        username_match = re.search(
            r"\buser(?:name)?=([A-Za-z0-9_.@-]+)",
            line,
            re.IGNORECASE,
        )

        if timestamp:
            artifacts.append({
                "type": "timestamp",
                "value": timestamp,
                "line": line_number,
            })

        for ip in ips:
            octets = ip.split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                artifacts.append({
                    "type": "ip_address",
                    "value": ip,
                    "line": line_number,
                })

        for url in urls:
            artifacts.append({
                "type": "url",
                "value": url.rstrip(".,);"),
                "line": line_number,
            })

        if username_match:
            artifacts.append({
                "type": "username",
                "value": username_match.group(1),
                "line": line_number,
            })

    return artifacts


def extract_artifacts(filename, data):
    extension = filename.lower().rsplit(".", 1)[-1]
    text = data.decode("utf-8-sig", errors="replace")

    if extension in {"txt", "log", "eml"}:
        return extract_from_text(text)

    if extension == "csv":
        rows = csv.DictReader(io.StringIO(text))
        artifacts = []

        for row_number, row in enumerate(rows, start=2):
            for column, value in row.items():
                if not value:
                    continue

                if column and column.lower() in {
                    "timestamp", "time", "datetime", "date"
                }:
                    timestamp = valid_timestamp(value)
                    if timestamp:
                        artifacts.append({
                            "type": "timestamp",
                            "value": timestamp,
                            "line": row_number,
                        })

                for item in extract_from_text(value):
                    item["line"] = row_number
                    artifacts.append(item)

        return artifacts

    if extension == "json":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return []

        return extract_from_text(
            json.dumps(parsed, ensure_ascii=False)
        )

    return []
