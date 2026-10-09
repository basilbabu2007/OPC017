
import re


SQLI_PATTERNS = [
    (
        "SQL keyword followed by a condition",
        re.compile(
            r"\bOR\s+\d+\s*=\s*\d+",
            re.IGNORECASE,
        ),
    ),
    (
        "UNION SELECT pattern",
        re.compile(
            r"\bUNION\s+(?:ALL\s+)?SELECT\b",
            re.IGNORECASE,
        ),
    ),
    (
        "SQL comment marker",
        re.compile(r"(?:--|#|/\*)"),
    ),
    (
        "SQL statement termination",
        re.compile(r";\s*(?:SELECT|DROP|INSERT|UPDATE|DELETE)\b",
                   re.IGNORECASE),
    ),
]


def detect_sqli(text):
    """Flag lines containing patterns commonly associated with SQL injection."""
    findings = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        for description, pattern in SQLI_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "type": "possible_sql_injection",
                    "rule": description,
                    "line": line_number,
                    "evidence": line.strip()[:500],
                    "confidence": "low",
                    "explanation": (
                        "This line matches a pattern associated with SQL "
                        "injection. Manual investigation is required; "
                        "a pattern match alone does not prove an attack."
                    ),
                })

    return findings
