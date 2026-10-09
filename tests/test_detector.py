
from app.detector import detect_sqli


def test_detects_union_select():
    findings = detect_sqli(
        "GET /search?q=test UNION SELECT username FROM users"
    )

    assert len(findings) >= 1
    assert findings[0]["type"] == "possible_sql_injection"


def test_ignores_normal_request():
    findings = detect_sqli(
        "GET /products?category=books"
    )

    assert findings == []


def test_includes_line_number():
    findings = detect_sqli(
        "Normal request\n"
        "GET /login?q=' OR 1=1"
    )

    assert findings
    assert findings[0]["line"] == 2
