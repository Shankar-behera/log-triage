from app.security_engine import security_engine


def test_sql_injection():
    r = security_engine.analyze("Blocked attempt: SELECT * FROM users WHERE 1=1")
    types = [f["type"] for f in r["findings"]]
    assert "sql_injection" in types
    assert r["has_security_issues"] is True


def test_xss():
    r = security_engine.analyze("Payload: <script>alert(1)</script>")
    types = [f["type"] for f in r["findings"]]
    assert "xss" in types


def test_brute_force():
    r = security_engine.analyze("Multiple failed login attempts from one IP")
    types = [f["type"] for f in r["findings"]]
    assert "brute_force" in types


def test_clean_log_no_findings():
    r = security_engine.analyze("User logged in successfully")
    assert r["has_security_issues"] is False
    assert r["risk_level"] == "none"


def test_ip_in_suspicious_context_flagged():
    r = security_engine.analyze("Blocked attack from 203.0.113.45 on port 22")
    assert "203.0.113.45" in r["flagged_ips"]


def test_ip_in_benign_context_not_flagged():
    r = security_engine.analyze("User connected from 10.0.0.5 normally")
    assert "10.0.0.5" not in r["flagged_ips"]
def test_security_count_deduplicates_patterns_on_same_line():
    result = security_engine.analyze(
        "SQL injection blocked: SELECT * FROM users WHERE 1=1"
    )
    finding = next(
        f for f in result["findings"] if f["type"] == "sql_injection"
    )
    assert finding["count"] == 1


def test_invalid_ipv4_is_not_flagged():
    result = security_engine.analyze(
        "Blocked attack from 999.999.999.999"
    )
    assert "999.999.999.999" not in result["flagged_ips"]


def test_multiple_matching_lines_are_counted():
    result = security_engine.analyze(
        "authentication failed for user A\n"
        "authentication failed for user B\n"
    )
    finding = next(
        f for f in result["findings"] if f["type"] == "failed_login"
    )
    assert finding["count"] == 2


def test_examples_are_readable_strings():
    result = security_engine.analyze(
        "Blocked attempt: SELECT * FROM users WHERE 1=1"
    )
    finding = next(
        f for f in result["findings"] if f["type"] == "sql_injection"
    )
    assert all(isinstance(example, str) for example in finding["examples"])