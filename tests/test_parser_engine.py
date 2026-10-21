from app.parser_engine import parser_engine


def test_parses_standard_error_line():
    events = parser_engine.parse_logs("2024-03-15 08:31:05 ERROR [PaymentGateway] Connection timeout")
    assert events[0]["severity"] == "ERROR"
    assert events[0]["service"] == "PaymentGateway"
    assert events[0]["timestamp"] == "2024-03-15 08:31:05"


def test_parses_security_severity():
    events = parser_engine.parse_logs("2024-03-15 08:40:35 SECURITY [AuthService] Brute force detected")
    assert events[0]["severity"] == "SECURITY"
    assert events[0]["service"] == "AuthService"


def test_warn_normalizes_to_warning():
    events = parser_engine.parse_logs("2024-01-01 00:00:00 WARN [Svc] slow")
    assert events[0]["severity"] == "WARNING"


def test_critical_normalizes_to_fatal():
    events = parser_engine.parse_logs("2024-01-01 00:00:00 CRITICAL [Svc] boom")
    assert events[0]["severity"] == "FATAL"


def test_unparseable_becomes_info_unknown():
    events = parser_engine.parse_logs("this line has no timestamp")

    assert len(events) == 1
    assert events[0]["severity"] == "UNKNOWN"
    assert events[0]["service"] == "unknown"
    assert events[0]["parse_status"] == "unparsed"
    assert events[0]["message"] == "this line has no timestamp"

def test_colon_format():
    events = parser_engine.parse_logs("2024-01-15 10:25:30 ERROR PaymentService: Failed")
    assert events[0]["severity"] == "ERROR"
    assert events[0]["service"] == "PaymentService"


def test_empty_input():
    assert parser_engine.parse_logs("") == []


def test_blank_lines_skipped():
    events = parser_engine.parse_logs("\n\n2024-01-01 00:00:00 INFO [S] ok\n\n")
    assert len(events) == 1


def test_parses_timestamped_severity_without_service_name():
    events = parser_engine.parse_logs(
        "2026-10-22 10:00:02 ERROR Database connection failed"
    )
    assert len(events) == 1
    assert events[0]["severity"] == "ERROR"
    assert events[0]["timestamp"] == "2026-10-22 10:00:02"
    assert events[0]["message"] == "Database connection failed"
    assert events[0]["parse_status"] == "parsed"


def test_parses_simple_timestamped_critical_as_fatal():
    events = parser_engine.parse_logs(
        "2026-10-22 10:00:03 CRITICAL API process crashed"
    )
    assert len(events) == 1
    assert events[0]["severity"] == "FATAL"
    assert events[0]["message"] == "API process crashed"


def test_parses_simple_timestamped_info_as_info():
    events = parser_engine.parse_logs(
        "2026-10-22 10:00:01 INFO Application started"
    )
    assert len(events) == 1
    assert events[0]["severity"] == "INFO"
    assert events[0]["message"] == "Application started"
