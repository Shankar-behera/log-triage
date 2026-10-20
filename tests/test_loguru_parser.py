from app.parser_engine import parser_engine
from app.root_cause_engine import root_cause_engine


def test_parses_loguru_error_with_module_function_and_line():
    line = (
        "2026-06-18 23:59:07 | ERROR    | "
        "src.services.vector_kb_service:initialize:59 - "
        "Failed to initialize vector KB: unexpected keyword argument"
    )

    event = parser_engine.parse_logs(line)[0]

    assert event["timestamp"] == "2026-06-18 23:59:07"
    assert event["severity"] == "ERROR"
    assert event["service"] == "src.services.vector_kb_service"
    assert event["message"] == (
        "Failed to initialize vector KB: unexpected keyword argument"
    )
    assert event["parse_status"] == "parsed"


def test_parses_loguru_info_and_error_in_same_log():
    log = (
        "2026-06-18 23:59:06 | INFO     | src.api.app:startup_event:56 - "
        "Initializing database...\n"
        "2026-06-18 23:59:07 | ERROR    | "
        "src.services.db_service:health_check:355 - "
        "Database health check failed"
    )

    events = parser_engine.parse_logs(log)

    assert [event["severity"] for event in events] == ["INFO", "ERROR"]
    assert events[0]["service"] == "src.api.app"
    assert events[1]["service"] == "src.services.db_service"


def test_loguru_error_reaches_root_cause_engine():
    log = (
        "2026-06-18 23:59:07 | ERROR    | "
        "src.services.db_service:health_check:355 - "
        "Database health check failed"
    )

    events = parser_engine.parse_logs(log)
    result = root_cause_engine.analyze(events)

    assert result["error_count"] == 1
    assert result["severity_distribution"]["ERROR"] == 1
    assert result["service_impact"]["src.services.db_service"] == 1
    assert result["root_cause_candidates"]


def test_unrecognized_line_is_not_mislabeled_info():
    events = parser_engine.parse_logs("some unstructured text without a level")

    assert len(events) == 1
    assert events[0]["severity"] == "UNKNOWN"
    assert events[0]["parse_status"] == "unparsed"
    assert events[0]["raw"] == "some unstructured text without a level"


def test_existing_timestamped_formats_still_parse():
    lines = (
        "2024-03-15 08:31:05 ERROR [PaymentGateway] Connection timeout\n"
        "2024-01-15 10:25:30 ERROR PaymentService: Failed"
    )

    events = parser_engine.parse_logs(lines)

    assert len(events) == 2
    assert all(event["severity"] == "ERROR" for event in events)
    assert events[0]["service"] == "PaymentGateway"
    assert events[1]["service"] == "PaymentService"
