from app.parser_engine import parser_engine


def test_traceback_is_attached_to_its_error_event():
    log = (
        "2026-10-17 10:00:00 | ERROR | app.worker:run:10 - Job failed\n"
        "Traceback (most recent call last):\n"
        '  File "worker.py", line 10, in run\n'
        "    raise ValueError('bad input')\n"
        "ValueError: bad input"
    )

    events = parser_engine.parse_logs(log)

    assert len(events) == 1
    event = events[0]
    assert event["severity"] == "ERROR"
    assert event["service"] == "app.worker"
    assert event["parse_status"] == "parsed"
    assert event["continuation_lines"] == 4
    assert "Traceback (most recent call last):" in event["message"]
    assert 'File "worker.py", line 10' in event["raw"]
    assert "ValueError: bad input" in event["message"]


def test_http_response_metadata_is_preserved_as_continuation():
    log = (
        "2026-10-17 10:01:00 | ERROR | app.client:request:20 - "
        "Request failed\n"
        "<CIMultiDictProxy('Content-Type': 'application/json', "
        "'Content-Length': '152')>\n"
        ">"
    )

    events = parser_engine.parse_logs(log)

    assert len(events) == 1
    event = events[0]
    assert event["severity"] == "ERROR"
    assert event["continuation_lines"] == 2
    assert "CIMultiDictProxy" in event["raw"]
    assert "\n>" in event["raw"]


def test_standalone_unknown_line_is_not_discarded():
    events = parser_engine.parse_logs(
        "unrecognized standalone record"
    )

    assert len(events) == 1
    assert events[0]["severity"] == "UNKNOWN"
    assert events[0]["parse_status"] == "unparsed"
    assert events[0]["raw"] == "unrecognized standalone record"


def test_new_log_record_after_traceback_starts_new_event():
    log = (
        "2026-10-17 10:00:00 | ERROR | app.worker:run:10 - Job failed\n"
        "Traceback (most recent call last):\n"
        '  File "worker.py", line 10, in run\n'
        "2026-10-17 10:00:01 | INFO | app.worker:run:11 - Retry started"
    )

    events = parser_engine.parse_logs(log)

    assert len(events) == 2
    assert events[0]["severity"] == "ERROR"
    assert events[0]["continuation_lines"] == 2
    assert events[1]["severity"] == "INFO"
    assert events[1]["continuation_lines"] == 0


def test_indented_continuation_is_preserved():
    log = (
        "2026-10-17 10:00:00 | ERROR | app.worker:run:10 - Job failed\n"
        "    additional diagnostic context"
    )

    events = parser_engine.parse_logs(log)

    assert len(events) == 1
    assert events[0]["continuation_lines"] == 1
    assert "additional diagnostic context" in events[0]["message"]
