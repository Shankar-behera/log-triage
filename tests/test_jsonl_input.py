
import json

import pytest
from click.testing import CliRunner

from app.jsonl_input import JSONLInputError, normalize_jsonl
from app.parser_engine import parser_engine
from cli import triage


def test_normalizes_timestamped_record():
    text = normalize_jsonl(json.dumps({
        "timestamp": "2026-10-17T10:00:00Z",
        "level": "error",
        "service": "payments",
        "message": "connection refused",
    }))

    event = parser_engine.parse_logs(text)[0]
    assert event["severity"] == "ERROR"
    assert event["timestamp"] == "2026-10-17T10:00:00Z"
    assert event["service"] == "payments"
    assert event["message"] == "connection refused"


def test_normalizes_aliases_and_missing_optional_fields():
    text = normalize_jsonl(json.dumps({
        "severity": "warn",
        "msg": "request is slow",
        "logger": "gateway",
    }))

    event = parser_engine.parse_logs(text)[0]
    assert event["severity"] == "WARNING"
    assert event["service"] == "gateway"
    assert event["message"] == "request is slow"


def test_blank_lines_are_ignored():
    content = '\n{"level":"INFO","message":"ready"}\n\n'
    assert normalize_jsonl(content) == "INFO [general] ready"


@pytest.mark.parametrize("record", [
    "not json",
    "[]",
    '{"level":"ERROR"}',
    '{"message":"missing severity"}',
    '{"level":"MAJOR","message":"unknown severity"}',
])
def test_invalid_records_raise_clear_errors(record):
    with pytest.raises(JSONLInputError):
        normalize_jsonl(record, source="sample.jsonl")


def test_malformed_json_error_includes_source_and_line():
    content = (
        '{"level":"INFO","message":"ready"}\n'
        '{"level":\n'
    )

    with pytest.raises(JSONLInputError, match=r"sample\.jsonl: line 2"):
        normalize_jsonl(content, source="sample.jsonl")


def test_cli_jsonl_fail_on_error(tmp_path):
    path = tmp_path / "errors.jsonl"
    path.write_text(
        '{"timestamp":"2026-10-17T10:00:00Z",'
        '"severity":"ERROR","service":"db",'
        '"message":"connection failed"}\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        triage,
        [
            str(path), "--input-format", "jsonl",
            "--fail-on", "error", "--quiet",
        ],
    )

    assert result.exit_code == 1, result.output


def test_cli_malformed_jsonl_returns_usage_error(tmp_path):
    path = tmp_path / "broken.jsonl"
    path.write_text('{"severity":\n', encoding="utf-8")

    result = CliRunner().invoke(
        triage, [str(path), "--input-format", "jsonl"]
    )

    assert result.exit_code == 2
    assert "line 1" in result.output


def test_cli_jsonl_directory_scan(tmp_path):
    (tmp_path / "a.jsonl").write_text(
        '{"severity":"INFO","message":"started"}\n',
        encoding="utf-8",
    )
    (tmp_path / "b.ndjson").write_text(
        '{"severity":"FATAL","message":"shutdown"}\n',
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        triage,
        [
            str(tmp_path), "--input-format", "jsonl",
            "--fail-on", "fatal", "--quiet",
        ],
    )

    assert result.exit_code == 1, result.output
