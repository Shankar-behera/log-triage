"""Acceptance tests for the new public Python facade."""

import json
import os
import subprocess
import sys

import pytest

from logtriage import (
    AnalysisOptions,
    Analyzer,
    InvalidInputError,
    UnsupportedModeError,
)


def test_public_import_and_rules_analysis_work_without_ai(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "GROQ_API_KEY", "")
    result = Analyzer().analyze("2026-10-19 10:00:00 ERROR [payments] database unavailable")

    assert result.success is True
    assert result.analysis_type == "quick"
    assert result.summary
    assert result.events
    assert result.events[0]["severity"] == "ERROR"
    assert result.priority in {"low", "medium", "high", "critical"}


def test_source_label_and_event_identity_are_exposed():
    options = AnalysisOptions(source="service-a/app.log")
    result = Analyzer().analyze("ERROR [payments] database unavailable", options=options)

    event = result.events[0]
    assert event["source"] == "service-a/app.log"
    assert event["source_line"] == 1
    assert event["source_end_line"] == 1
    assert len(event["event_id"]) == 24


def test_default_redaction_masks_common_secret_patterns():
    result = Analyzer().analyze("ERROR [auth] password=hunter2")
    serialized = json.dumps(result.to_dict())

    assert "hunter2" not in serialized
    assert "[REDACTED]" in serialized


def test_redaction_can_be_disabled_for_local_rules_only():
    result = Analyzer().analyze(
        "ERROR [auth] password=hunter2",
        options=AnalysisOptions(redact=False),
    )
    assert "hunter2" in json.dumps(result.to_dict())


def test_include_events_false_omits_top_level_events():
    result = Analyzer().analyze(
        "ERROR [payments] database unavailable",
        options=AnalysisOptions(include_events=False),
    )
    assert "events" not in result.to_dict()
    assert result.summary


def test_non_string_content_is_rejected():
    with pytest.raises(InvalidInputError, match="content must be a string"):
        Analyzer().analyze(None)  # type: ignore[arg-type]


def test_unknown_analysis_mode_is_rejected_explicitly():
    with pytest.raises(UnsupportedModeError, match="rules-only"):
        Analyzer().analyze("ERROR something", analysis_mode="ai")


def test_invalid_options_are_rejected():
    with pytest.raises(InvalidInputError, match="AnalysisOptions"):
        Analyzer().analyze("ERROR something", options={})  # type: ignore[arg-type]


def test_result_mapping_is_defensive_copy():
    result = Analyzer().analyze("ERROR [payments] database unavailable")
    first = result.to_dict()
    first["events"][0]["message"] = "changed"

    assert result.events[0]["message"] != "changed"


def test_importing_public_package_does_not_create_a_database(tmp_path):
    database = tmp_path / "must-not-exist.db"
    env = os.environ.copy()
    env["CACHE_ENABLED"] = "True"
    env["CACHE_DB_PATH"] = str(database)
    env["PYTHONPATH"] = str(__import__("pathlib").Path(__file__).resolve().parents[1])
    completed = subprocess.run(
        [sys.executable, "-c", "import logtriage; print(logtriage.__version__)"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )

    assert completed.stdout.strip() == "0.1.0"
    assert not database.exists()
