"""Tests for the log-triage CLI (raw Click). Uses Quick mode only, no Groq key needed.

Verifies the exit-code contract:
  0  clean
  1  at least one parsed event >= --fail-on severity
  2  usage error (missing file, bad --fail-on, missing key)
"""
import json
import pytest
from click.testing import CliRunner

from cli import triage as app


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def clean_log(tmp_path):
    p = tmp_path / "clean.log"
    p.write_text(
        "2024-01-15 10:00:00 INFO [App] started\n"
        "2024-01-15 10:00:01 INFO [App] ready\n"
        "2024-01-15 10:00:02 INFO [App] serving\n"
    )
    return p


@pytest.fixture
def error_log(tmp_path):
    p = tmp_path / "errors.log"
    p.write_text(
        "2024-01-15 10:00:00 ERROR [DB] connection failed\n"
        "2024-01-15 10:00:01 FATAL [App] shutdown\n"
    )
    return p


@pytest.fixture
def error_only_log(tmp_path):
    p = tmp_path / "error_only.log"
    p.write_text("2024-01-15 10:00:00 ERROR [S] only error\n")
    return p


@pytest.fixture
def security_log(tmp_path):
    p = tmp_path / "security.log"
    p.write_text("2024-03-15 08:40:35 SECURITY [Auth] brute force from 203.0.113.45\n")
    return p


# --- version / help ---

def test_version(runner):
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0
    # Click's version_option prints "prog_name, version X.Y.Z" (comma included).
    assert "0.1.0" in r.stdout
    assert "log-triage" in r.stdout


def test_help_exits_zero(runner):
    r = runner.invoke(app, ["--help"])
    assert r.exit_code == 0


# --- exit 0 ---

def test_clean_log_exits_zero(runner, clean_log):
    r = runner.invoke(app, [str(clean_log), "--fail-on", "error"])
    assert r.exit_code == 0


def test_clean_log_default_no_fail_on(runner, clean_log):
    r = runner.invoke(app, [str(clean_log)])
    assert r.exit_code == 0


def test_fail_on_fatal_ignores_errors(runner, error_only_log):
    r = runner.invoke(app, [str(error_only_log), "--fail-on", "fatal"])
    assert r.exit_code == 0


# --- exit 1 ---

def test_error_log_exits_one(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--fail-on", "error"])
    assert r.exit_code == 1


def test_fail_on_fatal_catches_fatal(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--fail-on", "fatal"])
    assert r.exit_code == 1


def test_fail_on_accepts_critical_alias(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--fail-on", "critical"])
    assert r.exit_code == 1


def test_fail_on_accepts_warn_alias(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--fail-on", "warn"])
    assert r.exit_code == 1


def test_fail_on_security_events(runner, security_log):
    r = runner.invoke(app, [str(security_log), "--fail-on", "error"])
    assert r.exit_code == 1


def test_fail_on_info_threshold(runner, clean_log):
    r = runner.invoke(app, [str(clean_log), "--fail-on", "info"])
    assert r.exit_code == 1


# --- exit 2 ---

def test_missing_file_exits_two(runner):
    r = runner.invoke(app, ["/nonexistent/path/to/log.log"])
    assert r.exit_code == 2


def test_unknown_severity_exits_two(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--fail-on", "banana"])
    assert r.exit_code == 2


def test_empty_directory_exits_two(runner, tmp_path):
    r = runner.invoke(app, [str(tmp_path)])
    assert r.exit_code == 2


def test_empty_file_exits_two(runner, tmp_path):
    p = tmp_path / "empty.log"
    p.write_text("")
    r = runner.invoke(app, [str(p)])
    assert r.exit_code == 2


def test_whitespace_only_file_exits_two(runner, tmp_path):
    p = tmp_path / "blank.log"
    p.write_text("   \n\n\t\n   \n")
    r = runner.invoke(app, [str(p)])
    assert r.exit_code == 2


def test_explain_without_key_exits_two(runner, error_log, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "GROQ_API_KEY", "")
    r = runner.invoke(app, [str(error_log), "--explain"])
    assert r.exit_code == 2


# --- output formats ---

def test_json_format_is_valid(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--format", "json"])
    assert r.exit_code == 0
    data = json.loads(r.stdout)
    for key in ("priority", "errors_found", "security_findings",
                "root_cause_signals", "total_lines"):
        assert key in data


def test_json_output_includes_events_list(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--format", "json"])
    data = json.loads(r.stdout)
    assert "events" in data
    assert isinstance(data["events"], list)
    assert len(data["events"]) > 0
    for event in data["events"]:
        assert isinstance(event, dict)
        assert "severity" in event
    assert isinstance(data["structured_events"], int)


def test_short_format_flag(runner, error_log):
    r = runner.invoke(app, [str(error_log), "-f", "json"])
    assert r.exit_code == 0
    json.loads(r.stdout)


# --- input methods ---

def test_stdin_input(runner):
    r = runner.invoke(
        app, ["-", "--format", "json"],
        input="2024-01-15 10:00:00 ERROR [S] boom\n",
    )
    assert r.exit_code == 0
    data = json.loads(r.stdout)
    assert data["total_lines"] == 1


def test_stdin_fail_on(runner):
    r = runner.invoke(
        app, ["-", "--fail-on", "error", "--quiet"],
        input="2024-01-15 10:00:00 ERROR [S] boom\n",
    )
    assert r.exit_code == 1


def test_directory_input(runner, tmp_path):
    (tmp_path / "a.log").write_text("2024-01-15 10:00:00 ERROR [S] bad\n")
    (tmp_path / "b.log").write_text("2024-01-15 10:00:01 FATAL [S] worse\n")
    r = runner.invoke(app, [str(tmp_path), "--fail-on", "error"])
    assert r.exit_code == 1


def test_directory_input_clean(runner, tmp_path):
    (tmp_path / "a.log").write_text("2024-01-15 10:00:00 INFO [S] ok\n")
    (tmp_path / "b.log").write_text("2024-01-15 10:00:01 INFO [S] fine\n")
    r = runner.invoke(app, [str(tmp_path), "--fail-on", "error"])
    assert r.exit_code == 0


def test_directory_accepts_txt_files(runner, tmp_path):
    (tmp_path / "a.txt").write_text("2024-01-15 10:00:00 ERROR [S] boom\n")
    r = runner.invoke(app, [str(tmp_path), "--fail-on", "error"])
    assert r.exit_code == 1


# --- quiet ---

def test_quiet_suppresses_stdout(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--quiet", "--fail-on", "error"])
    assert r.stdout == ""
    assert r.exit_code == 1


def test_quiet_short_flag(runner, error_log):
    r = runner.invoke(app, [str(error_log), "-q", "--fail-on", "error"])
    assert r.stdout == ""
    assert r.exit_code == 1


def test_quiet_clean_log(runner, clean_log):
    r = runner.invoke(app, [str(clean_log), "--quiet", "--fail-on", "error"])
    assert r.stdout == ""
    assert r.exit_code == 0


# --- combined ---

def test_quiet_with_json_format(runner, error_log):
    r = runner.invoke(app, [str(error_log), "--quiet", "--format", "json"])
    assert r.stdout == ""
    assert r.exit_code == 0


def test_human_output_contains_priority(runner, error_log):
    r = runner.invoke(app, [str(error_log)])
    assert r.exit_code == 0
    assert "Priority" in r.stdout or "priority" in r.stdout


def test_human_output_contains_error_counts(runner, error_log):
    r = runner.invoke(app, [str(error_log)])
    assert "ERROR" in r.stdout
    assert "FATAL" in r.stdout
# --- ordering / error handling ---

def test_invalid_fail_on_is_rejected_before_reading_input(runner):
    """A bad --fail-on value is a usage error and must not read the file."""
    r = runner.invoke(
        app,
        ["/this/path/does/not/exist.log", "--fail-on", "banana"],
    )
    assert r.exit_code == 2
    assert "unknown severity" in r.output
    assert "not found" not in r.output


def test_unreadable_file_returns_cli_error(runner, tmp_path, monkeypatch):
    """PermissionError during read is reported as a clean CLI error, exit 2."""
    log_file = tmp_path / "unreadable.log"
    log_file.write_text("2024-01-15 10:00:00 INFO [App] ready\n")

    from pathlib import Path
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes

    def blocked_read_text(self, *args, **kwargs):
        if self == log_file:
            raise PermissionError("access denied")
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", blocked_read_text)
    original_read_bytes = Path.read_bytes

    def blocked_read_bytes(self, *args, **kwargs):
        if self == log_file:
            raise PermissionError("access denied")
        return original_read_bytes(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", blocked_read_bytes)

    r = runner.invoke(app, [str(log_file)])
    assert r.exit_code == 2
    assert "cannot read" in r.output
    assert "access denied" in r.output

def test_markdown_report_file_is_created(runner, error_log, tmp_path):
    report_path = tmp_path / "reports" / "incident.md"

    r = runner.invoke(
        app,
        [str(error_log), "--report", str(report_path)],
    )

    assert r.exit_code == 0
    assert report_path.is_file()
    assert "# Log Triage Incident Report" in report_path.read_text(encoding="utf-8")


def test_json_report_does_not_change_stdout_format(runner, error_log, tmp_path):
    report_path = tmp_path / "incident.json"

    r = runner.invoke(
        app,
        [
            str(error_log),
            "--format",
            "json",
            "--report",
            str(report_path),
            "--report-format",
            "json",
        ],
    )

    assert r.exit_code == 0
    stdout_data = json.loads(r.stdout)
    report_data = json.loads(report_path.read_text(encoding="utf-8"))

    assert "priority" in stdout_data
    assert report_data["analysis"]["priority"] == stdout_data["priority"]
    assert report_data["report_schema_version"] == "1.0"


def test_report_is_written_in_quiet_mode(runner, error_log, tmp_path):
    report_path = tmp_path / "incident.md"

    r = runner.invoke(
        app,
        [str(error_log), "--quiet", "--report", str(report_path)],
    )

    assert r.exit_code == 0
    assert r.stdout == ""
    assert report_path.is_file()


def test_report_cannot_overwrite_input(runner, error_log):
    original = error_log.read_text(encoding="utf-8")

    r = runner.invoke(
        app,
        [str(error_log), "--report", str(error_log)],
    )

    assert r.exit_code == 2
    assert "must not overwrite" in r.output
    assert error_log.read_text(encoding="utf-8") == original

def test_report_destination_rejects_inside_input_directory(
    tmp_path,
    capsys,
):
    import click
    import pytest

    from cli import _validate_report_destination

    input_dir = tmp_path / "logs"
    input_dir.mkdir()
    report_path = input_dir / "incident.md"

    with pytest.raises(click.exceptions.Exit) as exc:
        _validate_report_destination(str(input_dir), report_path)

    assert exc.value.exit_code == 2
    assert "outside the input directory" in capsys.readouterr().err
    assert not report_path.exists()


def test_report_destination_rejects_overwriting_input_file(tmp_path, capsys):
    import click
    import pytest

    from cli import _validate_report_destination

    input_file = tmp_path / "app.log"
    input_file.write_text("ERROR connection refused\n", encoding="utf-8")

    with pytest.raises(click.exceptions.Exit) as exc:
        _validate_report_destination(str(input_file), input_file)

    assert exc.value.exit_code == 2
    assert "must not overwrite" in capsys.readouterr().err
    assert input_file.read_text(encoding="utf-8") == (
        "ERROR connection refused\n"
    )

def test_cli_rejects_input_over_size_limit(runner, tmp_path):
    log = tmp_path / "large.log"
    log.write_text("ERROR " + "x" * 200, encoding="utf-8")
    result = runner.invoke(app, [str(log), "--max-input-mb", "1"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, [str(log), "--max-input-mb", "1", "--max-line-chars", "100"])
    assert result.exit_code == 2
    assert "line 1 exceeds 100 characters" in result.output


def test_cli_optional_pii_redaction(runner, tmp_path):
    log = tmp_path / "pii.log"
    log.write_text("2025-01-01 10:00:00 ERROR [auth] alice@example.com from 203.0.113.45 failed\n", encoding="utf-8")
    result = runner.invoke(app, [str(log), "--redact-pii", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "alice@example.com" not in result.output
    assert "203.0.113.45" not in result.output
    assert '"pii": true' in result.output


def test_cli_rejects_pii_redaction_with_no_redact(runner, tmp_path):
    log = tmp_path / "pii.log"
    log.write_text("INFO ready\n", encoding="utf-8")
    result = runner.invoke(app, [str(log), "--redact-pii", "--no-redact"])
    assert result.exit_code == 2
    assert "cannot be combined" in result.output
