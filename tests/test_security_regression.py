import json

import pytest
from click.testing import CliRunner

from cli import triage
from app.redaction import redact_text, sanitize_output


def test_redacts_common_secret_forms():
    text = ('password=hunter2 api_key: sk-abc123456 bearer abcdefghijklmnop '
            'https://alice:secret@internal.example/?token=xyz')
    safe = redact_text(text)
    for secret in ('hunter2', 'sk-abc123456', 'abcdefghijklmnop', 'alice:secret', 'token=xyz'):
        assert secret not in safe


def test_control_characters_are_visible():
    assert sanitize_output('ok\x1b[31mred\x07') == r'ok\x1b[31mred\x07'


def test_cli_redacts_by_default_and_jsonl_events_have_ids(tmp_path):
    log = tmp_path / 'service.log'
    log.write_text('2025-01-01 10:00:00 ERROR [auth] password=hunter2 failed\n', encoding='utf-8')
    result = CliRunner().invoke(triage, [str(log), '--format', 'jsonl'])
    assert result.exit_code == 0, result.output
    event = json.loads(result.output.strip().splitlines()[0])
    assert event.get('event_id')
    assert event.get('source') == str(log)
    assert 'hunter2' not in result.output


def test_no_redact_is_explicit_opt_out(tmp_path):
    log = tmp_path / 'service.log'
    log.write_text('ERROR password=hunter2\n', encoding='utf-8')
    result = CliRunner().invoke(triage, [str(log), '--no-redact', '--format', 'json'])
    assert result.exit_code == 0, result.output
    assert 'hunter2' in result.output
    assert json.loads(result.output)['redaction']['enabled'] is False


def test_no_redact_with_explain_is_rejected_before_input(monkeypatch):
    monkeypatch.setattr('cli.settings.GROQ_API_KEY', 'test-key')
    result = CliRunner().invoke(triage, ['/not/a/real/file.log', '--explain', '--no-redact'])
    assert result.exit_code == 2
    assert result.output.strip().startswith('error:')
    assert 'not found' not in result.output


def test_report_symlink_is_rejected(tmp_path):
    source = tmp_path / 'source.log'
    source.write_text('INFO ready\n', encoding='utf-8')
    real = tmp_path / 'real.md'
    real.write_text('keep me', encoding='utf-8')
    link = tmp_path / 'link.md'
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks unavailable')
    result = CliRunner().invoke(triage, [str(source), '--report', str(link)])
    assert result.exit_code == 2
    assert real.read_text(encoding='utf-8') == 'keep me'


def test_report_inside_scanned_directory_is_rejected(tmp_path):
    folder = tmp_path / 'logs'
    folder.mkdir()
    (folder / 'one.log').write_text('INFO ready\n', encoding='utf-8')
    result = CliRunner().invoke(triage, [str(folder), '--report', str(folder / 'report.md')])
    assert result.exit_code == 2
    assert not (folder / 'report.md').exists()


def test_cache_permissions_and_legacy_raw_payload_purge(tmp_path):
    import os
    from app.cache import ResultCache
    db = tmp_path / 'private' / 'cache.db'
    cache = ResultCache(str(db), enabled=True)
    cache.set('legacy', {'events': [{'raw': 'password=do-not-store'}]})
    reopened = ResultCache(str(db), enabled=True)
    assert reopened.get('legacy') is None
    if os.name == 'posix':
        assert db.stat().st_mode & 0o777 == 0o600
        assert db.parent.stat().st_mode & 0o777 == 0o700


def test_recent_results_do_not_persist_event_payloads(tmp_path):
    from app.cache import ResultCache
    cache = ResultCache(str(tmp_path / 'cache.db'), enabled=True)
    cache.store_recent('incident', {
        'summary': 'safe summary', 'events': [{'raw': 'secret log line'}],
        'timeline': [{'raw': 'secret timeline'}], 'priority': 'high',
    })
    result = cache.get_recent('incident')
    assert result['summary'] == 'safe summary'
    assert 'events' not in result and 'timeline' not in result


def test_explain_without_key_fails_before_reading_input(monkeypatch):
    monkeypatch.setattr('cli.settings.GROQ_API_KEY', '')
    result = CliRunner().invoke(triage, ['/missing/input.log', '--explain'])
    assert result.exit_code == 2
    assert 'requires GROQ_API_KEY' in result.output
    assert 'not found' not in result.output


@pytest.mark.parametrize(
    "field",
    [
        "events",
        "raw",
        "timeline",
        "root_cause_signals",
        "cascading_failures",
    ],
)
def test_legacy_cache_purge_removes_all_prohibited_payload_keys(
    tmp_path, field
):
    import sqlite3

    from app.cache import ResultCache

    db = tmp_path / "legacy-cache.db"
    ResultCache(str(db), enabled=True)

    payload = json.dumps(
        {"summary": "legacy", "nested": {field: [{"message": "sensitive"}]}}
    )

    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            INSERT INTO analysis_cache
                (cache_key, result_json, created_at, hit_count)
            VALUES (?, ?, ?, ?)
            """,
            (f"legacy-{field}", payload, 1.0, 0),
        )
        conn.execute(
            """
            INSERT INTO recent_results
                (analysis_id, result_json, created_at)
            VALUES (?, ?, ?)
            """,
            (f"legacy-{field}", payload, 1.0),
        )

    reopened = ResultCache(str(db), enabled=True)

    assert reopened.get(f"legacy-{field}") is None
    assert reopened.get_recent(f"legacy-{field}") is None


def test_legacy_cache_purge_keeps_benign_text(tmp_path):
    import sqlite3
    import time
    from app.cache import ResultCache

    db = tmp_path / "benign-cache.db"
    ResultCache(str(db), enabled=True)

    with sqlite3.connect(db) as conn:
        conn.execute(
            """
            INSERT INTO analysis_cache
                (cache_key, result_json, created_at, hit_count)
            VALUES (?, ?, ?, ?)
            """,
            (
                "benign",
                json.dumps({"summary": "raw logs were inspected"}),
                time.time(),
                0,
            ),
        )

    reopened = ResultCache(str(db), enabled=True)

    assert reopened.get("benign") == {
        "summary": "raw logs were inspected"
    }
