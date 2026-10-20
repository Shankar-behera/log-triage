from app.redaction import redact_log_input, redact_text


def test_url_password_containing_at_sign_is_redacted():
    value = "connect https://alice:p@ss@internal.example/path"
    safe = redact_text(value)
    assert "p@ss" not in safe
    assert "alice:p" not in safe
    assert "internal.example" in safe


def test_connection_string_credentials_are_redacted_but_diagnostics_remain():
    value = "Server=db01;Database=payments;User Id=svc_user;Password=s3cr3t;Encrypt=true"
    safe = redact_text(value)
    assert "s3cr3t" not in safe
    assert "svc_user" not in safe
    assert "Server=db01" in safe
    assert "Database=payments" in safe
    assert "Encrypt=true" in safe


def test_pii_redaction_is_opt_in():
    value = "contact alice@example.com from 203.0.113.45 failed"
    assert "alice@example.com" in redact_text(value)
    safe = redact_log_input(value, pii=True)
    assert "alice@example.com" not in safe
    assert "203.0.113.45" not in safe
    assert "[REDACTED_EMAIL]" in safe
    assert "[REDACTED_IP]" in safe


def test_input_reader_enforces_aggregate_byte_limit(tmp_path):
    from cli import _read_input
    import click
    source = tmp_path / "large.log"
    source.write_text("1234567890", encoding="utf-8")
    try:
        _read_input(str(source), max_input_bytes=5)
    except click.exceptions.Exit as exc:
        assert exc.exit_code == 2
    else:
        raise AssertionError("expected input size limit to reject oversized file")


def test_input_reader_enforces_directory_file_count(tmp_path):
    from cli import _read_input
    import click
    (tmp_path / "one.log").write_text("INFO one", encoding="utf-8")
    (tmp_path / "two.log").write_text("INFO two", encoding="utf-8")
    try:
        _read_input(str(tmp_path), max_files=1)
    except click.exceptions.Exit as exc:
        assert exc.exit_code == 2
    else:
        raise AssertionError("expected file-count limit to reject directory")
