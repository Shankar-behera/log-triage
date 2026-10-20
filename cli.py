
"""log-triage: deterministic log triage for CI pipelines."""
import json
import sys
import os
# import stat
import tempfile
from pathlib import Path
from typing import Optional

import click

from app.analyzer import get_analyzer
from app.config import settings
from app.jsonl_input import JSONLInputError, normalize_jsonl
from app.report_export import build_report
from app.redaction import redact_log_input,sanitize_output
from app.provenance import assign_event_ids
from app.analyzer import LLMUnavailable

__version__ = "0.1.0"

SEVERITY_ORDER = {
    "INFO": 0,
    "WARNING": 1,
    "WARN": 1,
    "ERROR": 2,
    "SECURITY": 3,
    "FATAL": 4,
    "CRITICAL": 4,
}


def _read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _read_input(
    path: str,
    input_format: str = "text",
    *,
    max_input_bytes: int = 10 * 1024 * 1024,
    max_line_chars: int = 20_000,
    max_files: int = 500,
) -> str:
    """Read bounded text/JSONL input without loading oversized inputs first."""
    is_jsonl = input_format.lower() == "jsonl"

    def validate_content(content: str, source: str) -> str:
        if len(content.encode("utf-8")) > max_input_bytes:
            click.echo(f"error: input exceeds {max_input_bytes} bytes ({source})", err=True)
            raise click.exceptions.Exit(2)
        for line_number, line in enumerate(content.splitlines(), start=1):
            if len(line) > max_line_chars:
                click.echo(
                    f"error: line {line_number} exceeds {max_line_chars} characters ({source})",
                    err=True,
                )
                raise click.exceptions.Exit(2)
        return content

    if path == "-":
        content = sys.stdin.read(max_input_bytes + 1)
        if len(content.encode("utf-8")) > max_input_bytes:
            click.echo(f"error: stdin exceeds {max_input_bytes} bytes", err=True)
            raise click.exceptions.Exit(2)
        content = validate_content(content, "stdin")
        return normalize_jsonl(content) if is_jsonl else content

    p = Path(path)
    if not p.exists():
        click.echo(f"error: '{path}' not found", err=True)
        raise click.exceptions.Exit(2)

    try:
        if p.is_dir():
            if is_jsonl:
                files = sorted(
                    (item for item in (set(p.rglob("*.jsonl")) | set(p.rglob("*.ndjson")))
                     if not item.is_symlink() and item.is_file()),
                    key=lambda item: str(item).casefold(),
                )
                extensions = ".jsonl/.ndjson"
            else:
                files = sorted(
                    (item for item in (set(p.rglob("*.log")) | set(p.rglob("*.txt")))
                     if not item.is_symlink() and item.is_file()),
                    key=lambda item: str(item).casefold(),
                )
                extensions = ".log/.txt"

            if len(files) > max_files:
                click.echo(f"error: directory contains more than {max_files} input files", err=True)
                raise click.exceptions.Exit(2)
            total_bytes = sum(item.stat().st_size for item in files)
            if total_bytes > max_input_bytes:
                click.echo(f"error: directory input exceeds {max_input_bytes} bytes", err=True)
                raise click.exceptions.Exit(2)

            if not files:
                click.echo(
                    f"error: no {extensions} files under '{path}'",
                    err=True,
                )
                raise click.exceptions.Exit(2)

            contents = []
            for file in files:
                raw_content = validate_content(_read_text_file(file), str(file))
                if is_jsonl:
                    contents.append(normalize_jsonl(raw_content, str(file)))
                else:
                    contents.append(raw_content)

            return "\n".join(contents)

        if not p.is_file():
            click.echo(f"error: '{path}' is not a regular file", err=True)
            raise click.exceptions.Exit(2)

        if p.stat().st_size > max_input_bytes:
            click.echo(f"error: input exceeds {max_input_bytes} bytes", err=True)
            raise click.exceptions.Exit(2)
        content = validate_content(_read_text_file(p), str(p))
        return normalize_jsonl(content, str(p)) if is_jsonl else content

    except JSONLInputError:
        raise
    except PermissionError as exc:
        click.echo(f"error: cannot read '{path}': {exc}", err=True)
        raise click.exceptions.Exit(2) from None
    except OSError as exc:
        click.echo(f"error: cannot read '{path}': {exc}", err=True)
        raise click.exceptions.Exit(2) from None


def _validate_report_destination(
    input_path: str,
    report_path: Path,
) -> None:
    """Reject report destinations that overwrite or contaminate input."""
    if input_path == "-":
        return

    if report_path.is_symlink():
        click.echo("error: report path must not be a symlink", err=True)
        raise click.exceptions.Exit(2)
    if report_path.exists() and report_path.is_dir():
        click.echo("error: report path must not be a directory", err=True)
        raise click.exceptions.Exit(2)
    source = Path(input_path).resolve()
    destination = report_path.resolve()

    if source.is_file() and destination == source:
        click.echo(
            "error: report path must not overwrite the input log",
            err=True,
        )
        raise click.exceptions.Exit(2)

    if source.is_file() and report_path.exists():
        try:
            if os.path.samefile(source, report_path):
                click.echo("error: report path must not alias the input log", err=True)
                raise click.exceptions.Exit(2)
        except OSError:
            pass

    if source.is_dir():
        try:
            destination.relative_to(source)
        except ValueError:
            return

        click.echo(
            "error: when scanning a directory, the report must be "
            "written outside the input directory",
            err=True,
        )
        raise click.exceptions.Exit(2)


def _should_fail(result: dict, fail_on: Optional[str]) -> bool:
    """Return True if any parsed event reaches or exceeds the fail threshold."""
    if not fail_on:
        return False

    threshold = fail_on.upper()
    if threshold not in SEVERITY_ORDER:
        return False

    aliases = {"CRITICAL": "FATAL", "WARN": "WARNING"}

    for event in result.get("events", []):
        if not isinstance(event, dict):
            continue

        severity = event.get("severity") or event.get("level")
        if not severity:
            continue

        severity = aliases.get(str(severity).upper(), str(severity).upper())
        if severity in SEVERITY_ORDER:
            if SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]:
                return True

    return False


def _print_human(result: dict) -> None:
    click.echo(f"Priority:  {result.get('priority', 'low').upper()}")
    click.echo(f"Lines:     {result.get('total_lines', 0)}")
    click.echo(f"Events:    {result.get('structured_events', 0)}")

    sec = result.get("security_findings", {})
    click.echo(f"Security:  {sec.get('risk_level', 'none')}")

    errors = {
        key: value
        for key, value in result.get("errors_found", {}).items()
        if value > 0
    }

    if errors:
        click.echo("")
        click.echo("Errors by severity:")
        for kind in ("FATAL", "SECURITY", "ERROR", "TIMEOUT", "FAILED", "WARN"):
            if kind in errors:
                click.echo(f"  {kind:<10} {errors[kind]}")

    if sec.get("findings"):
        click.echo("")
        click.echo("Security findings:")
        for finding in sec["findings"]:
            click.echo(
                f"  [{finding['severity']}] {finding['type']} "
                f"x{finding['count']}: {finding['description']}"
            )

    candidates = result.get("root_cause_signals", {}).get(
        "root_cause_candidates", []
    )

    if candidates:
        click.echo("")
        click.echo("Likely first incident:")
        top = candidates[0]
        msg = (top.get("message") or "")[:120]
        click.echo(
            f"  [{top.get('severity', '?')}] "
            f"{top.get('service', '?')}: {msg}"
        )


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("path", default="-")
@click.option(
    "--fail-on",
    default=None,
    help=(
        "Exit 1 if any event >= this severity "
        "(INFO/WARNING/ERROR/SECURITY/FATAL)."
    ),
)
@click.option(
    "--input-format",
    type=click.Choice(["text", "jsonl"], case_sensitive=False),
    default="text",
    show_default=True,
    help="Input format. jsonl accepts one JSON object per line.",
)
@click.option(
    "--format", "-f", "fmt",
    default="text",
    type=click.Choice(["text", "json", "jsonl"]),
    help="Output format.",
)
@click.option(
    "--explain",
    is_flag=True,
    default=False,
    help="Add LLM narrative (requires GROQ_API_KEY).",
)
@click.option(
    "--no-redact", is_flag=True, default=False,
    help="Disable default best-effort secret redaction (not allowed with --explain).",
)
@click.option(
    "--redact-pii", is_flag=True, default=False,
    help="Also redact email addresses and IPv4 addresses (may remove useful diagnostic evidence).",
)
@click.option(
    "--max-input-mb", type=click.IntRange(min=1, max=1024), default=10, show_default=True,
    help="Maximum aggregate input size in MiB (stdin, file, or directory).",
)
@click.option(
    "--max-line-chars", type=click.IntRange(min=100, max=1_000_000), default=20_000, show_default=True,
    help="Maximum physical line length before analysis.",
)
@click.option(
    "--max-files", type=click.IntRange(min=1, max=100_000), default=500, show_default=True,
    help="Maximum number of log files when scanning a directory.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress stdout; use only exit code.",
)
@click.option(
    "--report",
    "report_path",
    default=None,
    type=click.Path(path_type=Path),
    help="Write a separate incident report to this file.",
)
@click.option(
    "--report-format",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Format for --report; does not change stdout output.",
)
@click.version_option(version=__version__, prog_name="log-triage")
def triage(
    path: str,
    fail_on: Optional[str],
    input_format: str,
    fmt: str,
    explain: bool,
    no_redact: bool,
    redact_pii: bool,
    max_input_mb: int,
    max_line_chars: int,
    max_files: int,
    quiet: bool,
    report_path: Optional[Path],
    report_format: str,
) -> None:
    """Triage a log file, directory, or stdin.

    Exit codes:
      0  clean (no event >= --fail-on severity)
      1  at least one parsed log event >= --fail-on severity
      2  usage error
    """
    if fail_on:
        fail_on = fail_on.upper()
        if fail_on not in SEVERITY_ORDER:
            click.echo(
                f"error: unknown severity '{fail_on}'. "
                f"Choose from {', '.join(SEVERITY_ORDER)}",
                err=True,
            )
            raise click.exceptions.Exit(2)

    if redact_pii and no_redact:
        click.echo("error: --redact-pii cannot be combined with --no-redact", err=True)
        raise click.exceptions.Exit(2)

    if explain and no_redact:
        click.echo("error: --no-redact cannot be combined with --explain", err=True)
        raise click.exceptions.Exit(2)

    if explain and not settings.GROQ_API_KEY:
        click.echo("error: --explain requires GROQ_API_KEY in env", err=True)
        raise click.exceptions.Exit(2)

    try:
        log_text = _read_input(
            path, input_format.lower(), max_input_bytes=max_input_mb * 1024 * 1024,
            max_line_chars=max_line_chars, max_files=max_files,
        )
    except JSONLInputError as exc:
        click.echo(f"error: {exc}", err=True)
        raise click.exceptions.Exit(2) from None

    if not log_text.strip():
        click.echo("error: empty input", err=True)
        raise click.exceptions.Exit(2)

    if report_path is not None:
        _validate_report_destination(path, report_path)

    # Redact before analysis so reports and optional model prompts receive the
    # same sanitized text. --no-redact is an explicit local-only opt-out.
    safe_log_text = log_text if no_redact else redact_log_input(log_text, pii=redact_pii)
    analyzer = get_analyzer()

    try:
        if explain:
            import asyncio
            result = asyncio.run(analyzer.full_analysis(safe_log_text, strict=True))
        else:
            result = analyzer.quick_analysis(safe_log_text)
    except LLMUnavailable:
        click.echo("error: AI explanation failed; no report was written", err=True)
        raise click.exceptions.Exit(3) from None
    source_label = "<stdin>" if path == "-" else str(Path(path))
    if isinstance(result.get("events"), list):
        for event in result["events"]:
            if isinstance(event, dict):
                event["source"] = source_label
        assign_event_ids(result["events"], source_label)
    result["redaction"] = {
        "enabled": not no_redact,
        "mode": "best-effort" if not no_redact else "disabled",
        "pii": redact_pii,
    }
    result = sanitize_output(result, redact=not no_redact)

    if report_path is not None:
        try:
            report_text = build_report(
                result=result,
                source=path,
                report_format=report_format.lower(),
                redact=not no_redact,
            )
            report_path.parent.mkdir(parents=True, exist_ok=True)
            if report_path.is_symlink() or report_path.is_dir():
                raise ValueError("report destination must not be a symlink or directory")
            if path != "-" and Path(path).exists() and report_path.exists() and os.path.samefile(Path(path), report_path):
                raise ValueError("report path must not alias the input log")
            fd, temp_name = tempfile.mkstemp(prefix=f".{report_path.name}.", suffix=".tmp", dir=str(report_path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                    handle.write(report_text)
                    handle.flush()
                    os.fsync(handle.fileno())
                if report_path.is_symlink():
                    raise ValueError("report destination became a symlink")
                os.replace(temp_name, report_path)
            finally:
                try: os.unlink(temp_name)
                except FileNotFoundError: pass
        except (OSError, ValueError) as exc:
            click.echo(f"error: could not write report: {exc}", err=True)
            raise click.exceptions.Exit(2) from None

    if not quiet:
        if fmt == "json":
            click.echo(json.dumps(result, indent=2, default=str))
        elif fmt == "jsonl":
            for event in result.get("events", []):
                click.echo(json.dumps(event, ensure_ascii=False, default=str))
        else:
            _print_human(result)

    if fail_on and _should_fail(result, fail_on):
        raise click.exceptions.Exit(1)

    raise click.exceptions.Exit(0)


if __name__ == "__main__":
    triage()
