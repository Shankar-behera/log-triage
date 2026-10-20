
"""Validate and normalize JSON Lines log input."""
import json
from typing import Any, Dict, List, Optional, Tuple


SEVERITIES = {
    "TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "ERR",
    "FATAL", "CRITICAL", "SECURITY", "SEC", "SUCCESS",
}

SEVERITY_ALIASES = {
    "WARN": "WARNING",
    "ERR": "ERROR",
    "SEC": "SECURITY",
    "CRITICAL": "FATAL",
    "SUCCESS": "INFO",
    "TRACE": "DEBUG",
}


class JSONLInputError(ValueError):
    """Raised when a JSON Lines input record is invalid."""


def _string_field(
    record: Dict[str, Any],
    names: Tuple[str, ...],
    *,
    line_number: int,
    required: bool = False,
    default: Optional[str] = None,
) -> Optional[str]:
    """Return the first available field from an ordered list of aliases."""
    value = None
    selected_name = names[0]

    for name in names:
        if name in record and record[name] is not None:
            value = record[name]
            selected_name = name
            break

    if value is None:
        if required:
            raise JSONLInputError(
                f"line {line_number}: missing required field "
                f"'{names[0]}' (accepted aliases: {', '.join(names)})"
            )
        return default

    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise JSONLInputError(
            f"line {line_number}: field '{selected_name}' "
            "must be a string or number"
        )

    result = str(value).strip()

    if not result:
        if required:
            raise JSONLInputError(
                f"line {line_number}: field '{selected_name}' must not be empty"
            )
        return default

    return result


def normalize_jsonl(content: str, source: str = "<stdin>") -> str:
    """Convert JSONL objects into conventional log lines.

    Required fields:
      - severity or level
      - message or msg

    Optional fields:
      - timestamp, time, @timestamp, or ts
      - service, logger, or name

    Invalid records fail the entire input with a line-numbered error.
    """
    output: List[str] = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        if not raw_line.strip():
            continue

        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise JSONLInputError(
                f"{source}: line {line_number}: invalid JSON "
                f"(column {exc.colno}): {exc.msg}"
            ) from None

        if not isinstance(record, dict):
            raise JSONLInputError(
                f"{source}: line {line_number}: "
                "each JSONL record must be an object"
            )

        severity = _string_field(
            record,
            ("severity", "level"),
            line_number=line_number,
            required=True,
        ).upper()

        if severity not in SEVERITIES:
            raise JSONLInputError(
                f"{source}: line {line_number}: "
                f"unsupported severity '{severity}'"
            )

        severity = SEVERITY_ALIASES.get(severity, severity)

        message = _string_field(
            record,
            ("message", "msg"),
            line_number=line_number,
            required=True,
        )

        timestamp = _string_field(
            record,
            ("timestamp", "time", "@timestamp", "ts"),
            line_number=line_number,
        )

        service = _string_field(
            record,
            ("service", "logger", "name"),
            line_number=line_number,
            default="general",
        )

        # Prevent metadata from injecting extra physical log records.
        service = service.replace("\r", "_").replace("\n", "_")
        message = message.replace("\r", "\\r").replace("\n", "\\n")

        if timestamp:
            timestamp = timestamp.replace("\r", "_").replace("\n", "_")
            output.append(f"{timestamp} {severity} [{service}] {message}")
        else:
            output.append(f"{severity} [{service}] {message}")

    return "\n".join(output)
