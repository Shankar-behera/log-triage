
"""Parse common application log formats into structured events."""
import re
from collections import Counter
from app.provenance import assign_event_ids
from typing import Dict, List

from app.models import SeverityLevel, INCIDENT_SEVERITIES


_SEVERITY_ALT = (
    r"TRACE|DEBUG|INFO|WARN|WARNING|ERROR|ERR|FATAL|"
    r"CRITICAL|SECURITY|SEC|SUCCESS"
)

_TIMESTAMP = (
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)

_TRACEBACK_START = re.compile(
    r"^(?:Traceback \(most recent call last\):|"
    r"During handling of the above exception, another exception occurred:|"
    r"The above exception was the direct cause of the following exception\.)$"
)

_STACK_FRAME = re.compile(r'^\s*File\s+["\'].*["\'],\s+line\s+\d+')

_EXCEPTION_LINE = re.compile(
    r"^(?:[A-Za-z_][\w.]*(?:Error|Exception|Warning|Failure|Interrupt|Exit))"
    r"(?::|\s|$)"
)

_HTTP_METADATA = re.compile(r"^<CIMultiDictProxy\(")

_LOG_START_HINT = re.compile(
    rf"^\s*(?:{_TIMESTAMP}\s*\|\s*"
    rf"(?:{_SEVERITY_ALT})\s*\||"
    rf"{_TIMESTAMP}\s+(?:{_SEVERITY_ALT})\b|"
    rf"\[(?:{_TIMESTAMP})\]\s+"
    rf"(?:{_SEVERITY_ALT})\b|"
    rf"(?:{_SEVERITY_ALT}):)",
    re.IGNORECASE,
)


class LogParserEngine:
    """Parse timestamped logs while retaining common multiline evidence."""

    LOGURU_PATTERN = re.compile(
        rf"^\s*(?P<timestamp>{_TIMESTAMP})\s*\|\s*"
        rf"(?P<severity>{_SEVERITY_ALT})\s*\|\s*"
        rf"(?P<module>[\w./-]+)"
        rf"(?::(?P<function>[\w<>.-]+))?"
        rf"(?::(?P<line_no>\d+))?"
        rf"\s+-\s+(?P<message>.*)$",
        re.IGNORECASE,
    )

    PATTERNS = [
        # Timestamp-free structured JSONL normalization output.
        re.compile(
            rf"^\s*(?P<severity>{_SEVERITY_ALT})\s+"
            rf"\[(?P<service>[\w./-]+)\]\s+(?P<message>.*)$",
            re.IGNORECASE,
        ),
        re.compile(
            rf"^\s*(?P<timestamp>{_TIMESTAMP})\s+"
            rf"(?P<severity>{_SEVERITY_ALT})\s+"
            rf"(?P<service>[\w.-]+):\s+(?P<message>.*)$",
            re.IGNORECASE,
        ),
        re.compile(
            rf"^\s*\[(?P<timestamp>{_TIMESTAMP})\]\s+"
            rf"(?P<severity>{_SEVERITY_ALT})\s+"
            rf"\[(?P<service>[\w.-]+)\]\s+(?P<message>.*)$",
            re.IGNORECASE,
        ),
        re.compile(
            rf"^\s*(?P<timestamp>{_TIMESTAMP})\s+"
            rf"(?P<severity>{_SEVERITY_ALT})\s+"
            rf"\[(?P<service>[\w.-]+)\]\s+(?P<message>.*)$",
            re.IGNORECASE,
        ),
        re.compile(
            rf"^\s*(?P<severity>{_SEVERITY_ALT}):\s*(?P<message>.*)$",
            re.IGNORECASE,
        ),
        # Generic timestamp + severity + message, e.g.
        # 2026-10-22 10:00:02 ERROR Database connection failed.
        # Keep this after the more specific patterns above.
        re.compile(
            rf"^\s*(?P<timestamp>{_TIMESTAMP})\s+"
            rf"(?P<severity>{_SEVERITY_ALT})\b\s+"
            rf"(?P<message>.*)$",
            re.IGNORECASE,
        ),
    ]

    SEVERITY_WEIGHTS = {
        "FATAL": 100,
        "CRITICAL": 100,
        "SECURITY": 90,
        "ERROR": 70,
        "WARNING": 30,
        "WARN": 30,
        "INFO": 10,
        "SUCCESS": 10,
        "DEBUG": 5,
        "TRACE": 1,
        "UNKNOWN": 0,
    }

    @staticmethod
    def _normalize_severity(token: str) -> str:
        token = token.strip().upper()

        if token == "SUCCESS":
            return SeverityLevel.INFO.value
        if token == "TRACE":
            return SeverityLevel.DEBUG.value

        return SeverityLevel.from_token(token).value

    @staticmethod
    def _event(
        raw_line: str,
        timestamp=None,
        severity="UNKNOWN",
        service="unknown",
        message=None,
        parse_status="parsed",
    ) -> Dict:
        return {
            "timestamp": timestamp,
            "severity": severity,
            "service": service or "general",
            "message": message if message is not None else raw_line,
            "raw": raw_line.strip(),
            "parse_status": parse_status,
            "continuation_lines": 0,
        } | {"message": (message if message is not None else raw_line).strip()}

    @staticmethod
    def _is_continuation_line(original_line: str, stripped_line: str) -> bool:
        """Recognize common traceback and response continuation patterns."""
        if not stripped_line:
            return False

        if _LOG_START_HINT.match(stripped_line):
            return False

        if original_line[:1].isspace():
            return True

        if _TRACEBACK_START.match(stripped_line):
            return True

        if _STACK_FRAME.match(original_line):
            return True

        if _EXCEPTION_LINE.match(stripped_line):
            return True

        if _HTTP_METADATA.match(stripped_line):
            return True

        return stripped_line == ">"

    @staticmethod
    def _append_continuation(event: Dict, original_line: str) -> None:
        """Retain continuation text without creating a second event."""
        continuation = original_line.rstrip()
        event["raw"] = f'{event["raw"]}\n{continuation}'
        event["message"] = f'{event["message"]}\n{continuation}'
        event["continuation_lines"] = event.get("continuation_lines", 0) + 1

    def parse_logs(self, log_text: str) -> List[Dict]:
        """Return one event per recognized record, grouping known continuations."""
        events = []

        for source_line, original_line in enumerate(log_text.splitlines(), start=1):
            raw = original_line.strip()
            if not raw:
                continue

            match = self.LOGURU_PATTERN.match(raw)
            if match:
                groups = match.groupdict()
                events.append(
                    self._event(
                        raw_line=raw,
                        timestamp=groups["timestamp"],
                        severity=self._normalize_severity(groups["severity"]),
                        service=groups.get("module") or "general",
                        message=groups.get("message", ""),
                    )
                )
                continue

            matched = False
            for pattern in self.PATTERNS:
                match = pattern.match(raw)
                if not match:
                    continue

                groups = match.groupdict()
                events.append(
                    self._event(
                        raw_line=raw,
                        timestamp=groups.get("timestamp"),
                        severity=self._normalize_severity(groups["severity"]),
                        service=groups.get("service") or "general",
                        message=groups.get("message", raw),
                    )
                )
                matched = True
                break

            if matched:
                continue

            if events and self._is_continuation_line(original_line, raw):
                self._append_continuation(events[-1], original_line)
                continue

            events.append(
                self._event(
                    raw_line=raw,
                    severity="UNKNOWN",
                    service="unknown",
                    message=raw,
                    parse_status="unparsed",
                )
            )

        # Attach deterministic provenance after parsing. Continuation lines are
        # represented by source_end_line where their text can be matched safely.
        physical_lines = log_text.splitlines()
        cursor = 0
        for event in events:
            raw_start = str(event.get("raw", "")).splitlines()[0].strip()
            found = next((i for i in range(cursor, len(physical_lines)) if physical_lines[i].strip() == raw_start), None)
            if found is None:
                found = next((i for i, line in enumerate(physical_lines) if line.strip() == raw_start), 0)
            event["source"] = "<stdin>"
            event["source_line"] = found + 1
            continuation_count = int(event.get("continuation_lines", 0) or 0)
            event["source_end_line"] = min(len(physical_lines), found + 1 + continuation_count)
            cursor = found + 1
        return assign_event_ids(events, "<stdin>")

    def get_severity_score(self, events: List[Dict]) -> int:
        return sum(
            self.SEVERITY_WEIGHTS.get(
                str(event.get("severity", "UNKNOWN")).upper(), 0
            )
            for event in events
        )

    def get_service_errors(self, events: List[Dict]) -> Dict[str, int]:
        service_errors: Counter = Counter()

        for event in events:
            if str(event.get("severity", "")).upper() in INCIDENT_SEVERITIES:
                service_errors[event.get("service", "unknown")] += 1

        return dict(service_errors)


parser_engine = LogParserEngine()
