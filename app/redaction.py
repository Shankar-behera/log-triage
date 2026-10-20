"""Best-effort secret redaction and safe rendering for log content."""
import re
from typing import Any

_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]+=*"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|token)\b(\s*[:=]\s*)([^\s,;]+)"), r"\1\2[REDACTED]"),
    # Greedy password capture uses the final @ before the host as the delimiter,
    # so passwords containing literal @ characters are masked too.
    (re.compile(r"(?i)(https?://[^:/\s]+:)([^/\s]*)(@)"), r"\1[REDACTED]\3"),
    (re.compile(r"(?i)([?&](?:token|api_key|apikey|password|secret)=)[^&#\s]+"), r"\1[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(cookie\s*[:=]\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:password|pwd)\s*=\s*)[^;\r\n]*"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:user\s*id|uid)\s*=\s*)[^;\r\n]*"), r"\1[REDACTED]"),
]

_PII_PATTERNS = [
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "[REDACTED_EMAIL]"),
    (re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])"), "[REDACTED_IP]"),
]


def redact_text(value: str, *, pii: bool = False) -> str:
    """Redact common secrets and optionally email/IP PII.

    This heuristic is not a guarantee. PII redaction is opt-in so useful
    diagnostic IP addresses are preserved by default.
    """
    text = value
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    if pii:
        for pattern, replacement in _PII_PATTERNS:
            text = pattern.sub(replacement, text)
    return text


def redact_log_input(value: str, *, pii: bool = False) -> str:
    """Redact log input before analysis, provider calls, or storage."""
    return redact_text(value, pii=pii)


def sanitize_output(
    value: Any,
    redact: bool = True,
    pii: bool = False,
) -> Any:
    """Redact strings recursively and escape terminal control characters."""
    if isinstance(value, str):
        if redact:
            value = redact_text(value, pii=pii)
        return "".join(
            ch if ch in "\n\t" or (ord(ch) >= 32 and ord(ch) != 127)
            else f"\\x{ord(ch):02x}"
            for ch in value
        )
    if isinstance(value, list):
        return [sanitize_output(item, redact=redact, pii=pii) for item in value]
    if isinstance(value, tuple):
        return [sanitize_output(item, redact=redact, pii=pii) for item in value]
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            safe_key = sanitize_output(key, redact=redact, pii=pii)
            safe_value = sanitize_output(item, redact=redact, pii=pii)
            if safe_key in sanitized:
                # Keep colliding redacted keys distinct without restoring
                # the original sensitive key.
                base_key = (
                    safe_key if isinstance(safe_key, str) else str(safe_key)
                )
                suffix = 2
                candidate = f"{base_key}#{suffix}"
                while candidate in sanitized:
                    suffix += 1
                    candidate = f"{base_key}#{suffix}"
                safe_key = candidate
            sanitized[safe_key] = safe_value
        return sanitized
    return value
