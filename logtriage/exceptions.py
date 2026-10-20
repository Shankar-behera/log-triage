"""Stable exceptions exposed by the public Log Triage library."""


class LogTriageError(Exception):
    """Base exception for public Log Triage API errors."""


class InvalidInputError(LogTriageError, ValueError):
    """Raised when an input value is not supported by the public API."""


class UnsupportedModeError(LogTriageError, ValueError):
    """Raised when a requested analysis mode is not supported by this API."""
