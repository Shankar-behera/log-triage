"""Stable result object for the public Log Triage API."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional


@dataclass(frozen=True)
class AnalysisResult:
    """A typed wrapper around the engine's backward-compatible result mapping.

    The ``to_dict`` method returns a defensive copy so callers cannot mutate the
    result held by this object. Existing engine fields are preserved in ``data``.
    """

    data: Mapping[str, Any] = field(repr=False)

    @property
    def success(self) -> bool:
        return bool(self.data.get("success", False))

    @property
    def summary(self) -> str:
        return str(self.data.get("summary", ""))

    @property
    def priority(self) -> str:
        return str(self.data.get("priority", "low"))

    @property
    def events(self) -> List[Dict[str, Any]]:
        value = self.data.get("events", [])
        return deepcopy(value) if isinstance(value, list) else []

    @property
    def analysis_type(self) -> str:
        return str(self.data.get("analysis_type", "quick"))

    @property
    def source(self) -> Optional[str]:
        events = self.data.get("events", [])
        if events and isinstance(events[0], dict):
            return events[0].get("source")
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable defensive copy of the analysis result."""
        return deepcopy(dict(self.data))

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access for convenient migration from the CLI."""
        return deepcopy(self.data[key])
