"""Log Triage public Python API.

The public facade is intentionally small and stable. Internal ``app`` modules
remain implementation details and may change between releases.
"""

from .api import Analyzer
from .exceptions import InvalidInputError, LogTriageError, UnsupportedModeError
from .options import AnalysisOptions
from .results import AnalysisResult

__all__ = [
    "Analyzer",
    "AnalysisOptions",
    "AnalysisResult",
    "LogTriageError",
    "InvalidInputError",
    "UnsupportedModeError",
]

__version__ = "0.1.0"
