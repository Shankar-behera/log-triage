"""Log Triage public Python API.

The public facade is intentionally small and stable. Internal ``app`` modules
remain implementation details and may change between releases.
"""

from .api import Analyzer
from .exceptions import (
    InvalidInputError,
    LogTriageError,
    ProviderError,
    UnsupportedModeError,
)
from .options import AnalysisOptions
from .providers import (
    ExplanationProvider,
    ExplanationRequest,
    ExplanationResponse,
)
from .results import AnalysisResult
from .groq import GroqExplanationProvider

__all__ = [
    "Analyzer",
    "AnalysisOptions",
    "AnalysisResult",
    "ExplanationProvider",
    "ExplanationRequest",
    "ExplanationResponse",
    "LogTriageError",
    "InvalidInputError",
    "ProviderError",
    "UnsupportedModeError",
    "GroqExplanationProvider",
]

__version__ = "0.1.0"
