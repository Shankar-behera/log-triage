"""Public contracts for optional AI explanation providers."""

from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass(frozen=True)
class ExplanationRequest:
    """Request passed to a provider; content is redacted before dispatch."""

    redacted_content: str
    model: Optional[str] = None
    max_tokens: int = 512

    def __post_init__(self) -> None:
        if not isinstance(self.redacted_content, str):
            raise ValueError("redacted_content must be a string")
        if not self.redacted_content.strip():
            raise ValueError("redacted_content must not be empty")
        if not isinstance(self.max_tokens, int) or isinstance(self.max_tokens, bool):
            raise ValueError("max_tokens must be an integer")
        if not 1 <= self.max_tokens <= 4096:
            raise ValueError("max_tokens must be between 1 and 4096")
        if self.model is not None:
            if not isinstance(self.model, str) or not self.model.strip():
                raise ValueError("model must be a non-empty string or None")


@dataclass(frozen=True)
class ExplanationResponse:
    """Normalized explanation returned by a provider."""

    text: str
    provider: str
    model: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("text must be a non-empty string")
        if not isinstance(self.provider, str) or not self.provider.strip():
            raise ValueError("provider must be a non-empty string")
        if self.model is not None:
            if not isinstance(self.model, str) or not self.model.strip():
                raise ValueError("model must be a non-empty string or None")


class ExplanationProvider(Protocol):
    """Interface implemented by optional AI explanation providers."""

    async def explain(
        self,
        request: ExplanationRequest,
    ) -> ExplanationResponse:
        """Return an explanation for redacted log content."""
        ...
