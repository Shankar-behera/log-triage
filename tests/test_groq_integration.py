
import asyncio
from types import SimpleNamespace

import logtriage.groq as groq
from logtriage import Analyzer, GroqExplanationProvider
from logtriage.exceptions import ProviderError


class FakeResponse:
    status_code = 200

    def json(self):
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            "The database connection timed out. "
                            "Check database availability and connection limits."
                        )
                    }
                }
            ]
        }


class FakeSession:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeResponse()


def configure_test_settings(monkeypatch):
    monkeypatch.setattr(
        groq,
        "settings",
        SimpleNamespace(
            GROQ_API_KEY="synthetic-integration-test-key",
            GROQ_MODEL="test-model",
            GROQ_BASE_URL="https://example.invalid/openai/v1",
            GROQ_TIMEOUT_SECONDS=3.0,
        ),
    )


def test_analyzer_explain_integrates_with_groq_provider(monkeypatch):
    configure_test_settings(monkeypatch)
    session = FakeSession()
    provider = GroqExplanationProvider(session=session)

    result = asyncio.run(
        Analyzer().explain(
            "ERROR database connection timeout",
            provider=provider,
        )
    )

    assert result.provider == "groq"
    assert result.model == "test-model"
    assert "database connection timed out" in result.text.lower()
    assert len(session.calls) == 1

    _, kwargs = session.calls[0]
    sent_content = kwargs["json"]["messages"][1]["content"]
    assert "database connection timeout" in sent_content


def test_analyzer_explain_sanitizes_provider_failure(monkeypatch):
    configure_test_settings(monkeypatch)

    class FailingSession:
        def post(self, url, **kwargs):
            raise RuntimeError("synthetic-private-error")

    provider = GroqExplanationProvider(session=FailingSession())

    with __import__("pytest").raises(ProviderError) as exc:
        asyncio.run(
            Analyzer().explain(
                "ERROR database connection timeout",
                provider=provider,
            )
        )

    assert "synthetic-private-error" not in str(exc.value)
