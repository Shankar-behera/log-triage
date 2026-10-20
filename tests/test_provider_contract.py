import asyncio

import pytest

from logtriage import (
    Analyzer,
    ExplanationRequest,
    ExplanationResponse,
    InvalidInputError,
    ProviderError,
)


class FakeProvider:
    def __init__(self, response=None, failure=None):
        self.request = None
        self.response = response or ExplanationResponse(
            text="Database timeout detected",
            provider="fake",
            model="fake-model",
        )
        self.failure = failure

    async def explain(self, request):
        self.request = request
        if self.failure is not None:
            raise self.failure
        return self.response


def test_request_rejects_invalid_token_limits():
    with pytest.raises(ValueError):
        ExplanationRequest(redacted_content="ERROR", max_tokens=0)

    with pytest.raises(ValueError):
        ExplanationRequest(redacted_content="ERROR", max_tokens=True)


def test_response_rejects_empty_explanation():
    with pytest.raises(ValueError):
        ExplanationResponse(text=" ", provider="fake")


def test_explain_redacts_input_before_provider_call():
    provider = FakeProvider()

    result = asyncio.run(
        Analyzer().explain(
            "ERROR password=hunter2",
            provider=provider,
        )
    )

    assert provider.request is not None
    assert "hunter2" not in provider.request.redacted_content
    assert "[REDACTED]" in provider.request.redacted_content
    assert result.provider == "fake"


def test_explain_redacts_provider_output():
    provider = FakeProvider(
        response=ExplanationResponse(
            text="The observed password=hunter2 should be rotated",
            provider="fake",
        )
    )

    result = asyncio.run(
        Analyzer().explain("ERROR database failure", provider=provider)
    )

    assert "hunter2" not in result.text
    assert "[REDACTED]" in result.text


def test_provider_exception_is_sanitized():
    provider = FakeProvider(failure=RuntimeError("secret=hunter2"))

    with pytest.raises(ProviderError) as error:
        asyncio.run(
            Analyzer().explain(
                "ERROR password=original-secret",
                provider=provider,
            )
        )

    assert "hunter2" not in str(error.value)
    assert "original-secret" not in str(error.value)


def test_invalid_content_is_rejected_before_provider_call():
    provider = FakeProvider()

    with pytest.raises(InvalidInputError):
        asyncio.run(Analyzer().explain("  ", provider=provider))

    assert provider.request is None


def test_invalid_provider_response_is_rejected():
    class InvalidProvider:
        async def explain(self, request):
            return {"text": "not a typed response"}

    with pytest.raises(ProviderError, match="invalid response"):
        asyncio.run(
            Analyzer().explain(
                "ERROR database failure",
                provider=InvalidProvider(),
            )
        )


def test_provider_receives_requested_model_and_token_limit():
    provider = FakeProvider()

    asyncio.run(
        Analyzer().explain(
            "ERROR database failure",
            provider=provider,
            model="test-model",
            max_tokens=256,
        )
    )

    assert provider.request.model == "test-model"
    assert provider.request.max_tokens == 256


def test_explain_redacts_email_and_ip_before_provider_call():
    provider = FakeProvider()

    asyncio.run(
        Analyzer().explain(
            "Failed login for alice@example.com from 203.0.113.45",
            provider=provider,
        )
    )

    assert provider.request is not None
    assert "alice@example.com" not in provider.request.redacted_content
    assert "203.0.113.45" not in provider.request.redacted_content
    assert "[REDACTED_EMAIL]" in provider.request.redacted_content
    assert "[REDACTED_IP]" in provider.request.redacted_content


def test_explain_escapes_control_characters_in_provider_output():
    provider = FakeProvider(
        response=ExplanationResponse(
            text="Warning:\x1b[31m password=hunter2",
            provider="fake",
        )
    )

    result = asyncio.run(
        Analyzer().explain("ERROR login failed", provider=provider)
    )

    assert "\x1b" not in result.text
    assert "\\x1b" in result.text
    assert "hunter2" not in result.text
