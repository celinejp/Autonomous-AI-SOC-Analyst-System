"""LLM provider selection."""

import pytest

from app.core import llm_factory
from app.core.config import settings


def test_default_provider_is_ollama(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "ollama")
    monkeypatch.setattr(settings, "llm_model", "default")
    llm = llm_factory.get_llm()
    assert type(llm).__name__ == "ChatOllama" and llm.model == "llama3.1"


def test_unknown_provider_falls_back_to_ollama(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "nonsense")
    assert type(llm_factory.get_llm()).__name__ == "ChatOllama"


@pytest.mark.parametrize("provider,key_setting", [("openai", "openai_api_key"), ("groq", "groq_api_key"), ("anthropic", "anthropic_api_key")])
def test_hosted_providers_require_an_api_key(monkeypatch, provider, key_setting):
    monkeypatch.setattr(settings, "llm_provider", provider)
    monkeypatch.setattr(settings, key_setting, "")
    with pytest.raises(ValueError):
        llm_factory.get_llm()
