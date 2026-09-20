"""Embedding service: Ollama call, Redis cache and loud failure."""

import pytest

from app.services import embedding_service as svc


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def fake_http(monkeypatch, payload=None, error=None):
    calls = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            pass

        async def post(self, url, json):
            calls.append(json)
            if error:
                raise error
            return FakeResponse(payload)

    monkeypatch.setattr(svc.httpx, "AsyncClient", FakeClient)
    return calls


async def test_returns_the_ollama_embedding_and_caches_it(monkeypatch, fake_redis):
    calls = fake_http(monkeypatch, {"embedding": [0.1] * svc.EMBEDDING_DIM})

    first = await svc.get_embedding("brute force")
    second = await svc.get_embedding("brute force")

    assert first == second and len(first) == svc.EMBEDDING_DIM
    assert len(calls) == 1, "second call must come from the cache"


async def test_ollama_outage_raises_instead_of_returning_a_fake_vector(monkeypatch, fake_redis):
    fake_http(monkeypatch, error=ConnectionError("ollama down"))
    with pytest.raises(svc.EmbeddingError):
        await svc.get_embedding("anything")


async def test_empty_embedding_raises(monkeypatch, fake_redis):
    fake_http(monkeypatch, {"embedding": []})
    with pytest.raises(svc.EmbeddingError):
        await svc.get_embedding("anything")
