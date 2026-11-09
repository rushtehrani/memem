"""Search by meaning, using Workers AI embeddings and a Vectorize index."""

import json
from urllib.parse import urlsplit

from js import Object
from pyodide.ffi import to_js
from workers import fetch

MODEL = "@cf/baai/bge-base-en-v1.5"
DIMENSIONS = 768


def _js(value):
    return to_js(value, dict_converter=Object.fromEntries)


def _py(value):
    return value.to_py() if hasattr(value, "to_py") else value


class CloudflareBackend:
    """Each memory space is a Vectorize namespace."""

    def __init__(self, ai, index):
        self._ai = ai
        self._index = index

    async def _embed(self, text: str) -> list[float]:
        result = await self._ai.run(MODEL, _js({"text": [text]}))
        return list(_py(result.data)[0])

    async def add(self, space: str, vector_id: str, text: str) -> None:
        vector = {"id": vector_id, "values": await self._embed(text), "namespace": space}
        await self._index.upsert(_js([vector]))

    async def query(self, space: str, text: str, limit: int) -> list[tuple[str, float]]:
        options = {"topK": limit, "namespace": space, "returnValues": False, "returnMetadata": "none"}
        result = await self._index.query(_js(await self._embed(text)), _js(options))
        return [(str(match.id), float(match.score)) for match in _py(result.matches)]

    async def remove(self, vector_id: str) -> None:
        await self._index.deleteByIds(_js([vector_id]))


class HttpBackend:
    """Stand-in used by tests, which cannot run Workers AI or Vectorize locally."""

    def __init__(self, base: str):
        self._base = base

    async def _post(self, path: str, body: dict) -> dict:
        reply = await fetch(
            f"{self._base}{path}",
            method="POST",
            headers={"content-type": "application/json"},
            body=json.dumps(body),
        )
        if reply.status != 200:
            raise RuntimeError("backend failed")
        return json.loads(await reply.text())

    async def add(self, space: str, vector_id: str, text: str) -> None:
        await self._post("/add", {"space": space, "id": vector_id, "text": text})

    async def query(self, space: str, text: str, limit: int) -> list[tuple[str, float]]:
        reply = await self._post("/query", {"space": space, "text": text, "limit": limit})
        return [(match["id"], match["score"]) for match in reply["matches"]]

    async def remove(self, vector_id: str) -> None:
        await self._post("/remove", {"id": vector_id})


def from_env(env, origin: str):
    test_base = getattr(env, "MEMEM_SEMANTIC_TEST_BASE", None)
    if isinstance(test_base, str) and urlsplit(origin).hostname == "127.0.0.1":
        return HttpBackend(test_base)
    ai, index = getattr(env, "AI", None), getattr(env, "VECTORIZE", None)
    return CloudflareBackend(ai, index) if ai and index else None
