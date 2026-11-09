"""Measure memem's search on LongMemEval, locally and for free.

This runs the real Store code against SQLite, so keyword search, the cutoff and rank fusion are memem's own.
Only the vector index is replaced, by exact search over the same embedding model the Worker uses.

It measures retrieval only: can search find the conversation that holds the answer? Every conversation is saved
whole, so this says nothing about what an assistant would choose to save.

    uv run --no-project --python 3.12 --with fastembed --with numpy python benchmarks/longmemeval.py --questions 100
"""

import argparse
import asyncio
import json
import random
import sqlite3
import statistics
import sys
import time
import types
import urllib.request
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".benchmark"
DATA_URL = "https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/main/longmemeval_s_cleaned.json"
MODEL = "BAAI/bge-base-en-v1.5"
SPACE = "benchmark"
CHUNK_CHARS = 1500
RESULT_LIMIT = 20
CUTOFFS = (0.0, 0.4, 0.45, 0.5, 0.52, 0.55, 0.6, 0.65)

# store.py imports these Worker-only modules, but only the file-deletion path uses them.
sys.modules["js"] = types.SimpleNamespace(Object=object)
sys.modules["pyodide"] = types.ModuleType("pyodide")
sys.modules["pyodide.ffi"] = types.SimpleNamespace(to_js=None)
sys.path.insert(0, str(ROOT / "src"))

import store as memem  # noqa: E402


class _Statement:
    def __init__(self, connection, sql):
        self._connection, self._sql, self._params = connection, sql, ()

    def bind(self, *params):
        self._params = params
        return self

    async def all(self):
        rows = self._connection.execute(self._sql, self._params).fetchall()
        return types.SimpleNamespace(results=[dict(row) for row in rows])


class SqliteDatabase:
    """The small part of D1's interface that Store uses."""

    def __init__(self):
        self._connection = sqlite3.connect(":memory:")
        self._connection.row_factory = sqlite3.Row
        for migration in sorted((ROOT / "migrations").glob("*.sql")):
            self._connection.executescript(migration.read_text())

    def prepare(self, sql):
        return _Statement(self._connection, sql)

    def build_full_text_index(self):
        self._connection.executescript(
            "CREATE VIRTUAL TABLE memories_fts USING fts5(content, content='memories', content_rowid='id',"
            " tokenize='porter unicode61');"
            "INSERT INTO memories_fts(memories_fts) VALUES('rebuild');"
        )


class Embedder:
    def __init__(self):
        from fastembed import TextEmbedding

        self._model = TextEmbedding(MODEL, cache_dir=str(CACHE / "model"))
        self._vectors = {}

    def prepare(self, texts):
        missing = list({text for text in texts if text not in self._vectors})
        if missing:
            # parallel=0 uses every CPU core.
            for done, (text, vector) in enumerate(zip(missing, self._model.embed(missing, batch_size=32, parallel=0)), 1):
                self._vectors[text] = vector / np.linalg.norm(vector)
                if done % 2000 == 0:
                    print(f"embedded {done}/{len(missing)}", flush=True)

    def __call__(self, text):
        return self._vectors[text]


class ExactVectors:
    """Stands in for Vectorize, with the same add and query shape as the Worker's backend."""

    def __init__(self, embed):
        self._embed, self._ids, self._vectors, self._matrix = embed, [], [], None

    async def add(self, space, vector_id, text):
        self._ids.append(vector_id)
        self._vectors.append(self._embed(text))
        self._matrix = None

    async def query(self, space, text, limit):
        if self._matrix is None:
            self._matrix = np.stack(self._vectors)
        scores = self._matrix @ self._embed(text)
        best = np.argsort(-scores)[:limit]
        return [(self._ids[i], float(scores[i])) for i in best]

    async def remove(self, vector_id):
        raise NotImplementedError


class MeaningOnlyStore(memem.Store):
    async def _keyword_matches(self, space, query):
        return []


class RankedKeywordStore(memem.Store):
    """Tries SQLite full-text search with BM25 ranking in place of memem's word-count keyword search."""

    async def _keyword_matches(self, space, query):
        words = memem._search_words(query)
        if not words:
            return []
        match = " OR ".join('"' + word.replace('"', '""') + '"' for word in words)
        return await self._all(
            "SELECT m.id, m.content, m.source, m.created_at FROM memories_fts"
            " JOIN memories m ON m.id = memories_fts.rowid"
            " WHERE memories_fts MATCH ? AND m.space = ? ORDER BY bm25(memories_fts), m.id DESC LIMIT ?",
            match,
            space,
            memem.CANDIDATES,
        )


def chunks(session):
    """Split a conversation into pieces no longer than the embedding model reads well."""
    pieces, pending = [], ""
    for turn in session:
        line = f"{turn['role'].title()}: {turn['content']}"
        if pending and turn["role"] == "user":
            pieces.append(pending)
            pending = ""
        pending = f"{pending}\n{line}".strip()
    if pending:
        pieces.append(pending)
    return [piece[i : i + CHUNK_CHARS] for piece in pieces for i in range(0, len(piece), CHUNK_CHARS)]


def load_questions(count, seed):
    CACHE.mkdir(exist_ok=True)
    path = CACHE / "longmemeval_s_cleaned.json"
    if not path.exists():
        print("Downloading LongMemEval (277 MB)...", flush=True)
        request = urllib.request.Request(DATA_URL, headers={"user-agent": "memem-benchmark"})
        with urllib.request.urlopen(request) as reply, open(path, "wb") as out:
            while block := reply.read(1 << 20):
                out.write(block)
    questions = [
        q for q in json.loads(path.read_text()) if q["answer_session_ids"] and not q["question_id"].endswith("_abs")
    ]
    return sorted(random.Random(seed).sample(questions, min(count, len(questions))), key=lambda q: q["question_id"])


def score(ranked_sessions, gold):
    """Rank-based measures, counting a conversation as found when any of its pieces is returned."""
    seen = list(dict.fromkeys(ranked_sessions))
    rank = next((i for i, session in enumerate(seen, 1) if session in gold), None)
    return {
        # The strict measure: is an answer conversation among the first 5 results an assistant actually receives?
        "first 5 results": float(bool(gold & set(ranked_sessions[:5]))),
        "hit@5": float(rank is not None and rank <= 5),
        "hit@10": float(rank is not None and rank <= 10),
        "recall@10": len(gold & set(seen[:10])) / len(gold),
        "mrr": 1 / rank if rank else 0.0,
        "returned": float(len(ranked_sessions)),
    }


async def evaluate(question, embed):
    sessions = []
    for session_id, session in zip(question["haystack_session_ids"], question["haystack_sessions"]):
        sessions += [(session_id, piece) for piece in chunks(session)]
    embed.prepare([text for _, text in sessions] + [question["question"]])

    db, vectors = SqliteDatabase(), ExactVectors(embed)
    loader, session_of = memem.Store(db, vectors), {}
    for session_id, text in sessions:
        session_of[await loader.remember(SPACE, text[:10_000], "benchmark")] = session_id

    db.build_full_text_index()

    async def run(store, cutoff):
        memem.MIN_SIMILARITY = cutoff
        found = await store.recall(SPACE, question["question"], RESULT_LIMIT)
        return score([session_of[m["id"]] for m in found], set(question["answer_session_ids"]))

    results = {"keyword only": await run(memem.Store(db), 0.0)}
    results["meaning only, cutoff 0.52"] = await run(MeaningOnlyStore(db, vectors), 0.52)
    for cutoff in CUTOFFS:
        results[f"hybrid, cutoff {cutoff:.2f}"] = await run(memem.Store(db, vectors), cutoff)
    results["ranked keyword only"] = await run(RankedKeywordStore(db), 0.0)
    results["ranked hybrid, cutoff 0.52"] = await run(RankedKeywordStore(db, vectors), 0.52)
    return results, len(sessions)


def average(rows):
    return {key: statistics.fmean(row[key] for row in rows) for key in rows[0]}


def summarize(rows, seed):
    by_mode, by_type = defaultdict(list), defaultdict(list)
    for row in rows:
        for mode, result in row["results"].items():
            by_mode[mode].append(result)
        by_type[row["type"]].append(row["results"]["hybrid, cutoff 0.52"])

    summary = {
        "questions": len(rows),
        "pieces": sum(row["pieces"] for row in rows),
        "seed": seed,
        "modes": {mode: average(results) for mode, results in by_mode.items()},
        "hybrid_0.52_by_type": {kind: {"n": len(results), **average(results)} for kind, results in sorted(by_type.items())},
    }
    (CACHE / "results.json").write_text(json.dumps(summary, indent=2))

    print(f"\n{'mode':<28}{'first 5':>9}{'hit@5':>8}{'hit@10':>8}{'recall@10':>11}{'mrr':>7}{'returned':>10}")
    for mode, row in summary["modes"].items():
        print(f"{mode:<28}{row['first 5 results']:>9.3f}{row['hit@5']:>8.3f}{row['hit@10']:>8.3f}{row['recall@10']:>11.3f}{row['mrr']:>7.3f}{row['returned']:>10.1f}")
    print(f"\n{'hybrid 0.52, by type':<28}{'n':>5}{'first 5':>9}{'hit@5':>8}{'recall@10':>11}")
    for kind, row in summary["hybrid_0.52_by_type"].items():
        print(f"{kind:<28}{row['n']:>5}{row['first 5 results']:>9.3f}{row['hit@5']:>8.3f}{row['recall@10']:>11.3f}")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--questions", type=int, default=100)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--shard", type=int, default=0, help="which part of the questions to run")
    parser.add_argument("--shards", type=int, default=1, help="how many parts to split the questions into")
    parser.add_argument("--merge", action="store_true", help="combine the rows-*.json files from finished shards")
    args = parser.parse_args()

    if args.merge:
        rows = [row for path in sorted(CACHE.glob("rows-*.json")) for row in json.loads(path.read_text())]
        summarize(rows, args.seed)
        return

    questions = load_questions(args.questions, args.seed)[args.shard :: args.shards]
    print("Loading the embedding model...", flush=True)
    embed = Embedder()
    # One pass, so the worker processes only start once.
    embed.prepare([text for q in questions for session in q["haystack_sessions"] for text in chunks(session)] + [q["question"] for q in questions])
    rows, start = [], time.time()
    for done, question in enumerate(questions, 1):
        results, count = await evaluate(question, embed)
        rows.append({"type": question["question_type"], "pieces": count, "results": results})
        if done % 5 == 0 or done == len(questions):
            print(f"{done}/{len(questions)} questions, {sum(r['pieces'] for r in rows)} pieces, {time.time() - start:.0f}s", flush=True)

    (CACHE / f"rows-{args.shard}.json").write_text(json.dumps(rows))
    summarize(rows, args.seed)


if __name__ == "__main__":
    asyncio.run(main())
