"""Measure memem end to end on LoCoMo: a model saves memories with memem's real tools, then answers from them.

Unlike the retrieval benchmark, this tests writing too. For each conversation, a model reads it session by session
with memem's tools and saves what it judges worth keeping. A fresh chat then answers each question using only
memem's search, and a judge model grades the answers. Adversarial questions (category 5) are left out.

memem runs inside the benchmark: the real tool handlers and Store over SQLite, with the same embedding model as the
Worker. Nothing touches a live deployment. It needs ANTHROPIC_API_KEY, and costs about $0.18 per conversation with
Claude Haiku 5.5. It normally runs on GitHub Actions: see benchmarks/README.md.

    uv run --no-project --python 3.12 --with anthropic --with fastembed --with numpy \\
        python benchmarks/locomo.py --conversations 0
    python benchmarks/locomo.py --merge
"""

import argparse
import asyncio
import json
import sqlite3
import sys
import time
import types
import urllib.request
from collections import defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".benchmark" / "locomo"
DATA_URL = "https://raw.githubusercontent.com/snap-research/locomo/main/data/locomo10.json"
EMBEDDING_MODEL = "BAAI/bge-base-en-v1.5"
MODEL = "claude-haiku-5-5"
PRICES = {"input": 0.10, "output": 0.50, "cache_write": 0.125, "cache_read": 0.01}  # dollars per million tokens
CATEGORIES = {1: "multi-hop", 2: "temporal", 3: "open-domain", 4: "single-hop"}
SAVE_TOOLS = ["get_memory_overview", "search_memories", "list_memories", "add_memory", "update_memory", "delete_memory"]
ANSWER_TOOLS = ["search_memories", "list_memories"]
MAX_TOOL_ROUNDS = 15
PARALLEL = 6

SAVE_SYSTEM = (
    "You are an AI assistant with memem, a memory the user shares across their AI assistants. The user is {a}. "
    "They will paste conversations between {a} and {b}, one session at a time, and have asked you to keep "
    "anything future chats should remember about either person. Save memories with memem's tools as you "
    "normally would. When done, reply with one short line."
)
ANSWER_SYSTEM = (
    "You are an AI assistant with memem, a memory the user shares across their AI assistants. Answer the "
    "question about {a} and {b} using memem. Reply with a short answer only, a few words or one sentence. "
    "If memem doesn't have it, say you don't know."
)
JUDGE_PROMPT = (
    "Question: {question}\nCorrect answer: {gold}\nResponse: {response}\n\n"
    "Does the response give the correct answer? Count it as correct if it states the same facts, even in other "
    "words or with extra detail. For dates, the same day, month or period written differently counts. "
    "Reply with only CORRECT or WRONG."
)


def load_memem(src: Path):
    """Imports memem's Worker code with the Worker-only modules stubbed out."""
    sys.modules["js"] = types.SimpleNamespace(Object=object)
    sys.modules["pyodide"] = types.ModuleType("pyodide")
    sys.modules["pyodide.ffi"] = types.SimpleNamespace(to_js=None)
    sys.modules["workers"] = types.SimpleNamespace(Response=object, WorkerEntrypoint=object, fetch=None)
    sys.path.insert(0, str(src))
    import entry
    import store

    return entry, store


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

    def __init__(self, migrations: Path):
        self._connection = sqlite3.connect(":memory:")
        self._connection.row_factory = sqlite3.Row
        for migration in sorted(migrations.glob("*.sql")):
            self._connection.executescript(migration.read_text())

    def prepare(self, sql):
        return _Statement(self._connection, sql)


class LocalVectors:
    """Stands in for Workers AI and Vectorize, using the same embedding model on this machine."""

    def __init__(self):
        from fastembed import TextEmbedding

        self._model = TextEmbedding(EMBEDDING_MODEL, cache_dir=str(ROOT / ".benchmark" / "model"))
        self._cache, self._vectors = {}, {}

    def _embed(self, text):
        if text not in self._cache:
            vector = next(iter(self._model.embed([text])))
            self._cache[text] = vector / np.linalg.norm(vector)
        return self._cache[text]

    async def add(self, space, vector_id, text):
        self._vectors[vector_id] = (space, self._embed(text))

    async def query(self, space, text, limit):
        query = self._embed(text)
        scores = [(vector_id, float(vector @ query)) for vector_id, (s, vector) in self._vectors.items() if s == space]
        return sorted(scores, key=lambda item: -item[1])[:limit]

    async def remove(self, vector_id):
        self._vectors.pop(vector_id, None)


class Usage:
    def __init__(self):
        self.tokens = defaultdict(lambda: defaultdict(int))

    def add(self, phase, usage):
        self.tokens[phase]["input"] += usage.input_tokens
        self.tokens[phase]["output"] += usage.output_tokens
        self.tokens[phase]["cache_write"] += usage.cache_creation_input_tokens or 0
        self.tokens[phase]["cache_read"] += usage.cache_read_input_tokens or 0

    def cost(self, phase=None):
        phases = [phase] if phase else list(self.tokens)
        return sum(self.tokens[p][kind] * PRICES[kind] / 1e6 for p in phases for kind in PRICES)


async def chat(client, usage, phase, system, prompt, tools, run_tool, cache=False):
    """One chat with memem's tools. Returns the final text reply. Caching pays off only for long saving chats."""
    messages = [{"role": "user", "content": prompt}]
    for _ in range(MAX_TOOL_ROUNDS):
        response = await client.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=system,
            tools=tools,
            messages=messages,
            **({"cache_control": {"type": "ephemeral"}} if cache else {}),
        )
        usage.add(phase, response.usage)
        if response.stop_reason != "tool_use":
            return "".join(block.text for block in response.content if block.type == "text").strip()
        messages.append({"role": "assistant", "content": response.content})
        results = []
        for block in response.content:
            if block.type == "tool_use":
                text, is_error = await run_tool(block.name, block.input)
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": is_error})
        messages.append({"role": "user", "content": results})
    return ""


def session_text(conversation, key):
    lines = []
    for turn in conversation[key]:
        line = f"{turn['speaker']}: {turn['text']}"
        if turn.get("blip_caption"):
            line += f" [shares a photo: {turn['blip_caption']}]"
        lines.append(line)
    return "\n".join(lines)


async def run_conversation(sample, entry, store_module, vectors, client, usage, migrations):
    conversation = sample["conversation"]
    a, b = conversation["speaker_a"], conversation["speaker_b"]
    store = store_module.Store(SqliteDatabase(migrations), vectors)
    conn = store_module.Connection(label="benchmark", space=sample["sample_id"], can_write=True)
    by_name = {tool["name"]: tool for tool in entry.READ_TOOLS + entry.WRITE_TOOLS}

    def tools(names):
        return [{"name": n, "description": by_name[n]["description"], "input_schema": by_name[n]["inputSchema"]} for n in names]

    calls = defaultdict(int)

    async def run_tool(name, arguments):
        calls[name] += 1
        result = await entry._call_tool(store, conn, {"name": name, "arguments": arguments})
        return result["content"][0]["text"], result["isError"]

    sessions = sorted(
        (k for k in conversation if k.startswith("session_") and not k.endswith("date_time")),
        key=lambda k: int(k.split("_")[1]),
    )
    for number, key in enumerate(sessions, 1):
        prompt = f"Session {number}, on {conversation[key + '_date_time']}:\n\n{session_text(conversation, key)}"
        await chat(client, usage, "save", SAVE_SYSTEM.format(a=a, b=b), prompt, tools(SAVE_TOOLS), run_tool, cache=True)
        print(f"  saved session {number}/{len(sessions)}, {usage.cost():.3f} dollars so far", flush=True)

    saved = (await store.browse(conn.space, None, 100))[0]
    total = (await store.overview(conn.space))["total"]
    questions = [q for q in sample["qa"] if q["category"] != 5]
    gate = asyncio.Semaphore(PARALLEL)

    async def answer(question):
        async with gate:
            reply = await chat(
                client, usage, "answer", ANSWER_SYSTEM.format(a=a, b=b), question["question"],
                tools(ANSWER_TOOLS), run_tool,
            )
            verdict = await client.messages.create(
                model=MODEL,
                max_tokens=2000,
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": JUDGE_PROMPT.format(
                    question=question["question"], gold=question["answer"], response=reply or "(no answer)"
                )}],
            )
            usage.add("judge", verdict.usage)
            text = "".join(block.text for block in verdict.content if block.type == "text").upper()
            return {**question, "response": reply, "correct": "CORRECT" in text and "WRONG" not in text}

    answered = await asyncio.gather(*(answer(q) for q in questions))
    return answered, saved, total, dict(calls)


def merge():
    """Combines results files, such as one per GitHub job, into a comparison of the versions tested."""
    by_label = defaultdict(list)
    for path in sorted(CACHE.glob("results-*.json")):
        data = json.loads(path.read_text())
        by_label[data["summary"]["label"]].append(data)
    comparison = {}
    for label, runs in sorted(by_label.items()):
        answers = [a for run in runs for r in run["results"] for a in r["answers"]]
        categories = defaultdict(list)
        for a in answers:
            categories[CATEGORIES.get(a["category"], str(a["category"]))].append(a["correct"])
        comparison[label] = {
            "conversations": sorted(r["conversation"] for run in runs for r in run["results"]),
            "questions": len(answers),
            "accuracy": round(sum(a["correct"] for a in answers) / len(answers), 4),
            "by_category": {c: {"n": len(v), "accuracy": round(sum(v) / len(v), 4)} for c, v in sorted(categories.items())},
            "memories_saved": sum(r["memories"] for run in runs for r in run["results"]),
            "cost_dollars": round(sum(run["summary"]["cost_dollars"]["total"] for run in runs), 4),
        }
    (CACHE / "comparison.json").write_text(json.dumps(comparison, indent=2))
    print(f"\n{'version':<12}{'questions':>10}{'accuracy':>10}{'memories':>10}{'cost $':>9}")
    for label, row in comparison.items():
        print(f"{label:<12}{row['questions']:>10}{row['accuracy']:>10.3f}{row['memories_saved']:>10}{row['cost_dollars']:>9.2f}")
    kinds = sorted({c for row in comparison.values() for c in row["by_category"]})
    print(f"\n{'category':<14}" + "".join(f"{label:>12}" for label in comparison))
    for kind in kinds:
        cells = [row["by_category"].get(kind, {}).get("accuracy") for row in comparison.values()]
        print(f"{kind:<14}" + "".join(f"{c:>12.3f}" if c is not None else f"{'-':>12}" for c in cells))


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--conversations", default="0", help="comma-separated indexes, such as 0 or 0,1,2")
    parser.add_argument("--src", default=str(ROOT / "src"), help="memem source to test, for comparing versions")
    parser.add_argument("--migrations", default=str(ROOT / "migrations"))
    parser.add_argument("--label", default="current")
    parser.add_argument("--merge", action="store_true", help="combine results files into a comparison")
    args = parser.parse_args()
    if args.merge:
        merge()
        return

    from anthropic import AsyncAnthropic

    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / "locomo10.json"
    if not path.exists():
        urllib.request.urlretrieve(DATA_URL, path)
    samples = json.loads(path.read_text())
    entry, store_module = load_memem(Path(args.src))
    vectors, client, usage = LocalVectors(), AsyncAnthropic(max_retries=6), Usage()

    results, start = [], time.time()
    for index in (int(i) for i in args.conversations.split(",")):
        print(f"Conversation {index} ({samples[index]['sample_id']})", flush=True)
        answered, saved, total, calls = await run_conversation(
            samples[index], entry, store_module, vectors, client, usage, Path(args.migrations)
        )
        results.append({"conversation": index, "memories": total, "saved": saved, "tool_calls": calls, "answers": answered})

    answers = [a for r in results for a in r["answers"]]
    by_category = defaultdict(list)
    for a in answers:
        by_category[a["category"]].append(a["correct"])
    summary = {
        "label": args.label,
        "model": MODEL,
        "conversations": args.conversations,
        "questions": len(answers),
        "accuracy": sum(a["correct"] for a in answers) / len(answers),
        "by_category": {c: {"n": len(v), "accuracy": sum(v) / len(v)} for c, v in sorted(by_category.items())},
        "memories_saved": sum(r["memories"] for r in results),
        "tool_calls": [r["tool_calls"] for r in results],
        "tokens": {phase: dict(t) for phase, t in usage.tokens.items()},
        "cost_dollars": {phase: round(usage.cost(phase), 4) for phase in usage.tokens} | {"total": round(usage.cost(), 4)},
        "minutes": round((time.time() - start) / 60, 1),
    }
    out = CACHE / f"results-{args.label}-{args.conversations.replace(',', '_')}.json"
    out.write_text(json.dumps({"summary": summary, "results": results}, indent=2, default=str))
    print(json.dumps(summary, indent=2))
    print(f"Details in {out}")


if __name__ == "__main__":
    asyncio.run(main())
