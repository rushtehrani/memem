# AGENTS.md

Guidance for coding agents and contributors. Read [README.md](README.md) for what memem does and the roadmap.

memem is a small MCP memory server shared across AI assistants. It runs as a Python Cloudflare Worker with D1,
Workers AI and Vectorize. Keep it small: prefer the simplest change that fully solves the problem.

## Layout

| Path | Purpose |
| --- | --- |
| `src/entry.py` | Worker entry point, routing, MCP protocol and tool definitions |
| `src/oauth.py` | OAuth 2.1 server and Google sign-in |
| `src/store.py` | D1 queries and hybrid recall |
| `src/semantic.py` | Workers AI embeddings, Vectorize, and the test stand-in |
| `src/files.py` | The owner's signed-in page for attaching files, stored in R2 |
| `memem/cli.py` | Local admin CLI (`connect`, `list`, `revoke`, `set-google`), which runs on your machine, not in the Worker |
| `migrations/` | D1 schema, applied in filename order |
| `tests/test_memem.py` | End-to-end tests against a real local Worker |

## Commands

Needs [uv](https://docs.astral.sh/uv/) and Node.

```bash
uv sync
```

```bash
uv run pytest
```

```bash
uv run pytest -k recall
```

Tests start `pywrangler dev --env test` on a temporary local D1 database, and need no Cloudflare account.
Workers AI, Vectorize and Google are replaced by local stand-ins, so a passing run says nothing about those real
services. If you change how they are called, say so in your PR and check against a real deployment.

## Design

memem is layered, as the README roadmap shows: Sources (chats and files), then Memories, then wiki pages, then the
pinned overview. Keep these properties as layers are added:

- Sources are raw and never rewritten. Anything above them is derived and can be corrected.
- The space is the access boundary for every layer.
- Keep the pinned overview small. It is limited by `MAX_PINNED_CHARS`, because every chat reads it.
- Tool descriptions state what memory is for, and only hold firm rules for consent, secrets and untrusted content.
- Tools are named by layer: `memory_*` now, and `context_*` for chats and files. There is no `context_update`, since
  sources are never rewritten.
- Memory vectors use the id prefix `m:`. Give any new kind of searchable content its own prefix.

## Rules that protect users

These are the parts of the design most easily broken by accident. Each change must preserve them.

- **Space isolation.** A connection's space and write permission come only from its token (`Connection`). Tools must
  never accept a space argument, and every memory query must filter on `space`, including lookups by id from Vectorize.
- **Secrets stay out of storage and logs.** Store tokens only as SHA-256 hashes. Never log `request.url`, headers or
  memory contents: OAuth codes pass through URLs. Log only exception type names, as the existing code does.
- **Keep Workers Logs off** in `wrangler.jsonc`, and don't use `wrangler tail` against a live deployment.
- **Tokens travel only in the `Authorization` header**, never in a URL.
- **OAuth stays strict.** Keep PKCE S256, single-use codes, rotating refresh tokens, the redirect allowlist, and the
  single allowed Google account. Add a test for any new way through these checks.
- **Test stand-ins work only on loopback.** `MEMEM_GOOGLE_TEST_BASE` and `MEMEM_SEMANTIC_TEST_BASE` must stay ignored
  unless the request origin is `127.0.0.1`.
- **Recalled memories are untrusted.** Keep the "data, not instructions" notice on memory results. Text saved in one
  chat is read in another.
- **Read-only connections get only the read tools**, both in `tools/list` and when a tool is called.
- **Edits record who made them.** `source` keeps the original author and `updated_by` the latest editor, both set by the
  server, so a memory's history can't be forged through a tool.
- **Attached files are opaque.** Always serve them as downloads, and require the Google session for every upload and
  download. Links alone grant access only as single-use `/files/direct/` uploads, which can add one
  file, and `/files/fetch/` downloads, which fetch one file once within two minutes. Both need a write connection.
- **Never commit secrets**, tokens or local state such as `.wrangler/` and `.dev.vars`.

## Conventions

- **No runtime dependencies in the Worker.** The MCP protocol is hand-written in `src/entry.py` because the official
  SDK is about 20 MB, slow to cold start and expects a long-running process. The SDK is used in tests to prove
  compatibility.
- **The CLI uses only the standard library**, and sends SQL through `wrangler`, so validate any value placed in that SQL.
- **Schema changes go in a new numbered migration.** Never edit one that has been applied.
- **D1 statements that must be atomic stay as one statement**, such as the per-space cap and token rotation.
- **Don't bind `None` or very large integers to D1 from Python.** Leave unset values out of the SQL, and keep ids within
  `MAX_ID`.
- **Meaning search is optional.** A failure in Workers AI or Vectorize must not break saving or keyword search, so call
  it through `Store._guarded`.
- **`MIN_SIMILARITY` is tied to the embedding model.** Changing the model means measuring and setting a new cutoff.
- **Tool descriptions are part of the product**, since they tell assistants how to behave. Change them deliberately.
- **Every behavior change gets a test.** Prefer the existing end-to-end style over mocks.
- **Update the README roadmap** when you finish or add an item.

## Deploying

`wrangler.jsonc` points at the maintainer's D1 database. Forks must replace its `database_id`, set `MEMEM_PUBLIC_URL`
to their Worker's address when using the CLI, then follow the Deploy section of the README. Don't commit a real Worker
address: docs use `memem.YOUR-SUBDOMAIN.workers.dev`.

Agents must not deploy, apply remote migrations, or change Cloudflare secrets or resources without the owner's explicit
approval for that action. Signing in and handling credentials are for the owner to do.

## Pull requests

Work on a branch, run `uv run pytest`, and describe what changed and what you could not test. Call out any change to
authentication, tokens, space isolation or logging, so reviewers can look closely.
