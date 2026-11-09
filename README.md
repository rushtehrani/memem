# memem

One small memory server you can attach to individual Claude, ChatGPT and Gemini CLI chats.
It speaks MCP and exposes five tools: `overview`, `recall`, `remember`, `update` and `forget`.

It runs as a Cloudflare Worker in Python, with a D1 database. Needs [uv](https://docs.astral.sh/uv/),
Node (for `npx wrangler`) and a Cloudflare account. The Workers free plan is enough to start.

## Deploy

```bash
uv sync
npx wrangler login
npx wrangler d1 create memem
```

Paste the printed `database_id` into `wrangler.jsonc`, then:

```bash
npx wrangler d1 migrations apply memem --remote
npx wrangler vectorize create memem --dimensions=768 --metric=cosine
uv run pywrangler deploy
```

The deploy prints your Worker's address. Use it wherever this README shows `memem.YOUR-SUBDOMAIN.workers.dev`.

Then set up sign-in. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials), create an
**OAuth client ID** of type **Web application**, with this authorized redirect URI:

```text
https://memem.YOUR-SUBDOMAIN.workers.dev/oauth/google/callback
```

The consent screen only needs your own email as a test user, or publish it, since memem requests just `openid email`.
Then store the details on the Worker:

```bash
uv run memem set-google
```

## Add it to an assistant

The address is the same for every app: `https://memem.YOUR-SUBDOMAIN.workers.dev/mcp`. There's no token to copy.
The app opens an approval page, where you pick a memory space, optionally choose read-only, and sign in with Google.

| Client | How to add | How to limit it |
| --- | --- | --- |
| Claude (web, desktop) | Settings > Connectors > Add custom connector, paste the address and leave the OAuth fields empty | Turn it on per chat from the **+** menu |
| ChatGPT | Enable Developer Mode in settings, then add a connector with the address and **OAuth** | Turn it on in each chat where you want it |
| Claude Code | `claude mcp add --transport http memem https://memem.YOUR-SUBDOMAIN.workers.dev/mcp`, then authenticate from `/mcp` | Applies to the current project only by default |
| Gemini CLI | Use a static token from `uv run memem connect gemini --space personal` with the config below in `.gemini/settings.json` | Applies to that project only |

Plan limits apply and change over time. ChatGPT may limit write tools on some plans, in which case `overview` and `recall`
may be the only tools that work there. The consumer Gemini app is not covered: this was built without
confirming that it can add custom MCP servers, so Gemini CLI is the supported route.

```json
{
  "mcpServers": {
    "memem": {
      "httpUrl": "https://memem.YOUR-SUBDOMAIN.workers.dev/mcp",
      "headers": { "Authorization": "Bearer $MEMEM_TOKEN" }
    }
  }
}
```

## Choosing what each chat can see

- A chat without the connector turned on has no access at all.
- A connection reaches exactly one space, chosen on the approval page. Reconnect to change it.
- Read-only connections get `overview` and `recall` only.

```bash
uv run memem list
uv run memem revoke claude-ab12cd
```

Revoking takes effect on the next request.

## Security

- Apps sign in with OAuth 2.1 and PKCE. Access tokens last an hour, and refresh tokens rotate on each use.
- New connections need a sign-in with the one allowed Google account, and redirects are limited to Claude, ChatGPT and local apps.
- All tokens are 256-bit random values, stored only as SHA-256 hashes, and travel only in the `Authorization` header.
- The space and write permission come from the token. Tools cannot choose another space.
- `memem connect` makes a static token for CLIs on your machine. Only its hash is sent to D1.
- Memories are stored in Cloudflare D1, so Cloudflare hosts their contents. Check its current encryption
  documentation if that matters for what you store.
- The Worker does not log URLs and `wrangler.jsonc` keeps Workers Logs off. Turning them on, or running
  `wrangler tail`, can expose OAuth codes passing through URLs.
- Each memory records which connection wrote it, set by the server.

Known limits of this first version:

- **Your Google account is the master credential.** Anyone who can sign in as it can approve a connection, so keep
  2-step verification on. memem has a single owner and no per-user accounts.
- **Memories can carry prompt injection.** Text saved from one chat is read by another. `recall` labels results
  as data, but that only lowers the risk. Use `--read-only` for chats that process untrusted content.
- **The model provider sees what it recalls.** Don't store secrets, and keep sensitive spaces away from
  providers you don't want reading them.

- **Search works best in English.** `recall` combines keywords with meaning search from Workers AI and Vectorize.
  New memories can take a little while to become searchable by meaning, but keywords find them right away. If
  saving a vector fails, that memory is only findable by keyword.

## Roadmap

memem is designed as layers, informed by Anthropic's
[components of agent memory](https://www.anthropic.com/research/components-of-agent-memory). Sources are the raw record,
and each layer above is derived from the ones below, so consolidation can rewrite anything except Sources.

```text
Pinned overview   small, read at the start of a chat
Wiki pages        linked summaries across many memories (later)
Memories          notes that can be searched, browsed and revised
Sources           chats and files: raw, never rewritten
```

### Pinned overview

- [x] `overview` tool that returns pinned notes and a memory count
- [x] Pin and unpin memories, with a size budget for each space
- [x] Tool descriptions ask assistants to read memory first

### Memories

- [x] `recall`, `remember`, `update` and `forget` tools over MCP
- [x] Search by meaning and keyword, combined
- [x] Fall back to keyword search if meaning search fails
- [x] Revise outdated memories in place, recording which connection changed them
- [x] Browse a whole space, page by page
- [x] Tool descriptions state the purpose of memory rather than strict rules
- [ ] Link memories to the Sources they came from
- [ ] Repair command to index memories whose vectors failed to save
- [ ] Tune the relevance cutoff on real memories (0.52 was set from a small sample)
- [ ] Better meaning search for languages other than English

### Sources: chat history

- [x] Vector ids leave room for other kinds of content
- [ ] Save an entire chat when asked
- [ ] Search and read saved chats from other assistants
- [ ] Full-text keyword search, since `LIKE` won't scale to whole transcripts

### Sources: files

- [ ] Shared text files
- [ ] Shared binary files, stored in R2
- [ ] Confirm files can be saved and fetched from Claude web and ChatGPT

### Consolidation

- [ ] Guided tidy-up, where an assistant reviews a space and corrects or merges memories
- [ ] Scheduled consolidation that checks memories against Sources, with protection against injected instructions

### Wiki pages

- [ ] Linked summary pages, if questions spanning many documents become common

### Access and security

- [x] Separate memory spaces, one per connection
- [x] Read-only connections
- [x] Immediate revocation
- [x] OAuth 2.1 sign-in, with no token to copy
- [x] Google sign-in limited to one account
- [x] Static tokens for CLIs

### Clients and project

- [x] Deployed on Cloudflare Workers with D1, Workers AI and Vectorize
- [x] Connected and saved memories from Claude web
- [x] Connected and saved memories from ChatGPT
- [x] End-to-end test suite
- [ ] Try the documented Claude Code and Gemini CLI setups on the live service
- [ ] Find out whether the consumer Gemini app can add custom MCP servers
- [ ] Run tests in CI
- [ ] Let forks deploy without editing the database id in `wrangler.jsonc`

## Contributing

See [AGENTS.md](AGENTS.md) for project layout, commands and the rules that keep memem secure. It's written for coding
agents and applies equally to people.

## Development

`uv run pytest` starts the Worker on a temporary local D1 database. To run it yourself:

```bash
npx wrangler d1 migrations apply memem --local
uv run pywrangler dev
uv run memem --local connect dev --space test
```

The local dev server records full request URLs in `.wrangler/`, so only use throwaway tokens there. Tests use a stand-in Google server, which only applies on loopback addresses.
