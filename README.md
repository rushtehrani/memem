# memem

One small memory server you can attach to Claude, ChatGPT and Gemini.
It speaks MCP and exposes nine tools: `memory_overview`, `memory_search`, `memory_list`, `memory_add`, `memory_update`, `memory_delete`,
`memory_upload_link`, `memory_sandbox_upload` and `memory_sandbox_download`.

It runs as a Cloudflare Worker in Python, with a D1 database and R2 for attached files. Needs [uv](https://docs.astral.sh/uv/),
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
npx wrangler r2 bucket create memem-files
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
| Gemini (web) | Settings > Connected Apps > Custom apps > Add a custom app, then paste the address | Google's help page describes no per-chat switch, so consider a read-only connection or its own space. Type `@` to direct a prompt to it |

Plan limits apply and change over time. ChatGPT may limit write tools on some plans, in which case only the read tools
(`memory_overview`, `memory_search` and `memory_list`) may work that work there. Google limits custom apps in the Gemini app to personal accounts in
the US with Keep Activity on. Other developers have reported Gemini's sign-in failing on Google's side.

## Saving files

Files are attached to memories, so assistants can find them through memory search. There are two ways to move a file:

- **Automatic, from the app's code sandbox.** Ask the assistant to save a file, or to fetch one. It gets a single-use
  link for that one file. Upload links expire in 10 minutes, and download links in 2 minutes.
- **Manual.** Ask for an upload link or a file's link, or open `/files` on your Worker, and sign in.

Keep approval on for `memory_sandbox_download`, because text hidden in a memory or document could try to get an
assistant to fetch a file and send it elsewhere. Each memory's page on `/files` shows which connection requested each file.

| App | Automatic transfer |
| --- | --- |
| ChatGPT | Upload and download worked in testing with no setup |
| Claude | Add `memem.YOUR-SUBDOMAIN.workers.dev` to the allowed domains in Claude's capabilities settings. Without it, the sandbox gets a 403. Download worked in testing, and upload is not yet confirmed |
| Gemini | Not available, since the app had no code execution when tested. Use the manual upload |

Allowing the domain lets Claude's sandbox send data to your Worker. Availability depends on your plan and each app's
settings.

## Choosing what each chat can see

- A chat without the connector turned on has no access at all.
- A connection reaches exactly one space, chosen on the approval page. Reconnect to change it.
- Read-only connections get `memory_overview`, `memory_search` and `memory_list` only.

```bash
uv run memem list
uv run memem revoke claude-ab12cd
```

Revoking takes effect on the next request.

## Security

- Apps sign in with OAuth 2.1 and PKCE. Access tokens last an hour, and refresh tokens rotate on each use.
- New connections need a sign-in with the one allowed Google account, and redirects are limited to Claude, ChatGPT and Gemini.
- All tokens are 256-bit random values, stored only as SHA-256 hashes, and travel only in the `Authorization` header.
- The space and write permission come from the token. Tools cannot choose another space.
- Attached files are only ever served as downloads. Moving one needs the Google sign-in or a single-use link requested
  by a write connection. Upload links can't read anything, and download links fetch one file once within 2 minutes.
- `memem connect` makes a static token for development and testing. Only its hash is sent to D1.
- Memories are stored in Cloudflare D1, so Cloudflare hosts their contents. Check its current encryption
  documentation if that matters for what you store.
- The Worker does not log URLs and `wrangler.jsonc` keeps Workers Logs off. Turning them on, or running
  `wrangler tail`, can expose OAuth codes passing through URLs.
- Each memory records which connection wrote it, set by the server.

Known limits of this first version:

- **Your Google account is the master credential.** Anyone who can sign in as it can approve a connection, so keep
  2-step verification on. memem has a single owner and no per-user accounts.
- **Memories can carry prompt injection.** Text saved from one chat is read by another. Search results are labeled
  as data, but that only lowers the risk. Use `--read-only` for chats that process untrusted content.
- **The model provider sees what it recalls.** Don't store secrets, and keep sensitive spaces away from
  providers you don't want reading them.

- **Search works best in English.** `memory_search` combines keywords with meaning search from Workers AI and Vectorize.
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

- [x] `memory_overview` tool that returns pinned notes and a memory count
- [x] Pin and unpin memories, with a size budget for each space
- [x] Tool descriptions ask assistants to read memory first

### Memories

- [x] `memory_search`, `memory_list`, `memory_add`, `memory_update` and `memory_delete` tools over MCP
- [x] Search by meaning and keyword, combined
- [x] Fall back to keyword search if meaning search fails
- [x] Revise outdated memories in place, recording which connection changed them
- [x] Browse a whole space, page by page
- [x] Tool descriptions state the purpose of memory rather than strict rules
- [ ] Keep edit history, so changes can be undone
- [ ] Track deletions, so forgotten facts can't be recreated
- [ ] Refuse edits that would overwrite a newer change
- [ ] Link memories to the Sources they came from
- [ ] Repair command to index memories whose vectors failed to save
- [ ] Tune the relevance cutoff
- [ ] Better meaning search for languages other than English

### Sources: chat history

- [x] Vector ids leave room for other kinds of content
- [ ] Save an entire chat when asked, through `context_` tools
- [ ] Search and read saved chats from other assistants
- [ ] Full-text keyword search, since `LIKE` won't scale to whole transcripts

### Files

Files are attachments on memories. See [the design](docs/file-sharing-design.md).

- [x] Attach several files of any type to a memory, stored in R2
- [x] Signed-in upload and download page
- [x] Automatic upload from a code sandbox with single-use links
- [x] Automatic download into a code sandbox with single-use links
- [ ] Search file names and contents

### Consolidation

- [ ] Guided tidy-up, where an assistant reviews a space and corrects or merges memories
- [ ] Scheduled consolidation that checks memories against Sources, with protection against injected instructions

### Guides and skills

- [ ] `memory_guide` tool for multi-step workflows, such as tidying a space
- [ ] Optional `SKILL.md` that people can install in each app

### Wiki pages

- [ ] Linked summary pages, if questions spanning many documents become common

### Access and security

- [x] Separate memory spaces, one per connection
- [x] Read-only connections
- [x] Immediate revocation
- [x] OAuth 2.1 sign-in, with no token to copy
- [x] Google sign-in limited to one account

### Clients and project

- [x] Runs on Cloudflare Workers with D1, R2, Workers AI and Vectorize
- [x] Support for Claude, ChatGPT and Gemini web apps
- [ ] Support for Claude Code, Gemini CLI and other coding agents
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
