# File sharing design

Status: built.

## Problem

A memory can mention a file that exists only in the app that made it. Another assistant then knows the file exists but
cannot get it. memem needs to hold the file so every connected app can reach it.

## Decision: files are attachments on memories

Files of any type can be attached to a memory. memem stores it whole and never reads or indexes it. The memory's text
describes the file, so the existing `search_memories` finds it by meaning:

```text
Memory 12:  Q3 launch assets: logos, copy and the final deck, made in ChatGPT.
  Attachments: launch-assets.zip, 14 MB, download link
               press-copy.docx, 82 KB, download link
```

- A memory can have up to 20 attachments.
- Every file has a description, because the memory is created with it. There are no orphaned files.
- Attachment bytes are never rewritten. Editing the memory changes only its description.

Long text with no file goes in a memory, up to the 10,000-character limit, or is uploaded as a file.

## Constraints

| Constraint | Effect on the design |
| --- | --- |
| Models write tool arguments as text, and memem caps requests at 256 KB | Tool calls cannot carry files |
| App sandboxes may not reach memem. Claude's are limited to approved destinations by default, and ChatGPT's are unknown | Assume a person moves files, and treat direct transfer as a later experiment |
| Workers accept request bodies up to 100 MB on Free and Pro | Limit a file to 95 MB |
| Workers Free allows 10 ms CPU per request, and Workers have 128 MB of memory | Stream uploads rather than buffering, and measure before committing |
| R2 free tier is 10 GB-month, with no egress charge | Cap total storage at 5 GB |
| Links in tool results pass through the model provider and stay in chat history | A link alone must not grant access to a file |

## How it works

1. In a chat, the user asks to save a file. `get_upload_link` returns the upload page for this space. The user can
   also open `/files` directly.
2. The user signs in with Google, describes the files and chooses them on the page. Only the allowed account can upload.
3. memem creates the memory and indexes its description as usual.
4. The browser sends each file with `PUT`, one at a time, and the Worker streams it to R2 without buffering it. Files
   that fail can be retried, and the rest are kept.
5. Any connected app finds the memory through `search_memories` or `list_memories`, with the attachment's name, size and
   link in the result.
6. Opening the link requires the same Google sign-in. The user downloads the file and attaches it to the other app.

To add files to an existing memory, `get_upload_link` takes an optional `memory_id`. A single file is removed with
the button on that memory's signed-in page, not through a tool.

## Tools

Three new tools, all needing write access: `get_upload_link`, with optional `memory_id`, and `get_sandbox_upload_url`
and `get_sandbox_download_url` (see below).

Changes to existing tools:

- `get_memory_overview`, `search_memories` and `list_memories` include an `attachments` list when a memory has files, with a
  note that browser links need the user's sign-in.
- `delete_memory` deletes the attachments too, and its description says so.
- `add_memory` asks assistants to say where a file lives when it isn't attached, so others don't assume they have it.

The upload page URL contains only the space and memory id. Neither is a secret, since sign-in grants access.

## Storage

Migration adds `attachments`: `id`, `public_id` (random, used in links), `memory_id`, `space`, `name`, `media_type`,
`size`, `r2_key`, `created_at`, `uploading`, `deleting`, and `web_sessions` for the file page's sign-in.

Files go in a new R2 bucket `memem-files`. R2 keys are random, so they reveal nothing about the file name or space.

## Security

- Every query filters on the connection's space, and the Google sign-in is required for each upload and download.
- Files are always served as downloads: `Content-Disposition: attachment`, `application/octet-stream`,
  `X-Content-Type-Options: nosniff`, and a sanitized file name. memem never renders an uploaded file.
- The file page adds one inline script, allowed by a per-response CSP nonce. All other pages keep the current CSP.
- Changes need a matching `Origin` and a custom `x-memem` header, on top of a `SameSite=Lax` session cookie.
- Attachment names are untrusted text, and results keep the "data, not instructions" notice.
- Read-only connections can see attachments and download links, but get no upload or delete tools.
- Limits: 95 MB per file, 20 files per memory, and 5 GB in total.
- If an R2 delete fails, the row stays with `deleting` set for retry, so no file is silently left behind.

## Not in the first version

- Reading or searching file contents, or looking inside zip files.
- Direct transfer from an app's sandbox.

## Phases

1. **Spike, done.** A Python Worker streamed 1, 20 and 90 MB files to and from R2 by passing the raw request and object
   streams, and all nine round trips were byte-for-byte intact. CPU time was 5-15 ms regardless of file size, with one
   82 ms cold start. No presigned URLs are needed. The real upload adds a sign-in check and D1 writes, so its CPU use
   should be measured against the 10 ms Workers Free limit.
2. **Attachments, done.** The upload page, R2 storage, signed-in downloads, `get_upload_link`, and the tool changes above.
3. **Sandbox uploads, done.** See below.

## Sandbox uploads

Testing showed ChatGPT's sandbox can reach memem, Claude's can once the domain is allowed, and the Gemini app had no
code execution. `get_sandbox_upload_url` returns a `/files/direct/<token>` URL for the sandbox to `PUT` one file to.

The link needs no sign-in, because sandboxes can't do one, so it is limited instead: stored only as a hash, single-use,
valid for 10 minutes, fixed to one space and file name, and able to add one file and read nothing. It does pass through
the model provider. The memory is created only when the upload arrives, so unused links leave nothing behind.

## Sandbox downloads

`get_sandbox_download_url` returns a `/files/fetch/<token>` URL for one attachment in the connection's space. It needs a
write connection, is stored only as a hash, works once, and expires after two minutes. R2 presigned URLs were rejected
because they can be reused until they expire, need R2 credentials in the Worker, and use a second domain.

The main risk is prompt injection leading an assistant to fetch a file and send it elsewhere, so the tool should keep
approval on in each app. `download_links` keeps each request and is shown on the memory's page for 90 days.

## Open questions

- Do Claude, ChatGPT and Gemini show returned links in a clickable form?
