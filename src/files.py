"""The owner's signed-in page for attaching files to memories, stored whole in R2."""

import html
import json
import re
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote, urlencode, urlsplit

import js
from pyodide.ffi import to_js
from workers import Response

import oauth
from store import AttachmentRefused, SpaceFull

MAX_FILE_BYTES = 95 * 1024 * 1024
MAX_DESCRIPTION_CHARS = 10_000
MAX_JSON_BYTES = 64 * 1024
MAX_ID = 2**31 - 1
_SPACE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_MEDIA_TYPE = re.compile(r"[A-Za-z0-9.+_-]{1,64}/[A-Za-z0-9.+_-]{1,64}")
_PUBLIC_ID = re.compile(r"[A-Za-z0-9_-]{20,64}")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{32,64}")
_NO_STORE = {"cache-control": "no-store"}
DIRECT_UPLOAD_TTL = 600
DIRECT_DOWNLOAD_TTL = 120

_STYLE = """<style>
main{max-width:32rem}
textarea{display:block;width:100%;min-height:5.5rem;padding:.65rem .75rem;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit;resize:vertical}
label{display:block;margin:1.25rem 0 .4rem;font-size:.925rem;font-weight:600}
input[type=file]{display:block;width:100%;padding:.65rem;border:1px dashed var(--line);border-radius:8px;font:inherit;color:var(--muted)}
.description{margin:1.25rem 0 0;white-space:pre-wrap}
ul{list-style:none;margin:1.25rem 0 0;padding:0}
li{display:flex;align-items:center;gap:.75rem;padding:.6rem 0;border-top:1px solid var(--line);font-size:.925rem}
li span{flex:1;min-width:0;overflow-wrap:anywhere}
li a{flex:1;min-width:0;overflow-wrap:anywhere;color:var(--me)}
li small{color:var(--muted);white-space:nowrap}
button.remove{width:auto;margin:0;padding:.25rem .6rem;background:transparent;color:var(--err);border:1px solid var(--line);font-size:.85rem;font-weight:500}
#status{margin:1rem 0 0;font-size:.9rem;color:var(--muted);overflow-wrap:anywhere}
</style>
"""

_SCRIPT = """
const form = document.getElementById("upload");
const statusLine = document.getElementById("status");
const headers = { "x-memem": "1" };
let memoryId = form.dataset.memory;
let remaining = null;

function say(text) { statusLine.textContent = text; }

async function createMemory() {
  const reply = await fetch("/files/memories", {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ space: form.space.value, description: form.description.value }),
  });
  const body = await reply.json();
  if (!reply.ok) throw new Error(body.error);
  memoryId = String(body.id);
}

async function upload(file) {
  const query = new URLSearchParams({ memory_id: memoryId, name: file.name });
  const reply = await fetch("/files/upload?" + query, {
    method: "PUT",
    headers: { ...headers, "content-type": file.type || "application/octet-stream" },
    body: file,
  });
  if (!reply.ok) throw new Error((await reply.json()).error);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button[type=submit]");
  const files = remaining || [...form.files.files];
  if (!files.length) { say("Choose at least one file."); return; }
  button.disabled = true;
  try {
    if (!memoryId) await createMemory();
  } catch (error) {
    say(error.message || "Could not save the description.");
    button.disabled = false;
    return;
  }
  const failed = [];
  let problem = "";
  for (const [index, file] of files.entries()) {
    say(`Uploading ${index + 1} of ${files.length}: ${file.name}`);
    try { await upload(file); } catch (error) { failed.push(file); problem = `${file.name}: ${error.message}`; }
  }
  if (!failed.length) { location.href = "/files?" + new URLSearchParams({ memory_id: memoryId }); return; }
  remaining = failed;
  button.disabled = false;
  button.textContent = `Retry ${failed.length} failed`;
  say(problem);
});

for (const button of document.querySelectorAll("button.remove")) {
  button.addEventListener("click", async () => {
    const reply = await fetch("/files/attachments/" + button.dataset.id, { method: "DELETE", headers });
    if (reply.ok) location.reload(); else say("Could not remove that file.");
  });
}
"""


def _json(value: dict, status: int = 200) -> Response:
    return Response(json.dumps(value), status=status, headers={**_NO_STORE, "content-type": "application/json"})


def _size(bytes_: int) -> str:
    if bytes_ < 1024**2:
        return f"{max(bytes_ / 1024, 0.1):.1f} KB"
    return f"{bytes_ / 1024**2:.1f} MB"


def _when(timestamp: int) -> str:
    return datetime.fromtimestamp(timestamp, UTC).strftime("%b %d %H:%M UTC")


def _page(title: str, body: str) -> Response:
    nonce = secrets.token_urlsafe(16)
    csp = f"default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    page = f"""{oauth._HEAD}{_STYLE}<title>{title}</title>
<main><p class=brand><span>me</span>mem</p>
{body}
</main><script nonce="{nonce}">{_SCRIPT}</script>"""
    return Response(page, headers={**oauth._PAGE_HEADERS, "content-security-policy": csp})


def _params(request) -> dict:
    return {k: v[0] for k, v in parse_qs(urlsplit(request.url).query).items()}


def _int_param(value) -> int | None:
    return int(value) if isinstance(value, str) and value.isascii() and value.isdigit() and 1 <= int(value) <= MAX_ID else None


async def _upload_page(request, store) -> Response:
    e = lambda value: html.escape(str(value), quote=True)
    params = _params(request)
    if "memory_id" not in params:
        space = params.get("space", "personal")
        if not _SPACE.fullmatch(space):
            space = "personal"
        return _page(
            "Attach files",
            f"""<h1>Attach files</h1>
<p class=lead>Files are stored whole. Assistants find them through this description, so say what's in them.</p>
<form id=upload data-memory="">
<label for=description>Description</label>
<textarea id=description name=description required maxlength={MAX_DESCRIPTION_CHARS}></textarea>
<label for=space>Memory space</label>
<input id=space type=text name=space value="{e(space)}" required pattern="[A-Za-z0-9_\\-]{{1,64}}" autocomplete=off spellcheck=false>
<label for=files>Files</label>
<input id=files type=file name=files multiple required>
<p class=hint>Up to 20 files, {MAX_FILE_BYTES // 1024**2} MB each.</p>
<button type=submit>Upload</button></form>
<p id=status role=status></p>""",
        )

    memory_id = _int_param(params["memory_id"])
    found = await store.memory_with_attachments(memory_id) if memory_id else None
    if found is None:
        return oauth._message("That memory doesn't exist.", 404)
    memory, attachments = found
    activity = "".join(
        f"<li><span>{e(a['name'])}</span><small>{e(a['source'])}, {_when(a['requested_at'])}, "
        f"{'fetched' if a['fetched_at'] else 'not fetched'}</small></li>"
        for a in await store.download_activity(memory_id)
    )
    activity = f"<label>Sandbox downloads</label><ul>{activity}</ul>" if activity else ""
    items = "".join(
        f'<li><a href="/files/download/{e(a["public_id"])}">{e(a["name"])}</a><small>{_size(a["size"])}</small>'
        f'<button type=button class=remove data-id="{e(a["public_id"])}">Remove</button></li>'
        for a in attachments
    )
    return _page(
        "Memory files",
        f"""<h1>Memory files</h1>
<p class="lead description">{e(memory["content"])}</p>
<ul>{items}</ul>
{activity}
<form id=upload data-memory="{memory_id}">
<label for=files>Add files</label>
<input id=files type=file name=files multiple required>
<button type=submit>Upload</button></form>
<p id=status role=status></p>""",
    )


async def _create_memory(request, store) -> Response:
    raw = await request.text()
    if len(raw.encode()) > MAX_JSON_BYTES:
        return _json({"error": "That description is too long."}, 413)
    try:
        body = json.loads(raw)
        space, description = body["space"], body["description"]
    except (ValueError, KeyError, TypeError):
        return _json({"error": "Invalid request."}, 400)
    if not isinstance(space, str) or not _SPACE.fullmatch(space):
        return _json({"error": "Use 1-64 letters, numbers, _ or - for the space."}, 400)
    if not isinstance(description, str) or not description.strip() or len(description) > MAX_DESCRIPTION_CHARS:
        return _json({"error": "Add a description of up to 10,000 characters."}, 400)
    try:
        return _json({"id": await store.remember(space, description, "upload")})
    except SpaceFull as err:
        return _json({"error": str(err)}, 409)


def clean_name(name) -> str | None:
    if not isinstance(name, str) or not 1 <= len(name) <= 255 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        return None
    return name.replace("/", "_").replace("\\", "_")


def _declared_size(request) -> int | Response:
    length = request.headers.get("content-length") or ""
    if not length.isascii() or not length.isdigit():
        return _json({"error": "The upload needs a known size."}, 411)
    size = int(length)
    if size > MAX_FILE_BYTES:
        return _json({"error": f"Files can be up to {MAX_FILE_BYTES // 1024**2} MB."}, 413)
    if size == 0:
        return _json({"error": "That file is empty."}, 400)
    return size


async def _upload(request, store) -> Response:
    params = _params(request)
    memory_id, name = _int_param(params.get("memory_id")), clean_name(params.get("name"))
    if memory_id is None or name is None:
        return _json({"error": "Invalid file name or memory."}, 400)
    size = _declared_size(request)
    if not isinstance(size, int):
        return size
    return await _stream_to_r2(request, store, memory_id, name, size)


async def _stream_to_r2(request, store, memory_id: int, name: str, size: int) -> Response:
    media_type = (request.headers.get("content-type") or "").split(";")[0].strip()
    if not _MEDIA_TYPE.fullmatch(media_type):
        media_type = "application/octet-stream"

    public_id, r2_key = secrets.token_urlsafe(24), secrets.token_urlsafe(32)
    try:
        await store.reserve_attachment(memory_id, public_id, name, media_type, size, r2_key)
    except AttachmentRefused as err:
        return _json({"error": str(err)}, 409)
    except LookupError:
        return _json({"error": "That memory doesn't exist."}, 404)
    try:
        # Passing the stream straight through means the file is never held in memory.
        stored = await store.files.put(r2_key, request.js_object.body)
        if stored is None or stored.size != size:
            raise ValueError("size mismatch")
    except Exception as err:
        print("file upload failed:", type(err).__name__)
        await store.discard_attachment(public_id)
        return _json({"error": "The upload failed. Please try again."}, 502)
    await store.finish_attachment(public_id)
    return _json({"id": public_id, "memory_id": memory_id})


async def direct_upload_url(store, space: str, source: str, name: str, description: str, memory_id: int) -> dict:
    token = secrets.token_urlsafe(32)
    await store.create_upload_token(
        oauth.hash_secret(token), space, memory_id, description, name, source, int(time.time()) + DIRECT_UPLOAD_TTL
    )
    return {
        "upload_url": f"{store.origin}/files/direct/{token}",
        "method": "PUT",
        "expires_in_seconds": DIRECT_UPLOAD_TTL,
        "max_bytes": MAX_FILE_BYTES,
        "instructions": "From your code sandbox, send the file as the raw request body. The link works once.",
    }


async def _direct_upload(request, store, token: str) -> Response:
    """Sandboxes cannot sign in, so one link can add one file and can read nothing."""
    size = _declared_size(request)
    if not isinstance(size, int):
        return size  # Checked first, so a malformed request doesn't use up the link.
    claim = await store.claim_upload_token(oauth.hash_secret(token)) if _TOKEN.fullmatch(token) else None
    if claim is None:
        return _json({"error": "This upload link is invalid, used or expired."}, 403)
    memory_id, created = claim["memory_id"], False
    if memory_id == 0:
        try:
            memory_id, created = await store.remember(claim["space"], claim["description"], claim["source"]), True
        except SpaceFull as err:
            return _json({"error": str(err)}, 409)
    elif not await store.memory_exists(claim["space"], memory_id):
        return _json({"error": "That memory doesn't exist."}, 404)
    reply = await _stream_to_r2(request, store, memory_id, claim["name"], size)
    if reply.status != 200 and created:
        await store.forget(claim["space"], memory_id, claim["source"], forever=True)
    return reply


def _disposition(name: str) -> str:
    fallback = re.sub(r"[^A-Za-z0-9._ -]", "_", name) or "file"
    return f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quote(name, safe='')}"


async def _download(store, public_id: str):
    attachment = await store.attachment(public_id) if _PUBLIC_ID.fullmatch(public_id) else None
    return await _send_file(store, attachment)


async def _send_file(store, attachment: dict | None):
    stored = await store.files.get(attachment["r2_key"]) if attachment else None
    if stored is None:
        return oauth._message("That file doesn't exist.", 404)
    # Always a download of opaque bytes, so an uploaded file can never run on this site.
    headers = {
        **_NO_STORE,
        "content-type": "application/octet-stream",
        "content-length": str(attachment["size"]),
        "content-disposition": _disposition(attachment["name"]),
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'none'; sandbox",
    }
    options = to_js({"status": 200, "headers": headers}, dict_converter=js.Object.fromEntries)
    return js.Response.new(stored.body, options)


async def direct_download_url(store, space: str, source: str, public_id) -> dict | None:
    if not isinstance(public_id, str) or not _PUBLIC_ID.fullmatch(public_id):
        return None
    if not await store.attachment_in_space(space, public_id):
        return None
    token = secrets.token_urlsafe(32)
    await store.create_download_link(oauth.hash_secret(token), public_id, source, DIRECT_DOWNLOAD_TTL)
    return {
        "download_url": f"{store.origin}/files/fetch/{token}",
        "method": "GET",
        "expires_in_seconds": DIRECT_DOWNLOAD_TTL,
        "instructions": "Fetch this right away from your code sandbox. The link works once.",
    }


async def _direct_download(store, token: str):
    """Sandboxes cannot sign in, so one short-lived link can fetch one file, once."""
    claim = await store.claim_download_link(oauth.hash_secret(token)) if _TOKEN.fullmatch(token) else None
    if claim is None:
        return _json({"error": "This download link is invalid, used or expired."}, 403)
    return await _send_file(store, await store.attachment(claim["public_id"]))


def _same_site(request, origin: str) -> bool:
    return request.headers.get("origin") == origin and request.headers.get("x-memem") == "1"


async def _signed_in(request, store) -> bool:
    for part in (request.headers.get("cookie") or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == oauth.WEB_COOKIE and value:
            return await store.web_session_valid(oauth.hash_secret(value))
    return False


async def handle(request, store, origin: str, google: dict | None, path: str):
    if store.files is None:
        return oauth._message("File storage has not been set up on this server.", 503)
    method = request.method
    if path.startswith("/files/fetch/"):
        if method != "GET":
            return _json({"error": "method not allowed"}, 405)
        return await _direct_download(store, path.removeprefix("/files/fetch/"))
    if path.startswith("/files/direct/"):
        if method != "PUT":
            return _json({"error": "method not allowed"}, 405)
        return await _direct_upload(request, store, path.removeprefix("/files/direct/"))
    if not await _signed_in(request, store):
        if method != "GET":
            return _json({"error": "Sign in again, then retry."}, 401)
        url = urlsplit(request.url)
        target = f"{url.path}?{url.query}" if url.query else url.path
        return await oauth.begin_web_sign_in(store, origin, google, target)

    if method == "GET" and path == "/files":
        return await _upload_page(request, store)
    if method == "GET" and path.startswith("/files/download/"):
        return await _download(store, path.removeprefix("/files/download/"))
    if method in ("POST", "PUT", "DELETE") and not _same_site(request, origin):
        return _json({"error": "This request was not sent from memem."}, 403)
    if method == "POST" and path == "/files/memories":
        return await _create_memory(request, store)
    if method == "PUT" and path == "/files/upload":
        return await _upload(request, store)
    if method == "DELETE" and path.startswith("/files/attachments/"):
        removed = await store.discard_attachment(path.removeprefix("/files/attachments/"))
        return _json({"removed": removed}, 200 if removed else 404)
    return _json({"error": "not found"}, 404)


def upload_url(origin: str, space: str, memory_id: int | None) -> str:
    query = {"space": space} if memory_id is None else {"memory_id": memory_id}
    return f"{origin}/files?{urlencode(query)}"
