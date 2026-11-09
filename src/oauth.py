"""OAuth 2.1 authorization server for a single owner.

Clients register themselves, and the owner approves each one by signing in with the one
allowed Google account. Redirects are limited to known assistants.
"""

import base64
import hashlib
import hmac
import html
import json
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from workers import Response, fetch

ACCESS_TTL = 3600
REFRESH_TTL = 90 * 24 * 3600
CODE_TTL = 300
LOGIN_TTL = 900
SESSION_COOKIE = "memem_session"
WEB_COOKIE = "memem_web"
WEB_SESSION_TTL = 12 * 3600
# Registered clients are always named client_..., so this cannot be claimed through registration.
WEB_CLIENT = "web"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
MAX_FORM_BYTES = 16 * 1024
MAX_REDIRECT_URIS = 10
_SPACE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_CHATGPT_CALLBACK = re.compile(r"/connector/oauth/[A-Za-z0-9_-]+")
# googleusercontent.com also serves user uploads, so only Google's OAuth relay hosts are allowed.
_GEMINI_HOST = re.compile(r"oauth-redirect(?:-sandbox|-test)?\.googleusercontent\.com")
_GEMINI_CALLBACK = re.compile(r"/[ar]/user_bound_custom-mcp-[0-9]+-[A-Za-z0-9_]+")

_NO_STORE = {"cache-control": "no-store"}
_PAGE_HEADERS = {
    **_NO_STORE,
    "content-type": "text/html; charset=utf-8",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
}


_HEAD = """<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<meta name=color-scheme content="light dark">
<style>
:root{--bg:#f4f1ea;--card:#fffdf9;--ink:#23211c;--muted:#6f6a5f;--line:#ddd7ca;--accent:#6022fc;--on-accent:#fff;--me:#6022fc;--mem:#3f3f3f;--err:#a3271f;--err-bg:#fbeae7}
@media (prefers-color-scheme:dark){:root{--bg:#191814;--card:#24221d;--ink:#f0ece3;--muted:#a8a294;--line:#3b382f;--me:#a98bff;--mem:#d2cec6;--err:#f2a79f;--err-bg:#3a211e}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:1.5rem;background:var(--bg);color:var(--ink);font:16px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:100%;max-width:27rem;padding:2.25rem;background:var(--card);border:1px solid var(--line);border-radius:16px;box-shadow:0 12px 32px -20px rgb(0 0 0/.35)}
.brand{margin:0 0 1.75rem;font-size:1.35rem;font-weight:700;line-height:1;letter-spacing:-.02em;color:var(--mem)}
.brand span{color:var(--me)}
h1{margin:0 0 .5rem;font-size:1.75rem;line-height:1.2;letter-spacing:-.02em}
.lead{margin:0;color:var(--muted)}.lead strong{color:var(--ink);font-weight:600}
.err{margin:1.25rem 0 0;padding:.65rem .85rem;border-radius:8px;background:var(--err-bg);color:var(--err);font-size:.925rem}
form{margin-top:1.75rem}
label[for=space]{display:block;margin-bottom:.4rem;font-size:.925rem;font-weight:600}
input[type=text]{width:100%;padding:.65rem .75rem;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit}
.hint{margin:.4rem 0 0;color:var(--muted);font-size:.85rem}
.check{display:flex;gap:.65rem;margin-top:1.25rem;padding:.8rem .85rem;border:1px solid var(--line);border-radius:8px;cursor:pointer}
.check input{width:1.05rem;height:1.05rem;margin:.2rem 0 0;accent-color:var(--accent)}
.check b{display:block;font-weight:600;font-size:.95rem}.check small{display:block;color:var(--muted);font-size:.85rem}
button{width:100%;margin-top:1.5rem;padding:.75rem 1rem;border:0;border-radius:8px;background:var(--accent);color:var(--on-accent);font:inherit;font-weight:600;cursor:pointer}
button:hover{filter:brightness(1.08)}
input:focus-visible,button:focus-visible{outline:2px solid var(--me);outline-offset:2px}
</style>
"""


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _json(value: dict, status: int = 200) -> Response:
    return Response(json.dumps(value), status=status, headers={**_NO_STORE, "content-type": "application/json"})


def _error(code: str, status: int = 400) -> Response:
    return _json({"error": code}, status)


def client_kind(uri: str) -> str | None:
    """Name the kind of client a redirect URI belongs to, or None if it is not allowed."""
    try:
        parts = urlsplit(uri)
        parts.port
    except ValueError:
        return None
    if parts.fragment or parts.query or parts.username or parts.password:
        return None
    if parts.scheme == "https" and parts.netloc in ("claude.ai", "claude.com"):
        return "claude" if parts.path == "/api/mcp/auth_callback" else None
    if parts.scheme == "https" and parts.netloc == "chatgpt.com":
        allowed = parts.path == "/connector_platform_oauth_redirect" or _CHATGPT_CALLBACK.fullmatch(parts.path)
        return "chatgpt" if allowed else None
    if parts.scheme == "https" and _GEMINI_HOST.fullmatch(parts.netloc):
        return "gemini" if _GEMINI_CALLBACK.fullmatch(parts.path) else None
    return None


def resource_metadata(origin: str) -> Response:
    return _json(
        {
            "resource": f"{origin}/mcp",
            "authorization_servers": [origin],
            "scopes_supported": ["memory"],
            "bearer_methods_supported": ["header"],
        }
    )


def server_metadata(origin: str) -> Response:
    return _json(
        {
            "issuer": origin,
            "authorization_endpoint": f"{origin}/oauth/authorize",
            "token_endpoint": f"{origin}/oauth/token",
            "registration_endpoint": f"{origin}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["memory", "offline_access"],
            "authorization_response_iss_parameter_supported": True,
        }
    )


async def register(request, store) -> Response:
    raw = await request.text()
    if len(raw.encode()) > MAX_FORM_BYTES:
        return _error("invalid_client_metadata", 413)
    try:
        body = json.loads(raw)
        uris = body["redirect_uris"]
    except (ValueError, KeyError, TypeError):
        return _error("invalid_client_metadata")
    if not isinstance(uris, list) or not 1 <= len(uris) <= MAX_REDIRECT_URIS:
        return _error("invalid_redirect_uri")
    if not all(isinstance(u, str) and client_kind(u) for u in uris):
        return _error("invalid_redirect_uri")
    client_id = f"client_{secrets.token_urlsafe(16)}"
    if not await store.create_client(client_id, uris):
        return _error("temporarily_unavailable", 503)
    return _json(
        {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
        201,
    )


async def _form(request) -> dict[str, str] | None:
    raw = await request.text()
    if len(raw.encode()) > MAX_FORM_BYTES:
        return None
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


async def _validate(params: dict, store, origin: str) -> str | None:
    """Return a problem with an authorization request, or None if it is acceptable."""
    client_id = params.get("client_id", "")
    uris = await store.client_redirects(client_id) if client_id else None
    if uris is None:
        return "Unknown client."
    given = params.get("redirect_uri", "")
    if not client_kind(given) or given not in uris:
        return "This redirect address is not allowed."
    if params.get("response_type", "code") != "code":
        return "Unsupported response type."
    if params.get("code_challenge_method") != "S256" or not _CHALLENGE.fullmatch(params.get("code_challenge", "")):
        return "A PKCE S256 challenge is required."
    if params.get("resource", f"{origin}/mcp") != f"{origin}/mcp":
        return "This request is for a different server."
    return None


def _page(params: dict, session: str, problem: str = "") -> str:
    e = lambda value: html.escape(value, quote=True)
    uri = params["redirect_uri"]
    name = {"claude": "Claude", "chatgpt": "ChatGPT", "gemini": "Gemini"}[client_kind(uri)]
    fields = ("client_id", "redirect_uri", "code_challenge", "code_challenge_method", "resource", "state")
    hidden = "".join(f'<input type=hidden name="{f}" value="{e(params.get(f, ""))}">' for f in fields)
    hidden += f'<input type=hidden name="session" value="{e(session)}">'
    error = f"<p class=err>{e(problem)}</p>" if problem else ""
    return f"""{_HEAD}<title>Connect memem</title>
<main>
<p class=brand><span>me</span>mem</p>
<h1>Connect {name}</h1>
<p class=lead><strong>{name}</strong> is asking for access to one memory space. After you approve, you'll return to <strong>{e(urlsplit(uri).hostname)}</strong>.</p>
{error}
<form method=post>{hidden}
<label for=space>Memory space</label>
<input id=space type=text name=space value="{e(params.get("space", "personal"))}" required pattern="[A-Za-z0-9_\\-]{{1,64}}" autocomplete=off spellcheck=false>
<p class=hint>Apps connected to the same space share memories.</p>
<label class=check><input type=checkbox name=read_only><span><b>Read-only</b><small>{name} can read memories but can't change them.</small></span></label>
<button type=submit>Continue with Google</button></form>
</main>"""


def _html(body: str, status: int = 200, cookie: str | None = None) -> Response:
    headers = dict(_PAGE_HEADERS)
    if cookie:
        headers["set-cookie"] = cookie
    return Response(body, status=status, headers=headers)


def _message(text: str, status: int) -> Response:
    return _html(f"{_HEAD}<title>memem</title><main><p class=brand><span>me</span>mem</p><p class=lead>{html.escape(text)}</p></main>", status)


def _cookie(origin: str, value: str, max_age: int) -> str:
    secure = "; Secure" if origin.startswith("https:") else ""
    return f"{SESSION_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/oauth; Max-Age={max_age}{secure}"


def _session_from(request) -> str:
    for part in (request.headers.get("cookie") or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == SESSION_COOKIE:
            return value
    return ""


def google_config(env, origin: str) -> dict | None:
    def read(name: str) -> str | None:
        value = getattr(env, name, None)
        return value if isinstance(value, str) and value else None

    config = {
        "client_id": read("GOOGLE_CLIENT_ID"),
        "client_secret": read("GOOGLE_CLIENT_SECRET"),
        "owner_email": read("MEMEM_OWNER_EMAIL"),
    }
    if not all(config.values()):
        return None
    config["auth_url"], config["token_url"] = GOOGLE_AUTH_URL, GOOGLE_TOKEN_URL
    # The stand-in Google used by tests can only apply on a loopback address.
    test_base = read("MEMEM_GOOGLE_TEST_BASE")
    if test_base and urlsplit(origin).hostname == "127.0.0.1":
        config["auth_url"], config["token_url"] = f"{test_base}/auth", f"{test_base}/token"
    return config


async def authorize(request, store, origin: str, google: dict | None) -> Response:
    if request.method == "GET":
        params = {k: v[0] for k, v in parse_qs(urlsplit(request.url).query).items()}
    elif request.method == "POST":
        params = await _form(request)
        if params is None:
            return _error("invalid_request", 413)
    else:
        return _error("invalid_request", 405)

    # Nothing is redirected until the client and redirect address are validated.
    problem = await _validate(params, store, origin)
    if problem:
        return _message(problem, 400)
    if request.method == "GET":
        session = secrets.token_urlsafe(32)
        return _html(_page(params, session), cookie=_cookie(origin, session, LOGIN_TTL))

    # The form must carry the value in this browser's cookie, so other sites cannot submit it.
    session = _session_from(request)
    if not session or not hmac.compare_digest(params.get("session", "").encode(), session.encode()):
        return _message("This page expired. Go back to the app and connect again.", 403)
    if google is None:
        return _html(_page(params, session, "Google sign-in has not been set up on this server."), 503)
    space = params.get("space", "")
    if not _SPACE.fullmatch(space):
        return _html(_page(params, session, "Use 1-64 letters, numbers, _ or - for the space."), 400)

    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    await store.create_pending(
        state_hash=hash_secret(state),
        session_hash=hash_secret(session),
        nonce=nonce,
        client_id=params["client_id"],
        redirect_uri=params["redirect_uri"],
        code_challenge=params["code_challenge"],
        client_state=params.get("state", ""),
        resource=f"{origin}/mcp",
        space=space,
        can_write="read_only" not in params,
        expires_at=int(time.time()) + LOGIN_TTL,
    )
    return Response("", status=302, headers={**_NO_STORE, "location": _google_url(google, origin, state, nonce)})


def _google_url(google: dict, origin: str, state: str, nonce: str) -> str:
    query = urlencode(
        {
            "client_id": google["client_id"],
            "redirect_uri": f"{origin}/oauth/google/callback",
            "response_type": "code",
            "scope": "openid email",
            "state": state,
            "nonce": nonce,
            "prompt": "select_account",
        }
    )
    return f"{google['auth_url']}?{query}"


async def begin_web_sign_in(store, origin: str, google: dict | None, target: str) -> Response:
    """Send the owner to Google, returning afterward to a page under /files."""
    if google is None:
        return _message("Google sign-in has not been set up on this server.", 503)
    session, state, nonce = (secrets.token_urlsafe(32) for _ in range(3))
    await store.create_pending(
        state_hash=hash_secret(state),
        session_hash=hash_secret(session),
        nonce=nonce,
        client_id=WEB_CLIENT,
        redirect_uri=target,
        code_challenge="",
        client_state="",
        resource="",
        space="",
        can_write=False,
        expires_at=int(time.time()) + LOGIN_TTL,
    )
    return Response(
        "",
        status=302,
        headers={
            **_NO_STORE,
            "location": _google_url(google, origin, state, nonce),
            "set-cookie": _cookie(origin, session, LOGIN_TTL),
        },
    )


def _web_cookie(origin: str, value: str) -> str:
    secure = "; Secure" if origin.startswith("https:") else ""
    return f"{WEB_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/files; Max-Age={WEB_SESSION_TTL}{secure}"


def _claims_of(id_token: str) -> dict:
    # The token came straight from Google's token endpoint over TLS, so OpenID Connect
    # allows skipping the signature check. Its claims are still verified by the caller.
    payload = id_token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _identity_ok(claims: dict, google: dict, nonce: str) -> bool:
    return (
        claims.get("iss") in ("https://accounts.google.com", "accounts.google.com")
        and claims.get("aud") == google["client_id"]
        and isinstance(claims.get("exp"), int)
        and claims["exp"] > time.time()
        and hmac.compare_digest(str(claims.get("nonce", "")).encode(), nonce.encode())
        and claims.get("email_verified") is True
        and str(claims.get("email", "")).casefold() == google["owner_email"].casefold()
    )


async def google_callback(request, store, origin: str, google: dict | None) -> Response:
    if google is None:
        return _message("Google sign-in has not been set up on this server.", 503)
    params = {k: v[0] for k, v in parse_qs(urlsplit(request.url).query).items()}
    # Claiming deletes the pending login, so a callback works only once.
    pending = await store.claim_pending(hash_secret(params.get("state", "")))
    expired = "This sign-in expired. Go back to the app and connect again."
    if pending is None:
        return _message(expired, 400)
    session = _session_from(request)
    if not session or not hmac.compare_digest(hash_secret(session).encode(), pending["session_hash"].encode()):
        return _message(expired, 403)
    if "code" not in params:
        return _message("Google sign-in was cancelled. Go back to the app to try again.", 400)

    reply = await fetch(
        google["token_url"],
        method="POST",
        headers={"content-type": "application/x-www-form-urlencoded"},
        body=urlencode(
            {
                "grant_type": "authorization_code",
                "code": params["code"],
                "client_id": google["client_id"],
                "client_secret": google["client_secret"],
                "redirect_uri": f"{origin}/oauth/google/callback",
            }
        ),
    )
    if reply.status != 200:
        return _message("Google could not confirm this sign-in. Please try again.", 502)
    try:
        claims = _claims_of(json.loads(await reply.text())["id_token"])
    except (ValueError, KeyError, IndexError, AttributeError):
        return _message("Google could not confirm this sign-in. Please try again.", 502)
    if not _identity_ok(claims, google, pending["nonce"]):
        return _message("This Google account is not allowed to use this memem server.", 403)

    if pending["client_id"] == WEB_CLIENT:
        token = secrets.token_urlsafe(32)
        await store.create_web_session(hash_secret(token), int(time.time()) + WEB_SESSION_TTL)
        return Response(
            "",
            status=302,
            headers={**_NO_STORE, "location": pending["redirect_uri"], "set-cookie": _web_cookie(origin, token)},
        )

    code = secrets.token_urlsafe(32)
    uri = pending["redirect_uri"]
    await store.create_code(
        code_hash=hash_secret(code),
        client_id=pending["client_id"],
        redirect_uri=uri,
        code_challenge=pending["code_challenge"],
        resource=pending["resource"],
        label=f"{client_kind(uri)}-{secrets.token_hex(3)}",
        space=pending["space"],
        can_write=bool(pending["can_write"]),
        expires_at=int(time.time()) + CODE_TTL,
    )
    query = {"code": code, "iss": origin}
    if pending["client_state"]:
        query["state"] = pending["client_state"]
    return Response(
        "",
        status=302,
        headers={**_NO_STORE, "location": f"{uri}?{urlencode(query)}", "set-cookie": _cookie(origin, "", 0)},
    )


def _pkce_ok(verifier: str, challenge: str) -> bool:
    if not _VERIFIER.fullmatch(verifier):
        return False
    digest = hashlib.sha256(verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return hmac.compare_digest(computed, challenge)


def _new_tokens() -> dict:
    now = int(time.time())
    return {
        "access": f"memem_{secrets.token_urlsafe(32)}",
        "refresh": f"memem_r_{secrets.token_urlsafe(32)}",
        "access_expires_at": now + ACCESS_TTL,
        "refresh_expires_at": now + REFRESH_TTL,
    }


def _token_response(tokens: dict) -> Response:
    return _json(
        {
            "access_token": tokens["access"],
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": tokens["refresh"],
            "scope": "memory",
        }
    )


async def token(request, store, origin: str) -> Response:
    if request.method != "POST":
        return _error("invalid_request", 405)
    form = await _form(request)
    if form is None:
        return _error("invalid_request", 413)

    grant = form.get("grant_type")
    if grant == "authorization_code":
        # Claiming deletes the code, so it can be tried only once.
        row = await store.claim_code(hash_secret(form.get("code", "")))
        valid = (
            row is not None
            and row["client_id"] == form.get("client_id")
            and row["redirect_uri"] == form.get("redirect_uri")
            and form.get("resource", row["resource"]) == row["resource"]
            and _pkce_ok(form.get("code_verifier", ""), row["code_challenge"])
        )
        if not valid:
            return _error("invalid_grant")
        tokens = _new_tokens()
        await store.create_grant(row, tokens)
        return _token_response(tokens)

    if grant == "refresh_token":
        if form.get("resource", f"{origin}/mcp") != f"{origin}/mcp":
            return _error("invalid_grant")
        tokens = _new_tokens()
        if not await store.rotate_grant(hash_secret(form.get("refresh_token", "")), form.get("client_id", ""), tokens):
            return _error("invalid_grant")
        return _token_response(tokens)

    return _error("unsupported_grant_type")
