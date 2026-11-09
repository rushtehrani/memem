import asyncio
import base64
import hashlib
import html
import json
import os
import re
import secrets
import signal
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.auth.oauth2 import AuthorizationCodeResult, OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata

GOOGLE_CLIENT_ID = "test-google-id"
GOOGLE_CLIENT_SECRET = "test-google-secret"
OWNER_EMAIL = "owner@example.com"
CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
GEMINI_PATH = "user_bound_custom-mcp-123456-memem_example_workers_dev"
GEMINI_REDIRECT = f"https://oauth-redirect.googleusercontent.com/r/{GEMINI_PATH}"
TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
ACCEPT = {"accept": "application/json, text/event-stream"}
WRANGLER_ENV = {**os.environ, "CI": "1", "WRANGLER_SEND_METRICS": "false"}


def memem(persist, *args):
    return subprocess.run(
        ["uv", "run", "memem", "--local", "--persist-to", str(persist), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )


def d1(persist, sql):
    command = ["npx", "--yes", "wrangler", "d1", "execute", "memem", "--local", "--persist-to", str(persist)]
    subprocess.run([*command, "--command", sql], check=True, capture_output=True, env=WRANGLER_ENV, stdin=subprocess.DEVNULL)


def register(base, redirect=CLAUDE_REDIRECT):
    return httpx.post(f"{base}/oauth/register", json={"redirect_uris": [redirect], "client_name": "test"})


def pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def claims(nonce, **overrides):
    return {
        "iss": "https://accounts.google.com", "aud": GOOGLE_CLIENT_ID, "exp": int(time.time()) + 300,
        "nonce": nonce, "email": OWNER_EMAIL, "email_verified": True, **overrides,
    }


def fake_code(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode()


def open_consent(authorize_url):
    page = httpx.get(authorize_url)
    if page.status_code != 200:
        return page, None, {}
    session = re.search(r"memem_session=([^;]+)", page.headers["set-cookie"]).group(1)
    fields = {k: html.unescape(v) for k, v in re.findall(r'type=hidden name="([^"]+)" value="([^"]*)"', page.text)}
    return page, session, fields


def to_google(base, session, fields, space="work", read_only=False):
    form = {**fields, "space": space, **({"read_only": "on"} if read_only else {})}
    return httpx.post(f"{base}/oauth/authorize", data=form, headers={"cookie": f"memem_session={session}"})


def callback(base, query, session):
    headers = {"cookie": f"memem_session={session}"} if session else {}
    return httpx.get(f"{base}/oauth/google/callback", params=query, headers=headers)


def sign_in(base, authorize_url, space="work", read_only=False, session_override=None, **claim_overrides):
    page, session, fields = open_consent(authorize_url)
    if session is None:
        return page
    response = to_google(base, session, fields, space, read_only)
    assert response.status_code == 302, response.text
    google = {k: v[0] for k, v in parse_qs(urlsplit(response.headers["location"]).query).items()}
    code = fake_code({**claims(google["nonce"]), **claim_overrides})
    return callback(base, {"state": google["state"], "code": code}, session_override or session)


def authorize_url(base, client_id, challenge, redirect=CLAUDE_REDIRECT):
    return f"{base}/oauth/authorize?" + urlencode({
        "client_id": client_id, "redirect_uri": redirect, "response_type": "code", "code_challenge": challenge,
        "code_challenge_method": "S256", "resource": f"{base}/mcp", "state": "xyz",
    })


def approve(base, client_id, challenge, redirect=CLAUDE_REDIRECT, **kwargs):
    return sign_in(base, authorize_url(base, client_id, challenge, redirect), **kwargs)


def code_from(response):
    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def exchange(base, client_id, code, verifier, redirect=CLAUDE_REDIRECT):
    return httpx.post(
        f"{base}/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": redirect,
            "resource": f"{base}/mcp",
        },
    )


def grant(base, space, read_only=False):
    client_id = register(base).json()["client_id"]
    verifier, challenge = pkce()
    code = code_from(approve(base, client_id, challenge, space=space, read_only=read_only))
    tokens = exchange(base, client_id, code, verifier).json()
    return {**tokens, "client_id": client_id}


class FakeGoogle(BaseHTTPRequestHandler):
    """Stands in for Google's token endpoint. The code carries the claims to return."""

    vectors = {}
    related = [{"car", "vehicle", "honda", "civic", "drive"}, {"allergic", "peanuts", "food", "restrictions"}]

    def reply(self, value, status=200):
        self.send_response(status)
        self.end_headers()
        self.wfile.write(json.dumps(value).encode())

    def semantic(self, body):
        if self.path == "/add":
            if "failembed" in body["text"]:
                return self.reply({}, 500)
            type(self).vectors[body["id"]] = (body["space"], body["text"].lower())
        elif self.path == "/remove":
            type(self).vectors.pop(body["id"], None)
        else:
            query = set(body["text"].lower().split())
            if "failsearch" in query:
                return self.reply({}, 500)
            matches = []
            for memory_id, (space, text) in type(self).vectors.items():
                if "leakcheck" in query:
                    matches.append({"id": memory_id, "score": 0.9})
                elif space == body["space"]:
                    words = set(text.replace(".", "").split())
                    near = any(query & group and words & group for group in self.related)
                    matches.append({"id": memory_id, "score": 0.8 if near else 0.3})
            return self.reply({"matches": matches})
        return self.reply({})

    def do_POST(self):
        if self.path in ("/add", "/query", "/remove"):
            return self.semantic(json.loads(self.rfile.read(int(self.headers["content-length"]))))
        form = parse_qs(self.rfile.read(int(self.headers["content-length"])).decode())
        if form["client_secret"] != [GOOGLE_CLIENT_SECRET]:
            self.send_response(400)
            self.end_headers()
            return
        payload = base64.urlsafe_b64decode(form["code"][0]).rstrip(b"=")
        token = "x." + base64.urlsafe_b64encode(payload).decode().rstrip("=") + ".x"
        body = json.dumps({"id_token": token}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("memem")
    persist = tmp / "state"
    subprocess.run(
        ["npx", "--yes", "wrangler", "d1", "migrations", "apply", "memem", "--local", "--persist-to", str(persist)],
        check=True,
        capture_output=True,
        env=WRANGLER_ENV,
        stdin=subprocess.DEVNULL,
    )
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    fake = ThreadingHTTPServer(("127.0.0.1", 0), FakeGoogle)
    Thread(target=fake.serve_forever, daemon=True).start()
    fake_base = f"http://127.0.0.1:{fake.server_address[1]}"
    log_path = tmp / "server.log"
    with open(log_path, "w") as log:
        proc = subprocess.Popen(
            ["uv", "run", "pywrangler", "dev", "--env", "test", "--port", str(port), "--persist-to", str(persist),
             "--var", f"MEMEM_SEMANTIC_TEST_BASE:{fake_base}",
             "--var", f"GOOGLE_CLIENT_ID:{GOOGLE_CLIENT_ID}", "--var", f"GOOGLE_CLIENT_SECRET:{GOOGLE_CLIENT_SECRET}",
             "--var", f"MEMEM_OWNER_EMAIL:{OWNER_EMAIL}", "--var", f"MEMEM_GOOGLE_TEST_BASE:{fake_base}"],
            env=WRANGLER_ENV,
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    try:
        for _ in range(240):
            try:
                if httpx.get(f"{base}/health", timeout=60).status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.5)
        else:
            raise RuntimeError(log_path.read_text())
        tokens = {
            "claude": grant(base, "work"),
            "chatgpt": grant(base, "work"),
            "reader": grant(base, "work", read_only=True),
            "personal": grant(base, "home"),
        }
        yield {"base": base, "tokens": tokens, "persist": persist}
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait()
        fake.shutdown()


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(params=["auto", "legacy"])
def mode(request):
    return request.param


def client(env, name, mode="auto"):
    headers = {"authorization": f"Bearer {env['tokens'][name]['access_token']}"}
    http = httpx2.AsyncClient(headers=headers, timeout=60)
    return Client(streamable_http_client(f"{env['base']}/mcp", http_client=http), mode=mode)


async def call(c, tool, **args):
    result = await c.call_tool(tool, args)
    assert not result.is_error, result
    return json.loads(result.content[0].text)


def post(target, token=None):
    headers = {**ACCEPT, **({"authorization": f"Bearer {token}"} if token else {})}
    return httpx.post(target, headers=headers, json=TOOLS_LIST)


def test_unauthenticated_requests_point_to_discovery(env):
    base = env["base"]
    response = post(f"{base}/mcp")
    assert response.status_code == 401
    pointer = re.search(r'resource_metadata="([^"]+)"', response.headers["www-authenticate"]).group(1)
    resource = httpx.get(pointer).json()
    assert resource["resource"] == f"{base}/mcp"
    assert resource["authorization_servers"] == [base]
    server = httpx.get(f"{base}/.well-known/oauth-authorization-server").json()
    assert server["issuer"] == base
    assert server["code_challenge_methods_supported"] == ["S256"]
    assert server["token_endpoint_auth_methods_supported"] == ["none"]


def test_tokens_in_urls_are_gone(env):
    token = env["tokens"]["claude"]["access_token"]
    assert post(f"{env['base']}/mcp/{token}").status_code == 404


@pytest.mark.parametrize("redirect", [
    CLAUDE_REDIRECT, CHATGPT_REDIRECT, "https://chatgpt.com/connector/oauth/abc123",
    GEMINI_REDIRECT, f"https://oauth-redirect-sandbox.googleusercontent.com/a/{GEMINI_PATH}",
])
def test_known_redirects_register(env, redirect):
    assert register(env["base"], redirect).status_code == 201


@pytest.mark.parametrize("redirect", [
    "https://evil.example/callback",
    "http://localhost:3118/callback",
    "http://127.0.0.1:9999/callback",
    f"https://evil.googleusercontent.com/r/{GEMINI_PATH}",
    f"https://lh3.googleusercontent.com/r/{GEMINI_PATH}",
    f"https://oauth-redirect-evil.googleusercontent.com/r/{GEMINI_PATH}",
    f"https://oauth-redirect.googleusercontent.com.evil.example/r/{GEMINI_PATH}",
    "https://oauth-redirect.googleusercontent.com/evil",
    "https://oauth-redirect.googleusercontent.com/r/abc",
    f"https://oauth-redirect.googleusercontent.com/r/a/../../{GEMINI_PATH}",
    f"http://oauth-redirect.googleusercontent.com/r/{GEMINI_PATH}",
    "https://claude.ai.evil.example/api/mcp/auth_callback",
    "https://claude.ai/other",
    "http://claude.ai/api/mcp/auth_callback",
    "https://chatgpt.com/evil",
    "https://user@claude.ai/api/mcp/auth_callback",
    "javascript:alert(1)",
])
def test_unknown_redirects_are_refused(env, redirect):
    assert register(env["base"], redirect).status_code == 400


def test_consent_page_shows_destination_and_escapes(env):
    base = env["base"]
    client_id = register(base, CLAUDE_REDIRECT).json()["client_id"]
    _, challenge = pkce()
    page = httpx.get(f"{base}/oauth/authorize", params={
        "client_id": client_id, "redirect_uri": CLAUDE_REDIRECT, "response_type": "code",
        "code_challenge": challenge, "code_challenge_method": "S256", "state": '"><script>alert(1)</script>',
    })
    assert page.status_code == 200
    assert "claude.ai" in page.text and "<script>" not in page.text
    assert page.headers["x-frame-options"] == "DENY"


def test_authorize_refuses_unregistered_redirect(env):
    base = env["base"]
    client_id = register(base, CLAUDE_REDIRECT).json()["client_id"]
    _, challenge = pkce()
    response = approve(base, client_id, challenge, redirect=CHATGPT_REDIRECT)
    assert response.status_code == 400 and "location" not in response.headers


def test_gemini_signs_in_with_several_redirects_and_a_long_state(env):
    base = env["base"]
    # The six addresses the real app registers.
    uris = [
        f"https://{host}.googleusercontent.com/{kind}/{GEMINI_PATH}"
        for kind in "ra"
        for host in ("oauth-redirect", "oauth-redirect-sandbox", "oauth-redirect-test")
    ]
    registered = httpx.post(f"{base}/oauth/register", json={"redirect_uris": uris, "client_name": "gemini"})
    assert registered.status_code == 201
    verifier, challenge = pkce()
    long_state = "s" * 1_400
    target = authorize_url(base, registered.json()["client_id"], challenge, uris[0]).replace("state=xyz", f"state={long_state}")
    page, _, _ = open_consent(target)
    assert "Gemini" in page.text
    response = sign_in(base, target, space="geminicheck")
    assert response.status_code == 302
    assert response.headers["location"].startswith(uris[0] + "?")
    assert parse_qs(urlsplit(response.headers["location"]).query)["state"] == [long_state]
    tokens = exchange(base, registered.json()["client_id"], code_from(response), verifier, uris[0])
    assert tokens.status_code == 200


def start(env):
    base = env["base"]
    client_id = register(base).json()["client_id"]
    return base, client_id, pkce()[1]


@pytest.mark.parametrize("overrides", [
    {"email": "someone.else@example.com"},
    {"email_verified": False},
    {"aud": "another-app"},
    {"iss": "https://evil.example"},
    {"exp": 1},
    {"nonce": "wrong"},
])
def test_bad_google_identity_is_refused(env, overrides):
    base, client_id, challenge = start(env)
    response = approve(base, client_id, challenge, **overrides)
    assert response.status_code == 403 and "location" not in response.headers


def test_email_match_ignores_case(env):
    base, client_id, challenge = start(env)
    assert approve(base, client_id, challenge, email=OWNER_EMAIL.upper()).status_code == 302


def test_consent_form_needs_this_browsers_cookie(env):
    base, client_id, challenge = start(env)
    _, session, fields = open_consent(authorize_url(base, client_id, challenge))
    assert to_google(base, "other-browser", fields).status_code == 403
    assert httpx.post(f"{base}/oauth/authorize", data={**fields, "space": "work"}).status_code == 403


def test_callback_needs_the_browser_that_started_it(env):
    base, client_id, challenge = start(env)
    response = approve(base, client_id, challenge, session_override="other-browser")
    assert response.status_code == 403 and "location" not in response.headers


def test_callback_works_only_once(env):
    base, client_id, challenge = start(env)
    _, session, fields = open_consent(authorize_url(base, client_id, challenge))
    google = {k: v[0] for k, v in parse_qs(urlsplit(to_google(base, session, fields).headers["location"]).query).items()}
    query = {"state": google["state"], "code": fake_code(claims(google["nonce"]))}
    assert callback(base, query, session).status_code == 302
    assert callback(base, query, session).status_code == 400


def test_google_cancel_issues_nothing(env):
    base, client_id, challenge = start(env)
    _, session, fields = open_consent(authorize_url(base, client_id, challenge))
    state = parse_qs(urlsplit(to_google(base, session, fields).headers["location"]).query)["state"][0]
    response = callback(base, {"state": state, "error": "access_denied"}, session)
    assert response.status_code == 400 and "location" not in response.headers


def test_google_redirect_asks_for_identity_only(env):
    base, client_id, challenge = start(env)
    _, session, fields = open_consent(authorize_url(base, client_id, challenge))
    google = parse_qs(urlsplit(to_google(base, session, fields).headers["location"]).query)
    assert google["scope"] == ["openid email"]
    assert google["redirect_uri"] == [f"{base}/oauth/google/callback"]


def test_redirect_includes_state_and_issuer(env):
    base = env["base"]
    client_id = register(base).json()["client_id"]
    _, challenge = pkce()
    query = parse_qs(urlsplit(approve(base, client_id, challenge).headers["location"]).query)
    assert query["state"] == ["xyz"] and query["iss"] == [base]


def test_code_needs_correct_verifier_and_works_once(env):
    base = env["base"]
    client_id = register(base).json()["client_id"]
    verifier, challenge = pkce()
    code = code_from(approve(base, client_id, challenge))
    assert exchange(base, client_id, code, pkce()[0]).json()["error"] == "invalid_grant"
    # A failed attempt burns the code.
    assert exchange(base, client_id, code, verifier).status_code == 400

    code = code_from(approve(base, client_id, challenge))
    assert exchange(base, client_id, code, verifier).status_code == 200
    assert exchange(base, client_id, code, verifier).json()["error"] == "invalid_grant"


def test_refresh_rotates_and_old_tokens_stop(env):
    base = env["base"]
    first = grant(base, "rotate")
    form = {"grant_type": "refresh_token", "client_id": first["client_id"], "refresh_token": first["refresh_token"]}
    second = httpx.post(f"{base}/oauth/token", data=form).json()
    assert post(f"{base}/mcp", second["access_token"]).status_code == 200
    assert post(f"{base}/mcp", first["access_token"]).status_code == 401
    assert httpx.post(f"{base}/oauth/token", data=form).json()["error"] == "invalid_grant"
    wrong = {**form, "refresh_token": second["refresh_token"], "client_id": "client_other"}
    assert httpx.post(f"{base}/oauth/token", data=wrong).json()["error"] == "invalid_grant"


def test_expired_access_token_is_refused(env):
    base = env["base"]
    tokens = grant(base, "expires")
    assert post(f"{base}/mcp", tokens["access_token"]).status_code == 200
    d1(env["persist"], "UPDATE connections SET access_expires_at = 1 WHERE space = 'expires'")
    assert post(f"{base}/mcp", tokens["access_token"]).status_code == 401


@pytest.mark.anyio
async def test_memory_shared_between_assistants(env, mode):
    async with client(env, "claude", mode) as a, client(env, "chatgpt", mode) as b:
        saved = await call(a, "memory_add", content=f"Project Falcon ships in March {mode}")
        found = await call(b, "memory_search", query=f"falcon {mode}")
    assert found["memories"][0]["id"] == saved["id"]
    assert found["memories"][0]["source"].startswith("claude-")


def test_static_bearer_connection_and_revoke(env):
    done = memem(env["persist"], "connect", "doomed", "--space", "work")
    assert done.returncode == 0, done.stderr
    token = re.search(r"^Token: (\S+)$", done.stdout, re.M).group(1)
    target = f"{env['base']}/mcp"
    assert post(target, token).status_code == 200
    assert memem(env["persist"], "revoke", "doomed").returncode == 0
    assert post(target, token).status_code == 401


@pytest.mark.anyio
async def test_spaces_are_isolated(env, mode):
    word = f"secretword{mode}"
    async with client(env, "claude", mode) as work, client(env, "personal", mode) as home:
        saved = await call(work, "memory_add", content=word)
        assert (await call(home, "memory_search", query=word))["memories"] == []
        assert (await call(home, "memory_delete", id=saved["id"]))["deleted"] is False
        assert len((await call(work, "memory_search", query=word))["memories"]) == 1


@pytest.mark.anyio
async def test_read_only_has_no_write_tools(env, mode):
    async with client(env, "reader", mode) as c:
        assert [t.name for t in (await c.list_tools()).tools] == ["memory_overview", "memory_search", "memory_list"]
        assert (await c.call_tool("memory_add", {"content": "readonlyattempt"})).is_error
        assert (await c.call_tool("memory_update", {"id": 1, "content": "readonlyattempt"})).is_error
        assert (await call(c, "memory_search", query="readonlyattempt"))["memories"] == []


@pytest.mark.anyio
async def test_invalid_arguments_are_rejected(env, mode):
    async with client(env, "claude", mode) as c:
        assert (await c.call_tool("memory_add", {"content": ""})).is_error
        assert (await c.call_tool("memory_add", {"content": "x" * 10_001})).is_error


def test_oversized_bodies_rejected(env):
    token = env["tokens"]["claude"]["access_token"]
    response = httpx.post(
        f"{env['base']}/mcp",
        headers={**ACCEPT, "authorization": f"Bearer {token}", "content-type": "application/json"},
        content=b"x" * (300 * 1024),
    )
    assert response.status_code == 413


def test_no_plaintext_tokens_at_rest(env):
    post(f"{env['base']}/mcp", env["tokens"]["claude"]["access_token"])
    files = [p for p in (env["persist"] / "v3" / "d1").rglob("*") if p.is_file()]
    assert any(p.suffix == ".sqlite" for p in files)
    data = b"".join(p.read_bytes() for p in files)
    for tokens in env["tokens"].values():
        assert tokens["access_token"].encode() not in data
        assert tokens["refresh_token"].encode() not in data


@pytest.mark.anyio
async def test_like_wildcards_are_literal(env):
    async with client(env, "personal") as c:
        await call(c, "memory_add", content="discount is 50% today")
        await call(c, "memory_add", content="discount is 50 dollars")
        found = await call(c, "memory_search", query="50%")
    assert [m["content"] for m in found["memories"]] == ["discount is 50% today"]


def test_cli_rejects_bad_input_and_duplicates(env):
    assert memem(env["persist"], "connect", "x'; DROP TABLE memories;--", "--space", "s").returncode == 1
    assert memem(env["persist"], "connect", "dup", "--space", "s").returncode == 0
    assert memem(env["persist"], "connect", "dup", "--space", "s").returncode == 1


@pytest.mark.anyio
async def test_concurrent_requests_stay_in_their_own_space(env):
    async with client(env, "claude") as work, client(env, "personal") as home:
        await call(work, "memory_add", content="racemarker workside")
        await call(home, "memory_add", content="racemarker homeside")

        async def check(c, expected):
            memories = (await call(c, "memory_search", query="racemarker"))["memories"]
            assert [m["content"] for m in memories] == [f"racemarker {expected}"]

        await asyncio.gather(*(check(c, e) for _ in range(25) for c, e in ((work, "workside"), (home, "homeside"))))


class MemoryTokenStorage:
    def __init__(self):
        self.tokens = None
        self.client_info = None

    async def get_tokens(self):
        return self.tokens

    async def set_tokens(self, tokens):
        self.tokens = tokens

    async def get_client_info(self):
        return self.client_info

    async def set_client_info(self, client_info):
        self.client_info = client_info


@pytest.mark.anyio
async def test_official_sdk_oauth_client_completes_the_flow(env):
    base = env["base"]
    result = {}

    async def redirect_handler(url):
        response = await asyncio.to_thread(sign_in, base, url, "sdkflow")
        assert response.status_code == 302, response.text
        query = parse_qs(urlsplit(response.headers["location"]).query)
        result.update(code=query["code"][0], state=query["state"][0], iss=query["iss"][0])

    async def callback_handler():
        return AuthorizationCodeResult(code=result["code"], state=result["state"], iss=result["iss"])

    provider = OAuthClientProvider(
        server_url=f"{base}/mcp",
        client_metadata=OAuthClientMetadata(
            redirect_uris=[CLAUDE_REDIRECT],
            client_name="sdk",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        ),
        storage=MemoryTokenStorage(),
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    http = httpx2.AsyncClient(auth=provider, timeout=60)
    async with Client(streamable_http_client(f"{base}/mcp", http_client=http), mode="legacy") as c:
        saved = await call(c, "memory_add", content="saved through sdk oauth")
        found = await call(c, "memory_search", query="sdk oauth")
    assert found["memories"][0]["id"] == saved["id"]


@pytest.mark.anyio
async def test_recall_finds_meaning_without_shared_words(env):
    async with client(env, "claude") as c:
        await call(c, "memory_add", content="I own a Honda Civic.")
        await call(c, "memory_add", content="Bananas are on sale.")
        found = await call(c, "memory_search", query="vehicle")
    assert [m["content"] for m in found["memories"]] == ["I own a Honda Civic."]


@pytest.mark.anyio
async def test_low_similarity_results_are_dropped(env):
    async with client(env, "personal") as c:
        await call(c, "memory_add", content="Unrelated gardening note zzq")
        found = await call(c, "memory_search", query="quantum chromodynamics")
    assert found["memories"] == []


@pytest.mark.anyio
async def test_common_words_do_not_match_everything(env):
    async with client(env, "personal") as c:
        await call(c, "memory_add", content="This is about the thing with it zzr")
        found = await call(c, "memory_search", query="what is the kumquat")
    assert all("zzr" not in m["content"] for m in found["memories"])


@pytest.mark.anyio
async def test_matching_both_ways_ranks_first(env):
    async with client(env, "chatgpt") as c:
        await call(c, "memory_add", content="The honda dealership zzs")
        await call(c, "memory_add", content="My vehicle inspection zzs is due")
        found = await call(c, "memory_search", query="vehicle zzs")
    assert found["memories"][0]["content"] == "My vehicle inspection zzs is due"


@pytest.mark.anyio
async def test_failed_embedding_still_saves_and_keywords_work(env):
    async with client(env, "personal") as c:
        await call(c, "memory_add", content="failembed zzt saved anyway")
        found = await call(c, "memory_search", query="zzt")
    assert [m["content"] for m in found["memories"]] == ["failembed zzt saved anyway"]


@pytest.mark.anyio
async def test_failed_meaning_search_falls_back_to_keywords(env):
    async with client(env, "personal") as c:
        await call(c, "memory_add", content="zzu fallback note")
        found = await call(c, "memory_search", query="failsearch zzu")
    assert [m["content"] for m in found["memories"]] == ["zzu fallback note"]


@pytest.mark.anyio
async def test_wrong_vector_results_cannot_cross_spaces(env):
    async with client(env, "claude") as work, client(env, "personal") as home:
        await call(work, "memory_add", content="zzv private work detail")
        found = await call(home, "memory_search", query="leakcheck")
    assert all("zzv" not in m["content"] for m in found["memories"])


@pytest.mark.anyio
async def test_forget_removes_the_vector_only_for_its_own_space(env):
    async with client(env, "claude") as work, client(env, "personal") as home:
        saved = await call(work, "memory_add", content="zzw honda parking pass")
        vector = f"m:{saved['id']}"
        assert vector in FakeGoogle.vectors
        assert (await call(home, "memory_delete", id=saved["id"]))["deleted"] is False
        assert vector in FakeGoogle.vectors
        assert (await call(work, "memory_delete", id=saved["id"]))["deleted"] is True
        assert vector not in FakeGoogle.vectors


def by_id(found, memory_id):
    return next(m for m in found["memories"] if m["id"] == memory_id)


@pytest.mark.anyio
async def test_update_rewrites_memory_and_records_who(env):
    async with client(env, "claude") as a, client(env, "chatgpt") as b:
        saved = await call(a, "memory_add", content="zya meeting is on Monday")
        assert (await call(b, "memory_update", id=saved["id"], content="zya meeting is on Friday"))["updated"] is True
        memory = by_id(await call(a, "memory_search", query="zya"), saved["id"])
    assert memory["content"] == "zya meeting is on Friday"
    assert memory["source"] != memory["updated_by"]
    assert memory["updated_at"]


@pytest.mark.anyio
async def test_update_refreshes_meaning_search(env):
    async with client(env, "chatgpt") as c:
        saved = await call(c, "memory_add", content="Bicycle storage zyb")
        await call(c, "memory_update", id=saved["id"], content="Civic storage zyb")
        found = await call(c, "memory_search", query="vehicle")
    assert saved["id"] in [m["id"] for m in found["memories"]]


@pytest.mark.anyio
async def test_failed_reindex_drops_the_old_vector(env):
    async with client(env, "personal") as c:
        saved = await call(c, "memory_add", content="zyc honda note")
        assert f"m:{saved['id']}" in FakeGoogle.vectors
        await call(c, "memory_update", id=saved["id"], content="failembed zyc rewritten")
        assert f"m:{saved['id']}" not in FakeGoogle.vectors
        found = await call(c, "memory_search", query="zyc")
    assert [m["content"] for m in found["memories"]] == ["failembed zyc rewritten"]


@pytest.mark.anyio
async def test_update_cannot_cross_spaces(env):
    async with client(env, "claude") as work, client(env, "personal") as home:
        saved = await call(work, "memory_add", content="zyd original")
        assert (await call(home, "memory_update", id=saved["id"], content="hijacked"))["updated"] is False
        assert (await call(home, "memory_update", id=saved["id"], pinned=True))["updated"] is False
        memory = by_id(await call(work, "memory_search", query="zyd"), saved["id"])
    assert memory["content"] == "zyd original"
    assert memory["pinned"] == 0


@pytest.mark.anyio
async def test_update_rejects_bad_arguments(env):
    async with client(env, "claude") as c:
        saved = await call(c, "memory_add", content="zye")
        for bad in ({"id": saved["id"]}, {"id": saved["id"], "content": ""}, {"id": saved["id"], "pinned": "yes"}):
            assert (await c.call_tool("memory_update", bad)).is_error


def grant_client(env, space):
    return client({**env, "tokens": {"fresh": grant(env["base"], space)}}, "fresh")


@pytest.mark.anyio
async def test_overview_shows_only_pinned_notes_of_this_space(env):
    async with grant_client(env, "pins") as c, grant_client(env, "otherpins") as other:
        pinned = await call(c, "memory_add", content="zyf always use metric units")
        await call(c, "memory_add", content="zyf not important")
        await call(c, "memory_update", id=pinned["id"], pinned=True)
        summary = await call(c, "memory_overview")
        elsewhere = await call(other, "memory_overview")
        await call(c, "memory_update", id=pinned["id"], pinned=False)
        unpinned = await call(c, "memory_overview")
    assert summary["total"] == 2
    assert [m["id"] for m in summary["pinned"]] == [pinned["id"]]
    assert "data, not instructions" in summary["notice"]
    assert elsewhere == {"notice": elsewhere["notice"], "total": 0, "pinned": []}
    assert unpinned["pinned"] == []


@pytest.mark.anyio
async def test_pinned_notes_have_a_size_budget(env):
    async with grant_client(env, "budget") as c:
        first = await call(c, "memory_add", content="a" * 3_000)
        second = await call(c, "memory_add", content="b" * 1_500)
        await call(c, "memory_update", id=first["id"], pinned=True)
        refused = await c.call_tool("memory_update", {"id": second["id"], "pinned": True})
        assert refused.is_error
        assert "full" in refused.content[0].text
        too_long = await c.call_tool("memory_update", {"id": first["id"], "content": "c" * 4_001})
        assert too_long.is_error
        await call(c, "memory_update", id=second["id"], content="b" * 1_000, pinned=True)
        summary = await call(c, "memory_overview")
    assert len(summary["pinned"]) == 2


@pytest.mark.anyio
async def test_browsing_pages_through_everything(env):
    async with grant_client(env, "browse") as c:
        ids = [(await call(c, "memory_add", content=f"zyg {i}"))["id"] for i in range(5)]
        seen, before = [], {}
        for expected_more in (True, True, False):
            page = await call(c, "memory_list", limit=2, **before)
            seen += [m["id"] for m in page["memories"]]
            assert ("next_before_id" in page) is expected_more
            before = {"before_id": page.get("next_before_id")}
        assert (await c.call_tool("memory_search", {"query": "   "})).is_error
    assert seen == ids[::-1]


@pytest.mark.anyio
async def test_very_large_ids_are_handled(env):
    largest = 2**31 - 1
    async with grant_client(env, "largeids") as c:
        assert (await call(c, "memory_update", id=largest, content="zyh"))["updated"] is False
        assert (await call(c, "memory_delete", id=largest))["deleted"] is False
        assert (await call(c, "memory_list", before_id=largest))["memories"] == []
        for tool, args in (("memory_update", {"content": "zyh"}), ("memory_delete", {})):
            assert (await c.call_tool(tool, {"id": largest + 1, **args})).is_error
        assert (await c.call_tool("memory_list", {"before_id": largest + 1})).is_error


def file_session(env, **claim_overrides):
    """Sign in to the file page through the stand-in Google, returning cookie headers."""
    base = env["base"]
    start = httpx.get(f"{base}/files")
    assert start.status_code == 302
    login = re.search(r"memem_session=([^;]+)", start.headers["set-cookie"]).group(1)
    google = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    code = fake_code({**claims(google["nonce"]), **claim_overrides})
    done = callback(base, {"state": google["state"], "code": code}, login)
    if done.status_code != 302:
        return done
    token = re.search(r"memem_web=([^;]+)", done.headers["set-cookie"]).group(1)
    return {"cookie": f"memem_web={token}"}


def same_site(env, cookies):
    return {**cookies, "origin": env["base"], "x-memem": "1"}


def new_memory(env, cookies, description, space="work"):
    reply = httpx.post(f"{env['base']}/files/memories", json={"space": space, "description": description}, headers=same_site(env, cookies))
    assert reply.status_code == 200, reply.text
    return reply.json()["id"]


def put_file(env, cookies, memory_id, name, content):
    return httpx.put(
        f"{env['base']}/files/upload",
        params={"memory_id": memory_id, "name": name},
        content=content,
        headers={**same_site(env, cookies), "content-type": "application/zip"},
    )


def test_file_page_requires_the_owner(env):
    base = env["base"]
    start = httpx.get(f"{base}/files?space=work")
    assert start.status_code == 302 and "/auth?" in start.headers["location"]
    assert httpx.put(f"{base}/files/upload", content=b"x").status_code == 401
    assert httpx.post(f"{base}/files/memories", json={}).status_code == 401
    assert httpx.get(f"{base}/files/download/{'a' * 32}").status_code == 302
    denied = file_session(env, email="someone@example.com")
    assert denied.status_code == 403 and "set-cookie" not in denied.headers
    assert httpx.get(f"{base}/files", headers={"cookie": "memem_web=forged"}).status_code == 302


def test_sign_in_returns_only_to_the_requested_file_page(env):
    base = env["base"]
    start = httpx.get(f"{base}/files?memory_id=7")
    login = re.search(r"memem_session=([^;]+)", start.headers["set-cookie"]).group(1)
    google = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    done = callback(base, {"state": google["state"], "code": fake_code(claims(google["nonce"]))}, login)
    assert done.headers["location"] == "/files?memory_id=7"
    assert "HttpOnly" in done.headers["set-cookie"] and "Path=/files" in done.headers["set-cookie"]


def test_upload_page_is_locked_down(env):
    cookies = file_session(env)
    page = httpx.get(f"{env['base']}/files", headers=cookies)
    policy = page.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", policy).group(1)
    assert f'<script nonce="{nonce}">' in page.text and page.text.count("<script") == 1
    assert "default-src 'none'" in policy and "frame-ancestors 'none'" in policy


@pytest.mark.anyio
async def test_several_files_attach_and_download(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzf launch assets for the vehicle campaign")
    contents = {"logo.png": secrets.token_bytes(5000), "copy.docx": b"copy", "bundle.zip": secrets.token_bytes(70000)}
    for name, content in contents.items():
        assert put_file(env, cookies, memory_id, name, content).status_code == 200
    async with client(env, "chatgpt") as c:
        found = await call(c, "memory_search", query="zzf launch")
        listed = await call(c, "memory_list", limit=5)
    attachments = by_id(found, memory_id)["attachments"]
    assert [a["name"] for a in attachments] == list(contents)
    assert by_id(listed, memory_id)["attachments"] == attachments
    assert attachments[2]["size"] == 70000
    for attachment in attachments:
        assert httpx.get(attachment["browser_download_url"]).status_code == 302
        download = httpx.get(attachment["browser_download_url"], headers=cookies)
        assert download.status_code == 200
        assert download.content == contents[attachment["name"]]
        assert download.headers["content-type"] == "application/octet-stream"
        assert download.headers["content-disposition"].startswith("attachment;")
        assert download.headers["x-content-type-options"] == "nosniff"


def test_other_sites_cannot_change_files(env):
    base = env["base"]
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzg")
    target = f"{base}/files/upload?memory_id={memory_id}&name=a.txt"
    assert httpx.put(target, content=b"x", headers={**cookies, "origin": "https://evil.example", "x-memem": "1"}).status_code == 403
    assert httpx.put(target, content=b"x", headers={**cookies, "origin": base}).status_code == 403
    assert httpx.post(f"{base}/files/memories", json={"space": "work", "description": "x"}, headers=cookies).status_code == 403


def test_file_limits_and_bad_names(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzh limits")
    for index in range(20):
        assert put_file(env, cookies, memory_id, f"{index}.bin", b"x").status_code == 200
    assert put_file(env, cookies, memory_id, "extra.bin", b"x").status_code == 409
    other = new_memory(env, cookies, "zzh names")
    assert put_file(env, cookies, other, "bad\nname.txt", b"x").status_code == 400
    assert put_file(env, cookies, other, "empty.txt", b"").status_code == 400
    assert put_file(env, cookies, 2_000_000_000, "a.txt", b"x").status_code == 404
    host, port = urlsplit(env["base"]).netloc.split(":")
    with socket.create_connection((host, int(port))) as raw:
        raw.sendall((
            f"PUT /files/upload?memory_id={other}&name=big.bin HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Cookie: {cookies['cookie']}\r\nOrigin: {env['base']}\r\nx-memem: 1\r\n"
            f"Content-Length: {95 * 1024 * 1024 + 1}\r\n\r\n"
        ).encode())
        assert b" 413 " in raw.recv(200)


def test_file_names_cannot_inject_markup_or_headers(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "<script>zzi</script>")
    name = 'a"><img src=x>.txt'
    assert put_file(env, cookies, memory_id, name, b"x").status_code == 200
    page = httpx.get(f"{env['base']}/files", params={"memory_id": memory_id}, headers=cookies)
    assert "<img src=x>" not in page.text and "<script>zzi" not in page.text
    link = re.search(r'/files/download/([A-Za-z0-9_-]+)', page.text).group(0)
    download = httpx.get(env["base"] + link, headers=cookies)
    assert '"><img' not in download.headers["content-disposition"]


@pytest.mark.anyio
async def test_removing_a_file_keeps_the_memory(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzj removal")
    keep = put_file(env, cookies, memory_id, "keep.txt", b"keep").json()["id"]
    drop = put_file(env, cookies, memory_id, "drop.txt", b"drop").json()["id"]
    assert httpx.delete(f"{env['base']}/files/attachments/{drop}", headers=same_site(env, cookies)).status_code == 200
    assert httpx.get(f"{env['base']}/files/download/{drop}", headers=cookies).status_code == 404
    assert httpx.get(f"{env['base']}/files/download/{keep}", headers=cookies).content == b"keep"
    async with client(env, "claude") as c:
        memory = by_id(await call(c, "memory_search", query="zzj"), memory_id)
    assert [a["name"] for a in memory["attachments"]] == ["keep.txt"]


@pytest.mark.anyio
async def test_deleting_a_memory_deletes_its_files(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzk deletion")
    file_id = put_file(env, cookies, memory_id, "a.txt", b"a").json()["id"]
    async with client(env, "personal") as home, client(env, "claude") as work:
        assert (await call(home, "memory_delete", id=memory_id))["deleted"] is False
        assert httpx.get(f"{env['base']}/files/download/{file_id}", headers=cookies).status_code == 200
        assert (await call(work, "memory_delete", id=memory_id))["deleted"] is True
    assert httpx.get(f"{env['base']}/files/download/{file_id}", headers=cookies).status_code == 404


@pytest.mark.anyio
async def test_attachments_stay_in_their_space(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzl private assets")
    put_file(env, cookies, memory_id, "a.txt", b"a")
    async with client(env, "personal") as home:
        assert (await call(home, "memory_search", query="zzl"))["memories"] == []
        assert all(m["id"] != memory_id for m in (await call(home, "memory_list", limit=100))["memories"])
        assert (await home.call_tool("memory_upload_link", {"memory_id": memory_id})).is_error


@pytest.mark.anyio
async def test_upload_link_tool(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzm link")
    async with client(env, "claude") as c, client(env, "reader") as reader:
        fresh = await call(c, "memory_upload_link")
        existing = await call(c, "memory_upload_link", memory_id=memory_id)
        assert (await reader.call_tool("memory_upload_link", {})).is_error
    assert fresh["url"] == f"{env['base']}/files?space=work"
    assert existing["url"] == f"{env['base']}/files?memory_id={memory_id}"
    assert httpx.get(existing["url"], headers=cookies).status_code == 200


async def sandbox_url(c, **args):
    return (await call(c, "memory_sandbox_upload", **args))["upload_url"]


@pytest.mark.anyio
async def test_sandbox_uploads_a_file_without_sign_in(env):
    content = secrets.token_bytes(40000)
    async with client(env, "chatgpt") as c:
        url = await sandbox_url(c, name="report.zip", description="zzn quarterly report bundle")
        reply = httpx.put(url, content=content)
        assert reply.status_code == 200, reply.text
        memory = by_id(await call(c, "memory_search", query="zzn"), reply.json()["memory_id"])
    assert memory["source"].startswith("claude-") and memory["attachments"][0]["name"] == "report.zip"
    download_url = memory["attachments"][0]["browser_download_url"]
    assert httpx.get(download_url).status_code == 302
    assert httpx.get(download_url, headers=file_session(env)).content == content


@pytest.mark.anyio
async def test_sandbox_link_works_once_and_grants_nothing_else(env):
    async with client(env, "claude") as c:
        url = await sandbox_url(c, name="a.bin", description="zzo")
    assert httpx.get(url).status_code == 405
    assert httpx.delete(url).status_code == 405
    assert httpx.put(url, content=b"").status_code == 400
    assert httpx.put(url, content=b"x").status_code == 200
    assert httpx.put(url, content=b"x").status_code == 403
    assert httpx.put(f"{env['base']}/files/direct/{'a' * 43}", content=b"x").status_code == 403
    token = url.rsplit("/", 1)[1]
    assert httpx.get(f"{env['base']}/files", headers={"cookie": f"memem_web={token}"}).status_code == 302


@pytest.mark.anyio
async def test_sandbox_link_expires_and_leaves_no_memory(env):
    async with client(env, "personal") as c:
        url = await sandbox_url(c, name="a.bin", description="zzp expired")
        d1(env["persist"], "UPDATE upload_tokens SET expires_at = 1")
        assert httpx.put(url, content=b"x").status_code == 403
        assert (await call(c, "memory_search", query="zzp"))["memories"] == []


@pytest.mark.anyio
async def test_sandbox_upload_is_limited_by_access_and_space(env):
    cookies = file_session(env)
    memory_id = new_memory(env, cookies, "zzq work only")
    async with client(env, "personal") as home, client(env, "reader") as reader, client(env, "claude") as work:
        assert (await home.call_tool("memory_sandbox_upload", {"name": "a", "memory_id": memory_id})).is_error
        assert (await reader.call_tool("memory_sandbox_upload", {"name": "a", "description": "x"})).is_error
        assert (await work.call_tool("memory_sandbox_upload", {"name": "a"})).is_error
        assert (await work.call_tool("memory_sandbox_upload", {"name": "a\nb", "description": "x"})).is_error
        url = await sandbox_url(work, name="more.bin", memory_id=memory_id)
    assert httpx.put(url, content=b"x").json()["memory_id"] == memory_id


async def attached(env, c, cookies, label, content=b"secret bytes"):
    memory_id = new_memory(env, cookies, label)
    assert put_file(env, cookies, memory_id, "file.bin", content).status_code == 200
    found = await call(c, "memory_search", query=label)
    return memory_id, by_id(found, memory_id)["attachments"][0], found


@pytest.mark.anyio
async def test_sandbox_downloads_a_file_once_without_sign_in(env):
    cookies = file_session(env)
    content = secrets.token_bytes(30000)
    async with client(env, "claude") as c:
        memory_id, attachment, found = await attached(env, c, cookies, "zzr", content)
        assert "sign-in" in found["attachment_note"]
        link = await call(c, "memory_sandbox_download", attachment_id=attachment["id"])
    assert link["expires_in_seconds"] == 120
    url = link["download_url"]
    assert httpx.put(url, content=b"x").status_code == 405
    first = httpx.get(url)
    assert first.status_code == 200 and first.content == content
    assert first.headers["content-type"] == "application/octet-stream"
    assert first.headers["content-disposition"].startswith("attachment;")
    assert httpx.get(url).status_code == 403
    assert httpx.get(f"{env['base']}/files/fetch/{'a' * 43}").status_code == 403
    page = httpx.get(f"{env['base']}/files", params={"memory_id": memory_id}, headers=cookies)
    assert "Sandbox downloads" in page.text and ", fetched" in page.text


@pytest.mark.anyio
async def test_sandbox_download_link_expires(env):
    cookies = file_session(env)
    async with client(env, "claude") as c:
        _, attachment, _ = await attached(env, c, cookies, "zzs expiring")
        url = (await call(c, "memory_sandbox_download", attachment_id=attachment["id"]))["download_url"]
    d1(env["persist"], "UPDATE download_links SET expires_at = 1")
    assert httpx.get(url).status_code == 403


@pytest.mark.anyio
async def test_sandbox_download_is_limited_by_access_and_space(env):
    cookies = file_session(env)
    async with client(env, "claude") as work, client(env, "personal") as home, client(env, "reader") as reader:
        _, attachment, _ = await attached(env, work, cookies, "zzt guarded")
        assert (await home.call_tool("memory_sandbox_download", {"attachment_id": attachment["id"]})).is_error
        assert (await reader.call_tool("memory_sandbox_download", {"attachment_id": attachment["id"]})).is_error
        assert (await work.call_tool("memory_sandbox_download", {"attachment_id": "a" * 32})).is_error
        url = (await call(work, "memory_sandbox_download", attachment_id=attachment["id"]))["download_url"]
        assert httpx.put(url.replace("/fetch/", "/direct/"), content=b"x").status_code == 403


@pytest.mark.anyio
async def test_results_without_files_have_no_attachment_note(env):
    async with grant_client(env, "notes") as c:
        await call(c, "memory_add", content="zzu plain")
        assert "attachment_note" not in await call(c, "memory_list")
