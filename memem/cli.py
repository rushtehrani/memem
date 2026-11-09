"""Manage who can reach which memory space, in the D1 database."""

import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from datetime import UTC, datetime

_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")


class CliError(Exception):
    pass


def _name(value: str, what: str) -> str:
    # Checked here because these values go into SQL sent through wrangler.
    if not _NAME.fullmatch(value):
        raise CliError(f"{what} must be 1-64 letters, numbers, _ or -")
    return value


def _d1(args, sql: str) -> dict:
    command = ["npx", "--yes", "wrangler", "d1", "execute", "memem", "--json", "--command", sql]
    command.append("--local" if args.local else "--remote")
    if args.persist_to:
        command += ["--persist-to", args.persist_to]
    done = subprocess.run(
        command, capture_output=True, text=True, env={**os.environ, "WRANGLER_SEND_METRICS": "false"}
    )
    if done.returncode != 0:
        output = done.stdout + done.stderr
        if "UNIQUE constraint" in output:
            raise CliError("that connection already exists")
        raise CliError(f"wrangler failed:\n{output.strip()}")
    return json.loads(done.stdout)[0]


def _connect(args) -> None:
    label = _name(args.label, "label")
    space = _name(args.space, "space")
    token = f"memem_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(UTC).isoformat()
    # Only the hash leaves this machine.
    _d1(
        args,
        "INSERT INTO connections (label, token_hash, space, can_write, created_at) VALUES "
        f"('{label}', '{token_hash}', '{space}', {0 if args.read_only else 1}, '{now}')",
    )
    base = (os.environ.get("MEMEM_PUBLIC_URL") or "https://memem.YOUR-SUBDOMAIN.workers.dev").rstrip("/")
    mode = "read-only" if args.read_only else "read/write"
    print(f'Connection "{label}" -> space "{space}" ({mode})')
    print("Shown once. Send it as a bearer token; never put it in a URL.\n")
    print(f"URL:   {base}/mcp")
    print(f"Token: {token}")


def _put_secret(name: str, value: str) -> None:
    done = subprocess.run(
        ["npx", "--yes", "wrangler", "secret", "put", name],
        input=value,
        capture_output=True,
        text=True,
        env={**os.environ, "WRANGLER_SEND_METRICS": "false"},
    )
    if done.returncode != 0:
        raise CliError(f"wrangler failed:\n{(done.stdout + done.stderr).strip()}")


def _set_google(args) -> None:
    email = input("Google account allowed to sign in: ").strip()
    client_id = input("Google OAuth client ID: ").strip()
    client_secret = getpass.getpass("Google OAuth client secret (hidden): ").strip()
    if "@" not in email or not client_id or not client_secret:
        raise CliError("all three values are required")
    _put_secret("MEMEM_OWNER_EMAIL", email)
    _put_secret("GOOGLE_CLIENT_ID", client_id)
    _put_secret("GOOGLE_CLIENT_SECRET", client_secret)
    print(f"Google sign-in is set up for {email}.")


def _list(args) -> None:
    rows = _d1(args, "SELECT label, space, can_write, created_at FROM connections ORDER BY label")
    for c in rows["results"]:
        mode = "read/write" if c["can_write"] else "read-only"
        print(f"{c['label']}\tspace={c['space']}\t{mode}\t{c['created_at']}")


def _revoke(args) -> None:
    label = _name(args.label, "label")
    result = _d1(args, f"DELETE FROM connections WHERE label = '{label}' RETURNING label")
    print(f'Revoked "{label}".' if result["results"] else f'No connection named "{label}".')


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="memem",
        epilog="Set MEMEM_PUBLIC_URL to your Worker's address to print ready-to-paste URLs.",
    )
    parser.add_argument("--local", action="store_true", help="use the local development database")
    parser.add_argument("--persist-to", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    connect = commands.add_parser("connect", help="create a connection and print its URL")
    connect.add_argument("label")
    connect.add_argument("--space", required=True)
    connect.add_argument("--read-only", action="store_true")
    connect.set_defaults(run=_connect)

    commands.add_parser("list", help="show connections").set_defaults(run=_list)

    revoke = commands.add_parser("revoke", help="cut a connection off immediately")
    revoke.add_argument("label")
    revoke.set_defaults(run=_revoke)

    commands.add_parser("set-google", help="set up Google sign-in").set_defaults(run=_set_google)

    args = parser.parse_args()
    try:
        args.run(args)
    except CliError as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
