"""D1 storage for connections and memories."""

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from js import Object
from pyodide.ffi import to_js

MAX_MEMORIES_PER_SPACE = 10_000
MAX_ATTACHMENTS_PER_MEMORY = 20
MAX_OVERVIEW_FILES = 10
# Written into the SQL directly, because D1 fails on integers this large bound from Python.
MAX_TOTAL_FILE_BYTES = 5 * 1024**3
ABANDONED_UPLOAD_AGE = 3600
DOWNLOAD_LOG_AGE = 90 * 24 * 3600
MAX_QUERY_WORDS = 20
CANDIDATES = 50
# Measured on bge-base-en-v1.5: relevant queries scored 0.55 or more, unrelated ones 0.50 or less.
MIN_SIMILARITY = 0.52
MAX_SIMILAR = 3
SIMILAR_PREVIEW_CHARS = 500
RANK_CONSTANT = 60
# Every chat reads the pinned notes first, so they must stay small.
MAX_PINNED_CHARS = 4_000
MAX_PINNED_ROWS = 100
_MEMORY_VECTOR = "m:"  # Other kinds of searchable content will use their own prefix.
_COLUMNS = "id, content, source, created_at, updated_at, updated_by, pinned"
_STOP_WORDS = frozenset(
    "the and for are but not you all any can had her was one our out has him his how its may new now "
    "see two who did get let put say she too use what when where which why with would could should "
    "about from have that them then there these they this will your does been into more some than".split()
)
MAX_OAUTH_CLIENTS = 1_000
UNUSED_CLIENT_TTL = 24 * 3600


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


class AlreadySaved(Exception):
    def __init__(self, memory_id: int):
        super().__init__("This exact memory is already saved.")
        self.memory_id = memory_id


class SpaceFull(Exception):
    pass


class PinnedFull(SpaceFull):
    pass


class AttachmentRefused(Exception):
    pass


@dataclass(frozen=True)
class Connection:
    label: str
    space: str
    can_write: bool


def _search_words(query: str) -> list[str]:
    """Words worth matching. Substring search would make "i" or "the" match nearly everything."""
    words = [w.strip("?!.,:;\"'()") for w in query.split()]
    useful = [w for w in words if len(w) >= 3 and w.lower() not in _STOP_WORDS]
    return (useful or [w for w in words if w])[:MAX_QUERY_WORDS]


def _like(word: str) -> str:
    escaped = word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


class Store:
    def __init__(self, db, semantic=None, files=None, origin=""):
        self._db = db
        self._semantic = semantic
        self.files = files
        self.origin = origin

    async def _all(self, sql: str, *params) -> list[dict]:
        result = await self._db.prepare(sql).bind(*params).all()
        rows = result.results
        return rows.to_py() if hasattr(rows, "to_py") else rows

    async def create_client(self, client_id: str, redirect_uris: list[str]) -> bool:
        now = int(time.time())
        # Registration is open, so unused registrations expire and the total is capped.
        await self._all(
            "DELETE FROM oauth_clients WHERE authorized = 0 AND created_at < ? RETURNING client_id",
            now - UNUSED_CLIENT_TTL,
        )
        rows = await self._all(
            "INSERT INTO oauth_clients (client_id, redirect_uris, created_at)"
            " SELECT ?, ?, ? WHERE (SELECT COUNT(*) FROM oauth_clients) < ?"
            " RETURNING client_id",
            client_id,
            json.dumps(redirect_uris),
            now,
            MAX_OAUTH_CLIENTS,
        )
        return bool(rows)

    async def client_redirects(self, client_id: str) -> list[str] | None:
        rows = await self._all("SELECT redirect_uris FROM oauth_clients WHERE client_id = ?", client_id)
        return json.loads(rows[0]["redirect_uris"]) if rows else None

    async def create_pending(self, **row) -> None:
        await self._all(
            "DELETE FROM oauth_pending WHERE expires_at <= ? RETURNING state_hash", int(time.time())
        )
        row["can_write"] = int(row["can_write"])
        columns = ", ".join(row)
        marks = ", ".join("?" * len(row))
        await self._all(
            f"INSERT INTO oauth_pending ({columns}) VALUES ({marks}) RETURNING state_hash", *row.values()
        )

    async def claim_pending(self, state_hash: str) -> dict | None:
        rows = await self._all(
            "DELETE FROM oauth_pending WHERE state_hash = ? AND expires_at > ? RETURNING *",
            state_hash,
            int(time.time()),
        )
        return rows[0] if rows else None

    async def create_code(
        self,
        code_hash: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        resource: str,
        label: str,
        space: str,
        can_write: bool,
        expires_at: int,
    ) -> None:
        await self._all(
            "DELETE FROM oauth_codes WHERE expires_at <= ? RETURNING code_hash", int(time.time())
        )
        await self._all(
            "UPDATE oauth_clients SET authorized = 1 WHERE client_id = ? RETURNING client_id", client_id
        )
        await self._all(
            "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, resource,"
            " label, space, can_write, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING code_hash",
            code_hash,
            client_id,
            redirect_uri,
            code_challenge,
            resource,
            label,
            space,
            int(can_write),
            expires_at,
        )

    async def claim_code(self, code_hash: str) -> dict | None:
        rows = await self._all(
            "DELETE FROM oauth_codes WHERE code_hash = ? AND expires_at > ? RETURNING *",
            code_hash,
            int(time.time()),
        )
        return rows[0] if rows else None

    async def create_grant(self, code: dict, tokens: dict) -> None:
        now = int(time.time())
        await self._all(
            "DELETE FROM connections WHERE refresh_expires_at <= ? RETURNING label", now
        )
        await self._all(
            "INSERT INTO connections (label, token_hash, space, can_write, created_at, client_id,"
            " access_expires_at, refresh_hash, refresh_expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING label",
            code["label"],
            _hash(tokens["access"]),
            code["space"],
            code["can_write"],
            datetime.now(UTC).isoformat(),
            code["client_id"],
            tokens["access_expires_at"],
            _hash(tokens["refresh"]),
            tokens["refresh_expires_at"],
        )

    async def rotate_grant(self, refresh_hash: str, client_id: str, tokens: dict) -> bool:
        # One statement, so a refresh token can be spent only once.
        rows = await self._all(
            "UPDATE connections SET token_hash = ?, refresh_hash = ?, access_expires_at = ?,"
            " refresh_expires_at = ? WHERE refresh_hash = ? AND client_id = ? AND refresh_expires_at > ?"
            " RETURNING label",
            _hash(tokens["access"]),
            _hash(tokens["refresh"]),
            tokens["access_expires_at"],
            tokens["refresh_expires_at"],
            refresh_hash,
            client_id,
            int(time.time()),
        )
        return bool(rows)

    async def authenticate(self, token: str) -> Connection | None:
        rows = await self._all(
            "SELECT label, space, can_write FROM connections WHERE token_hash = ?"
            " AND (access_expires_at IS NULL OR access_expires_at > ?)",
            _hash(token),
            int(time.time()),
        )
        if not rows:
            return None
        return Connection(rows[0]["label"], rows[0]["space"], bool(rows[0]["can_write"]))

    async def _guarded(self, step) -> object | None:
        """Meaning search is an extra: if it fails, memories still save and keywords still work."""
        if self._semantic is None:
            return None
        try:
            return await step()
        except Exception as err:
            print("semantic search failed:", type(err).__name__)
            return None

    async def _add_vector(self, space: str, memory_id: int, content: str) -> bool:
        await self._semantic.add(space, f"{_MEMORY_VECTOR}{memory_id}", content)
        return True

    async def _remove_vector(self, memory_id: int) -> None:
        await self._guarded(lambda: self._semantic.remove(f"{_MEMORY_VECTOR}{memory_id}"))

    async def remember(self, space: str, content: str, source: str, unique: bool = False) -> int:
        duplicate, duplicate_params = (
            (" AND NOT EXISTS (SELECT 1 FROM memories WHERE space = ? AND content = ?)", [space, content])
            if unique
            else ("", [])
        )
        # One statement, so concurrent writers cannot push a space past its cap or save the same memory twice.
        rows = await self._all(
            "INSERT INTO memories (space, content, source, created_at)"
            " SELECT ?, ?, ?, ?"
            f" WHERE (SELECT COUNT(*) FROM memories WHERE space = ?) < ?{duplicate}"
            " RETURNING id",
            space,
            content,
            source,
            datetime.now(UTC).isoformat(),
            space,
            MAX_MEMORIES_PER_SPACE,
            *duplicate_params,
        )
        if not rows:
            if unique:
                existing = await self._all(
                    "SELECT id FROM memories WHERE space = ? AND content = ? LIMIT 1", space, content
                )
                if existing:
                    raise AlreadySaved(existing[0]["id"])
            raise SpaceFull("This memory space is full. Forget something first.")
        memory_id = rows[0]["id"]
        await self._guarded(lambda: self._add_vector(space, memory_id, content))
        return memory_id

    async def similar(self, space: str, content: str, memory_id: int) -> list[dict]:
        """Short previews of other memories close in meaning, so a new one can be merged instead of piling up."""
        ids = [found for found in await self._meaning_matches(space, content) if found != memory_id][:MAX_SIMILAR]
        rows = {row["id"]: row for row in await self._rows_by_id(space, ids)}
        return [
            {
                "id": found,
                "content": rows[found]["content"][:SIMILAR_PREVIEW_CHARS],
                "created_at": rows[found]["created_at"],
            }
            for found in ids
            if found in rows
        ]

    async def update(
        self, space: str, memory_id: int, editor: str, content: str | None, pinned: bool | None
    ) -> bool:
        # Unchanged fields are left out of the SQL because D1 cannot bind None from Python.
        text, text_params = ("?", [content]) if content is not None else ("content", [])
        pin, pin_params = ("?", [int(pinned)]) if pinned is not None else ("pinned", [])
        # One statement, so concurrent writers cannot push the pinned notes past their budget.
        rows = await self._all(
            f"UPDATE memories SET content = {text}, pinned = {pin}, updated_at = ?, updated_by = ?"
            f" WHERE space = ? AND id = ? AND ({pin} = 0 OR LENGTH({text}) + (SELECT COALESCE(SUM(LENGTH(content)), 0)"
            " FROM memories WHERE space = ? AND pinned = 1 AND id <> ?) <= ?) RETURNING id",
            *text_params,
            *pin_params,
            datetime.now(UTC).isoformat(),
            editor,
            space,
            memory_id,
            *pin_params,
            *text_params,
            space,
            memory_id,
            MAX_PINNED_CHARS,
        )
        if not rows:
            if await self._all("SELECT id FROM memories WHERE space = ? AND id = ?", space, memory_id):
                raise PinnedFull("Pinned notes are full. Unpin or shorten something first.")
            return False
        if content is not None:
            # An old vector must not keep matching text that is gone.
            if not await self._guarded(lambda: self._add_vector(space, memory_id, content)):
                await self._remove_vector(memory_id)
        return True

    async def overview(self, space: str) -> dict:
        pinned = await self._all(
            f"SELECT {_COLUMNS} FROM memories WHERE space = ? AND pinned = 1 ORDER BY id DESC LIMIT ?",
            space,
            MAX_PINNED_ROWS,
        )
        count = await self._all("SELECT COUNT(*) AS total FROM memories WHERE space = ?", space)
        result = {"total": count[0]["total"], "pinned": await self._with_attachments(space, pinned)}
        files = await self._all(
            "SELECT public_id AS id, memory_id, name FROM attachments"
            " WHERE space = ? AND uploading = 0 AND deleting = 0 ORDER BY attachments.id DESC LIMIT ?",
            space,
            MAX_OVERVIEW_FILES,
        )
        if files:
            attached = await self._all(
                "SELECT COUNT(*) AS total FROM attachments WHERE space = ? AND uploading = 0 AND deleting = 0", space
            )
            result["attachment_count"], result["recent_files"] = attached[0]["total"], files
        return result

    async def _with_attachments(self, space: str, memories: list[dict]) -> list[dict]:
        if not memories:
            return memories
        marks = ", ".join("?" * len(memories))
        rows = await self._all(
            "SELECT memory_id, public_id, name, media_type, size FROM attachments"
            f" WHERE space = ? AND uploading = 0 AND deleting = 0 AND memory_id IN ({marks}) ORDER BY id",
            space,
            *[memory["id"] for memory in memories],
        )
        for row in rows:
            memory = next(m for m in memories if m["id"] == row["memory_id"])
            memory.setdefault("attachments", []).append(
                {
                    "id": row["public_id"],
                    "name": row["name"],
                    "media_type": row["media_type"],
                    "size": row["size"],
                    "browser_download_url": f"{self.origin}/files/download/{row['public_id']}",
                }
            )
        return memories

    async def memory_exists(self, space: str, memory_id: int) -> bool:
        return bool(await self._all("SELECT id FROM memories WHERE space = ? AND id = ?", space, memory_id))

    async def memory_with_attachments(self, memory_id: int) -> tuple[dict, list[dict]] | None:
        """For the signed-in owner's file page, which is not limited to one space."""
        memories = await self._all(f"SELECT space, {_COLUMNS} FROM memories WHERE id = ?", memory_id)
        if not memories:
            return None
        rows = await self._all(
            "SELECT public_id, name, size FROM attachments"
            " WHERE memory_id = ? AND uploading = 0 AND deleting = 0 ORDER BY id",
            memory_id,
        )
        return memories[0], rows

    async def reserve_attachment(self, memory_id: int, public_id: str, name: str, media_type: str, size: int, r2_key: str) -> None:
        now = int(time.time())
        await self._all(
            "UPDATE attachments SET deleting = 1 WHERE uploading = 1 AND created_at < ? RETURNING id",
            now - ABANDONED_UPLOAD_AGE,
        )
        await self.sweep_files()
        # One statement, so concurrent uploads cannot pass either limit.
        rows = await self._all(
            "INSERT INTO attachments (public_id, memory_id, space, name, media_type, size, r2_key, created_at)"
            " SELECT ?, id, space, ?, ?, ?, ?, ? FROM memories WHERE id = ?"
            " AND (SELECT COUNT(*) FROM attachments WHERE memory_id = ? AND deleting = 0) < ?"
            f" AND (SELECT COALESCE(SUM(size), 0) FROM attachments WHERE deleting = 0) + ? <= {MAX_TOTAL_FILE_BYTES}"
            " RETURNING id",
            public_id,
            name,
            media_type,
            size,
            r2_key,
            now,
            memory_id,
            memory_id,
            MAX_ATTACHMENTS_PER_MEMORY,
            size,
        )
        if rows:
            return
        if await self._all("SELECT id FROM memories WHERE id = ?", memory_id):
            raise AttachmentRefused(
                f"A memory can have {MAX_ATTACHMENTS_PER_MEMORY} files, and file storage has a size limit. "
                "Remove something first."
            )
        raise LookupError

    async def finish_attachment(self, public_id: str) -> None:
        await self._all("UPDATE attachments SET uploading = 0 WHERE public_id = ? RETURNING id", public_id)

    async def discard_attachment(self, public_id: str) -> bool:
        rows = await self._all(
            "UPDATE attachments SET deleting = 1 WHERE public_id = ? AND deleting = 0 RETURNING id", public_id
        )
        await self.sweep_files()
        return bool(rows)

    async def attachment(self, public_id: str) -> dict | None:
        rows = await self._all(
            "SELECT name, size, r2_key FROM attachments WHERE public_id = ? AND uploading = 0 AND deleting = 0",
            public_id,
        )
        return rows[0] if rows else None

    async def sweep_files(self) -> None:
        """Remove files marked for deletion. Rows stay marked until R2 confirms, so a failure is retried."""
        if self.files is None:
            return
        rows = await self._all("SELECT id, r2_key FROM attachments WHERE deleting = 1 LIMIT 100")
        if not rows:
            return
        try:
            await self.files.delete(to_js([row["r2_key"] for row in rows], dict_converter=Object.fromEntries))
        except Exception as err:
            print("file delete failed:", type(err).__name__)
            return
        marks = ", ".join("?" * len(rows))
        await self._all(f"DELETE FROM attachments WHERE id IN ({marks}) RETURNING id", *[row["id"] for row in rows])

    async def create_upload_token(self, token_hash: str, space: str, memory_id: int, description: str, name: str, source: str, expires_at: int) -> None:
        await self._all("DELETE FROM upload_tokens WHERE expires_at <= ? RETURNING token_hash", int(time.time()))
        await self._all(
            "INSERT INTO upload_tokens (token_hash, space, memory_id, description, name, source, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING token_hash",
            token_hash,
            space,
            memory_id,
            description,
            name,
            source,
            expires_at,
        )

    async def claim_upload_token(self, token_hash: str) -> dict | None:
        # Claiming deletes the token, so a link works only once.
        rows = await self._all(
            "DELETE FROM upload_tokens WHERE token_hash = ? AND expires_at > ? RETURNING *",
            token_hash,
            int(time.time()),
        )
        return rows[0] if rows else None

    async def attachment_in_space(self, space: str, public_id: str) -> bool:
        rows = await self._all(
            "SELECT id FROM attachments WHERE space = ? AND public_id = ? AND uploading = 0 AND deleting = 0",
            space,
            public_id,
        )
        return bool(rows)

    async def create_download_link(self, token_hash: str, public_id: str, source: str, ttl: int) -> None:
        now = int(time.time())
        await self._all(
            "DELETE FROM download_links WHERE requested_at < ? RETURNING token_hash", now - DOWNLOAD_LOG_AGE
        )
        await self._all(
            "INSERT INTO download_links (token_hash, public_id, source, requested_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?) RETURNING token_hash",
            token_hash,
            public_id,
            source,
            now,
            now + ttl,
        )

    async def claim_download_link(self, token_hash: str) -> dict | None:
        # One statement, so a link can be spent only once. The row stays as the download log.
        now = int(time.time())
        rows = await self._all(
            "UPDATE download_links SET fetched_at = ? WHERE token_hash = ? AND expires_at > ? AND fetched_at = 0"
            " RETURNING public_id",
            now,
            token_hash,
            now,
        )
        return rows[0] if rows else None

    async def download_activity(self, memory_id: int) -> list[dict]:
        return await self._all(
            "SELECT a.name, d.source, d.requested_at, d.fetched_at FROM download_links d"
            " JOIN attachments a ON a.public_id = d.public_id"
            " WHERE a.memory_id = ? ORDER BY d.requested_at DESC LIMIT 20",
            memory_id,
        )

    async def create_web_session(self, token_hash: str, expires_at: int) -> None:
        await self._all("DELETE FROM web_sessions WHERE expires_at <= ? RETURNING token_hash", int(time.time()))
        await self._all(
            "INSERT INTO web_sessions (token_hash, expires_at) VALUES (?, ?) RETURNING token_hash",
            token_hash,
            expires_at,
        )

    async def web_session_valid(self, token_hash: str) -> bool:
        rows = await self._all(
            "SELECT token_hash FROM web_sessions WHERE token_hash = ? AND expires_at > ?",
            token_hash,
            int(time.time()),
        )
        return bool(rows)
    async def browse(self, space: str, before_id: int | None, limit: int) -> tuple[list[dict], int | None]:
        """Newest first. Also returns the id to continue from, if there is more."""
        below, below_params = (" AND id < ?", [before_id]) if before_id is not None else ("", [])
        rows = await self._all(
            f"SELECT {_COLUMNS} FROM memories WHERE space = ?{below} ORDER BY id DESC LIMIT ?",
            space,
            *below_params,
            limit + 1,
        )
        more = rows[limit - 1]["id"] if len(rows) > limit else None
        return await self._with_attachments(space, rows[:limit]), more

    async def _keyword_matches(self, space: str, query: str) -> list[dict]:
        words = _search_words(query)
        if not words:
            return []
        return await self._ranked_keyword_matches(space, words) or await self._substring_matches(space, words)

    async def _ranked_keyword_matches(self, space: str, words: list[str]) -> list[dict]:
        """BM25 ranking, so rare words count for more than common ones, and word forms like moved and moving match."""
        # Each word is quoted, so nothing in a query can act as full-text search syntax.
        match = " OR ".join('"' + word.replace('"', '""') + '"' for word in words)
        try:
            return await self._all(
                "SELECT m.id, m.content, m.source, m.created_at FROM memories_fts"
                " JOIN memories m ON m.id = memories_fts.rowid"
                " WHERE memories_fts MATCH ? AND m.space = ?"
                " ORDER BY bm25(memories_fts), m.id DESC LIMIT ?",
                match,
                space,
                CANDIDATES,
            )
        except Exception as err:
            print("ranked keyword search failed:", type(err).__name__)
            return []

    async def _substring_matches(self, space: str, words: list[str]) -> list[dict]:
        """Finds parts of words, like Prime in PrimeYou, and text the word index splits poorly, such as Chinese."""
        score = " + ".join(["(content LIKE ? ESCAPE '\\')"] * len(words))
        return await self._all(
            f"SELECT id, content, source, created_at, {score} AS score FROM memories"
            " WHERE space = ? AND score > 0 ORDER BY score DESC, id DESC LIMIT ?",
            *[_like(word) for word in words],
            space,
            CANDIDATES,
        )

    async def _meaning_matches(self, space: str, query: str) -> list[int]:
        matches = await self._guarded(lambda: self._semantic.query(space, query, CANDIDATES)) or []
        return [
            int(vector_id.removeprefix(_MEMORY_VECTOR))
            for vector_id, score in matches
            if vector_id.startswith(_MEMORY_VECTOR) and score >= MIN_SIMILARITY
        ]

    async def _rows_by_id(self, space: str, ids: list[int]) -> list[dict]:
        if not ids:
            return []
        # Filtering on space here means a stale or wrong vector can never expose another space.
        marks = ", ".join("?" * len(ids))
        return await self._all(
            f"SELECT {_COLUMNS} FROM memories WHERE space = ? AND id IN ({marks})",
            space,
            *ids,
        )

    async def recall(self, space: str, query: str, limit: int) -> list[dict]:
        """Keyword and meaning results combined."""
        keyword_rows = await self._keyword_matches(space, query)
        meaning_ids = await self._meaning_matches(space, query)

        # Reciprocal rank fusion: being near the top of either list counts, and of both counts more.
        scores: dict[int, float] = {}
        for ranked in ([row["id"] for row in keyword_rows], meaning_ids):
            for rank, memory_id in enumerate(ranked):
                scores[memory_id] = scores.get(memory_id, 0) + 1 / (RANK_CONSTANT + rank)
        best = sorted(scores, key=lambda memory_id: (-scores[memory_id], -memory_id))[:limit]

        rows = {row["id"]: row for row in await self._rows_by_id(space, best)}
        return await self._with_attachments(space, [rows[memory_id] for memory_id in best if memory_id in rows])

    async def forget(self, space: str, memory_id: int) -> bool:
        rows = await self._all(
            "DELETE FROM memories WHERE space = ? AND id = ? RETURNING id", space, memory_id
        )
        if not rows:
            return False
        await self._all(
            "UPDATE attachments SET deleting = 1 WHERE space = ? AND memory_id = ? RETURNING id", space, memory_id
        )
        await self._remove_vector(memory_id)
        await self.sweep_files()
        return True
