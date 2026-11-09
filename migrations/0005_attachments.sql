CREATE TABLE attachments (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id  TEXT NOT NULL UNIQUE,
  memory_id  INTEGER NOT NULL,
  space      TEXT NOT NULL,
  name       TEXT NOT NULL,
  media_type TEXT NOT NULL,
  size       INTEGER NOT NULL,
  r2_key     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  uploading  INTEGER NOT NULL DEFAULT 1,
  deleting   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX attachments_memory ON attachments (memory_id);

CREATE TABLE upload_tokens (
  token_hash  TEXT PRIMARY KEY,
  space       TEXT NOT NULL,
  memory_id   INTEGER NOT NULL,
  description TEXT NOT NULL,
  name        TEXT NOT NULL,
  source      TEXT NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE TABLE web_sessions (
  token_hash TEXT PRIMARY KEY,
  expires_at INTEGER NOT NULL
);
