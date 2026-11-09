CREATE TABLE oauth_clients (
  client_id     TEXT PRIMARY KEY,
  redirect_uris TEXT NOT NULL,
  authorized    INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);

CREATE TABLE oauth_codes (
  code_hash      TEXT PRIMARY KEY,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource       TEXT NOT NULL,
  label          TEXT NOT NULL,
  space          TEXT NOT NULL,
  can_write      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);

-- Static bearer connections keep NULL in these columns and never expire.
ALTER TABLE connections ADD COLUMN client_id TEXT;
ALTER TABLE connections ADD COLUMN access_expires_at INTEGER;
ALTER TABLE connections ADD COLUMN refresh_hash TEXT;
ALTER TABLE connections ADD COLUMN refresh_expires_at INTEGER;

CREATE UNIQUE INDEX connections_refresh ON connections (refresh_hash);
