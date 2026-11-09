CREATE TABLE oauth_pending (
  state_hash     TEXT PRIMARY KEY,
  session_hash   TEXT NOT NULL,
  nonce          TEXT NOT NULL,
  client_id      TEXT NOT NULL,
  redirect_uri   TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  client_state   TEXT NOT NULL,
  resource       TEXT NOT NULL,
  space          TEXT NOT NULL,
  can_write      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);
