CREATE TABLE download_links (
  token_hash   TEXT PRIMARY KEY,
  public_id    TEXT NOT NULL,
  source       TEXT NOT NULL,
  requested_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  fetched_at   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX download_links_file ON download_links (public_id, requested_at);
