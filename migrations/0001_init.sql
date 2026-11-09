CREATE TABLE connections (
  label      TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  space      TEXT NOT NULL,
  can_write  INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE memories (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  space      TEXT NOT NULL,
  content    TEXT NOT NULL,
  source     TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX memories_space ON memories (space, id);
