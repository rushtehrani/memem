-- Earlier versions of memories, and memories that were deleted, kept for 30 days so changes can be undone.
-- Triggers record every edit and deletion, whichever code path made it. A pin-only change is not a new version.
CREATE TABLE memory_versions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  memory_id   INTEGER NOT NULL,
  space       TEXT NOT NULL,
  content     TEXT NOT NULL,
  source      TEXT NOT NULL,
  created_at  TEXT NOT NULL,
  pinned      INTEGER NOT NULL,
  written_by  TEXT NOT NULL,
  changed_by  TEXT,
  kind        TEXT NOT NULL CHECK (kind IN ('edit', 'delete')),
  replaced_at TEXT NOT NULL
);

CREATE INDEX memory_versions_space ON memory_versions (space, id);
CREATE INDEX memory_versions_memory ON memory_versions (space, memory_id, id);
CREATE INDEX memory_versions_age ON memory_versions (replaced_at);

CREATE TRIGGER memory_versions_edit AFTER UPDATE OF content ON memories WHEN old.content IS NOT new.content BEGIN
  INSERT INTO memory_versions
    (memory_id, space, content, source, created_at, pinned, written_by, changed_by, kind, replaced_at)
  VALUES
    (old.id, old.space, old.content, old.source, old.created_at, old.pinned, COALESCE(old.updated_by, old.source),
     new.updated_by, 'edit', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END;

CREATE TRIGGER memory_versions_delete AFTER DELETE ON memories BEGIN
  INSERT INTO memory_versions
    (memory_id, space, content, source, created_at, pinned, written_by, changed_by, kind, replaced_at)
  VALUES
    (old.id, old.space, old.content, old.source, old.created_at, old.pinned, COALESCE(old.updated_by, old.source),
     NULL, 'delete', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
END;
