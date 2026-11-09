ALTER TABLE memories ADD COLUMN updated_at TEXT;
ALTER TABLE memories ADD COLUMN updated_by TEXT;
ALTER TABLE memories ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;

CREATE INDEX memories_pinned ON memories (space) WHERE pinned = 1;
