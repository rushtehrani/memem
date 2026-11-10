-- Ranked keyword search. The index mirrors memories.content and is kept in step by triggers,
-- so every write path updates it in the same statement. It holds only content and rowid:
-- queries join back to memories and filter on space there.
CREATE VIRTUAL TABLE memories_fts USING fts5(
  content,
  content = 'memories',
  content_rowid = 'id',
  tokenize = 'porter unicode61'
);

CREATE TRIGGER memories_fts_insert AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts (rowid, content) VALUES (new.id, new.content);
END;

CREATE TRIGGER memories_fts_delete AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts (memories_fts, rowid, content) VALUES ('delete', old.id, old.content);
END;

CREATE TRIGGER memories_fts_update AFTER UPDATE OF content ON memories BEGIN
  INSERT INTO memories_fts (memories_fts, rowid, content) VALUES ('delete', old.id, old.content);
  INSERT INTO memories_fts (rowid, content) VALUES (new.id, new.content);
END;

INSERT INTO memories_fts (memories_fts) VALUES ('rebuild');
