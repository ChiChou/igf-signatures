PRAGMA user_version = 1;
PRAGMA foreign_keys = ON;
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE sources (
  id INTEGER PRIMARY KEY,
  platform TEXT NOT NULL,
  sdk TEXT NOT NULL,
  version TEXT NOT NULL,
  revision TEXT NOT NULL,
  url TEXT NOT NULL,
  compiler TEXT NOT NULL
);
CREATE TABLE types (
  id INTEGER PRIMARY KEY,
  c_spelling TEXT NOT NULL,
  canonical_c TEXT NOT NULL,
  frida_type TEXT NOT NULL CHECK(json_valid(frida_type)),
  size INTEGER,
  display_hint TEXT NOT NULL,
  approximate INTEGER NOT NULL CHECK(approximate IN (0, 1))
);
CREATE TABLE functions (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL REFERENCES sources(id),
  platform TEXT NOT NULL,
  arch TEXT NOT NULL,
  module TEXT NOT NULL,
  symbol TEXT NOT NULL,
  name TEXT NOT NULL,
  return_type_id INTEGER NOT NULL REFERENCES types(id),
  variadic INTEGER NOT NULL CHECK(variadic IN (0, 1)),
  header TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('function', 'syscall')),
  UNIQUE(source_id, platform, arch, module, symbol, kind)
);
CREATE INDEX functions_lookup ON functions(platform, symbol, arch, module);
CREATE TABLE parameters (
  function_id INTEGER NOT NULL REFERENCES functions(id),
  position INTEGER NOT NULL,
  name TEXT NOT NULL,
  type_id INTEGER NOT NULL REFERENCES types(id),
  PRIMARY KEY(function_id, position)
) WITHOUT ROWID;
CREATE TABLE syscalls (
  source_id INTEGER NOT NULL REFERENCES sources(id),
  arch TEXT NOT NULL,
  number INTEGER NOT NULL,
  name TEXT NOT NULL,
  function_id INTEGER REFERENCES functions(id),
  PRIMARY KEY(source_id, arch, number)
) WITHOUT ROWID;
CREATE INDEX syscalls_name ON syscalls(name, arch);
