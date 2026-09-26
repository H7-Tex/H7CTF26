CREATE ROLE app LOGIN PASSWORD 'app';
CREATE ROLE rollup_owner NOLOGIN;

CREATE TABLE bases (
  id text PRIMARY KEY,
  team text NOT NULL,
  name text NOT NULL,
  tbl text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE field_meta (
  base_id text NOT NULL,
  field_id text NOT NULL,
  col_ident text NOT NULL,
  label text NOT NULL,
  position int NOT NULL DEFAULT 0,
  PRIMARY KEY (base_id, field_id)
);

CREATE TABLE base_rollup (
  base_id text PRIMARY KEY,
  fingerprint text,
  note text,
  computed_at timestamptz
);

CREATE TABLE vault (
  team text PRIMARY KEY,
  license_key text NOT NULL
);
ALTER TABLE vault OWNER TO rollup_owner;

GRANT USAGE, CREATE ON SCHEMA public TO app;
GRANT SELECT, INSERT, UPDATE, DELETE ON bases, field_meta, base_rollup TO app;

GRANT SELECT ON field_meta TO rollup_owner;
GRANT SELECT, INSERT, UPDATE ON base_rollup TO rollup_owner;

REVOKE ALL ON vault FROM PUBLIC;
