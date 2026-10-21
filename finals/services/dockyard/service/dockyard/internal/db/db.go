package db

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3"
)

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := migrate(db); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY,
	username      TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repos (
	id         INTEGER PRIMARY KEY,
	name       TEXT UNIQUE NOT NULL,
	owner      TEXT NOT NULL,
	visibility TEXT NOT NULL DEFAULT 'private'
);
CREATE TABLE IF NOT EXISTS repo_members (
	repo     TEXT NOT NULL,
	username TEXT NOT NULL,
	role     TEXT NOT NULL DEFAULT 'reader',
	PRIMARY KEY(repo, username)
);
CREATE TABLE IF NOT EXISTS blobs (
	digest TEXT PRIMARY KEY,
	size   INTEGER NOT NULL,
	path   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS blob_links (
	repo   TEXT NOT NULL,
	digest TEXT NOT NULL,
	PRIMARY KEY(repo, digest)
);
CREATE TABLE IF NOT EXISTS uploads (
	uuid       TEXT PRIMARY KEY,
	repo       TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS manifests (
	repo         TEXT NOT NULL,
	ref          TEXT NOT NULL,
	digest       TEXT NOT NULL,
	content      BLOB NOT NULL,
	content_type TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	PRIMARY KEY(repo, ref)
);
CREATE TABLE IF NOT EXISTS repo_secrets (
	repo  TEXT NOT NULL,
	key   TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY(repo, key)
);
CREATE TABLE IF NOT EXISTS watches (
	id         TEXT PRIMARY KEY,
	repo       TEXT NOT NULL,
	url        TEXT NOT NULL,
	template   TEXT NOT NULL,
	created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
	id         TEXT PRIMARY KEY,
	watch_id   TEXT NOT NULL,
	rendered   TEXT NOT NULL,
	status     INTEGER NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fine_tokens (
	id     TEXT PRIMARY KEY,
	owner  TEXT NOT NULL,
	name   TEXT NOT NULL,
	scopes TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS log_entries (
	n          INTEGER PRIMARY KEY AUTOINCREMENT,
	repo       TEXT NOT NULL,
	tag        TEXT NOT NULL,
	digest     TEXT NOT NULL,
	ts         INTEGER NOT NULL,
	entry_type TEXT NOT NULL DEFAULT 'push'
);
CREATE TABLE IF NOT EXISTS log_keys (
	kid   TEXT PRIMARY KEY,
	owner TEXT NOT NULL,
	pub   TEXT NOT NULL
);
`)
	return err
}
