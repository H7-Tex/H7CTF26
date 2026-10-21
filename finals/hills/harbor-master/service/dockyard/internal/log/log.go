package log

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Entry is one record in the transparency log.
type Entry struct {
	N         int64  `json:"n"`
	Repo      string `json:"repo"`
	Tag       string `json:"tag"`
	Digest    string `json:"digest"`
	Ts        int64  `json:"ts"`
	EntryType string `json:"type"`
}

// TreeHead holds the current signed tree state.
type TreeHead struct {
	Size int64  `json:"size"`
	Root string `json:"root"`
	Sig  string `json:"sig"`
}

// Append inserts a push event into the log.
func Append(db *sql.DB, repo, tag, digest string) error {
	_, err := db.Exec(
		`INSERT INTO log_entries(repo,tag,digest,ts,entry_type) VALUES(?,?,?,?,'push')`,
		repo, tag, digest, time.Now().Unix(),
	)
	return err
}

// AppendAttestation inserts an attestation event.
func AppendAttestation(db *sql.DB, repo, tag, digest string) error {
	_, err := db.Exec(
		`INSERT INTO log_entries(repo,tag,digest,ts,entry_type) VALUES(?,?,?,?,'attest')`,
		repo, tag, digest, time.Now().Unix(),
	)
	return err
}

// GetEntry returns entry n (1-based).
func GetEntry(db *sql.DB, n int64) (*Entry, error) {
	var e Entry
	err := db.QueryRow(
		`SELECT n,repo,tag,digest,ts,entry_type FROM log_entries WHERE n=?`, n,
	).Scan(&e.N, &e.Repo, &e.Tag, &e.Digest, &e.Ts, &e.EntryType)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &e, err
}

// GetTree returns the current signed tree head.
func GetTree(db *sql.DB, privKey ed25519.PrivateKey) (*TreeHead, error) {
	rows, err := db.Query(`SELECT n,repo,tag,digest,ts,entry_type FROM log_entries ORDER BY n`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	h := sha256.New()
	var size int64
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.N, &e.Repo, &e.Tag, &e.Digest, &e.Ts, &e.EntryType); err != nil {
			return nil, err
		}
		b, _ := json.Marshal(e)
		// hash each entry into the running hash (simple sequential Merkle)
		leaf := sha256.Sum256(b)
		h.Write(leaf[:])
		size = e.N
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	root := hex.EncodeToString(h.Sum(nil))
	sig := ed25519.Sign(privKey, []byte(fmt.Sprintf("%d:%s", size, root)))

	return &TreeHead{
		Size: size,
		Root: root,
		Sig:  base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// RegisterKey stores a publisher signing key in the log.
func RegisterKey(db *sql.DB, kid, owner, pubHex string) error {
	_, err := db.Exec(
		`INSERT OR REPLACE INTO log_keys(kid,owner,pub) VALUES(?,?,?)`,
		kid, owner, pubHex,
	)
	return err
}

// GetKey looks up a publisher key by kid.
func GetKey(db *sql.DB, kid string) (string, error) {
	var pub string
	err := db.QueryRow(`SELECT pub FROM log_keys WHERE kid=?`, kid).Scan(&pub)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return pub, err
}
