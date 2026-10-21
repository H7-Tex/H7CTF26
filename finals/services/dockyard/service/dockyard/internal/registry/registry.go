package registry

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BlobPath returns the filesystem path for a digest under root.
func BlobPath(root, digest string) string {
	hex := strings.TrimPrefix(digest, "sha256:")
	if len(hex) < 2 {
		return ""
	}
	return filepath.Join(root, "blobs", "sha256", hex[:2], hex[2:])
}

// StoreBlobFromReader reads from r, writes to the blob store, verifies digest.
// Returns the canonical digest string.
func StoreBlobFromReader(db *sql.DB, blobRoot string, repo string, r io.Reader, expectedDigest string) (string, int64, error) {
	// stream into a temp file, compute hash
	tmp := filepath.Join(blobRoot, "uploads", "tmp-"+randomHex(16))
	if err := os.MkdirAll(filepath.Dir(tmp), 0755); err != nil {
		return "", 0, err
	}
	f, err := os.Create(tmp)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	mw := io.MultiWriter(f, h)
	n, err := io.Copy(mw, r)
	f.Close()
	if err != nil {
		os.Remove(tmp)
		return "", 0, err
	}
	digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
	if expectedDigest != "" && digest != expectedDigest {
		os.Remove(tmp)
		return "", 0, fmt.Errorf("digest mismatch: got %s want %s", digest, expectedDigest)
	}

	dst := BlobPath(blobRoot, digest)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		os.Remove(tmp)
		return "", 0, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return "", 0, err
	}

	if _, err := db.Exec(`INSERT OR IGNORE INTO blobs(digest,size,path) VALUES(?,?,?)`,
		digest, n, dst); err != nil {
		return "", 0, err
	}
	if err := LinkBlob(db, repo, digest); err != nil {
		return "", 0, err
	}
	return digest, n, nil
}

// LinkBlob links an existing blob to a repo (no auth check on source - the mount bug).
func LinkBlob(db *sql.DB, repo, digest string) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO blob_links(repo,digest) VALUES(?,?)`, repo, digest)
	return err
}

// BlobExists checks whether a blob exists globally (not repo-scoped).
func BlobExists(db *sql.DB, digest string) bool {
	var x int
	db.QueryRow(`SELECT 1 FROM blobs WHERE digest=?`, digest).Scan(&x)
	return x == 1
}

// BlobLinkedToRepo checks whether a blob is linked to a specific repo.
func BlobLinkedToRepo(db *sql.DB, repo, digest string) bool {
	var x int
	db.QueryRow(`SELECT 1 FROM blob_links WHERE repo=? AND digest=?`, repo, digest).Scan(&x)
	return x == 1
}

// Mount links a blob from src repo to dst repo.
// BUG: does NOT check pull permission on src. Just checks the blob exists anywhere.
func Mount(db *sql.DB, dstRepo, digest string) (bool, error) {
	if !BlobExists(db, digest) {
		return false, nil
	}
	return true, LinkBlob(db, dstRepo, digest)
}

// CheckAccess checks whether the given token access list grants the required actions
// on the given repo name.
// BUG (V2): splits granted repo names on ',' to support "multi-repo CI tokens".
func CheckAccess(access []AccessEntry, repo string, required []string) bool {
	for _, a := range access {
		if a.Type != "repository" {
			continue
		}
		// BUG: split the name on comma - allows "ns/x,ns/y:pull" to grant both
		granted := strings.Split(a.Name, ",")
		for _, gname := range granted {
			if gname == repo {
				if hasAll(a.Actions, required) {
					return true
				}
			}
		}
	}
	return false
}

// AccessEntry mirrors auth.AccessEntry to avoid import cycles.
type AccessEntry struct {
	Type    string
	Name    string
	Actions []string
}

func hasAll(have, need []string) bool {
	m := make(map[string]bool, len(have))
	for _, h := range have {
		m[h] = true
	}
	for _, n := range need {
		if !m[n] {
			return false
		}
	}
	return true
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := cryptorand.Read(b); err != nil {
		for i := range b {
			b[i] = byte(i)
		}
	}
	return hex.EncodeToString(b)
}
