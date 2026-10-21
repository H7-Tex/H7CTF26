package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
)

// giteaPush is the relevant subset of a Gitea push webhook payload.
type giteaPush struct {
	Ref    string `json:"ref"`
	After  string `json:"after"` // new commit SHA
	Pusher struct {
		Login string `json:"login"`
	} `json:"pusher"`
	HeadCommit struct {
		Added    []string `json:"added"`
		Modified []string `json:"modified"`
		Removed  []string `json:"removed"`
	} `json:"head_commit"`
}

func makeWebhookHandler(cfg *Config, st *State) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", 405)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
		if err != nil {
			http.Error(w, "read", 400)
			return
		}

		// HMAC verification
		if cfg.WebhookSecret != "" {
			sig := r.Header.Get("X-Gitea-Signature")
			if !verifyGiteaHMAC(cfg.WebhookSecret, body, sig) {
				log.Printf("webhook: HMAC mismatch from %s", r.RemoteAddr)
				http.Error(w, "forbidden", 403)
				return
			}
		}

		if r.Header.Get("X-Gitea-Event") != "push" {
			w.WriteHeader(204)
			return
		}

		var payload giteaPush
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, "bad json", 400)
			return
		}

		// only main branch
		if payload.Ref != "refs/heads/main" {
			w.WriteHeader(204)
			return
		}

		sha := payload.After
		if sha == "" || strings.Contains(sha, "0000000") {
			w.WriteHeader(204)
			return
		}

		// find changed top-level dirs (services)
		seen := map[string]struct{}{}
		for _, f := range append(append(payload.HeadCommit.Added, payload.HeadCommit.Modified...), payload.HeadCommit.Removed...) {
			parts := strings.SplitN(f, "/", 2)
			if len(parts) > 0 && parts[0] != "" && parts[0] != ".h7" {
				seen[parts[0]] = struct{}{}
			}
		}

		// if HeadCommit files are empty (some Gitea versions omit them), use all services
		if len(seen) == 0 {
			svcs, err := changedServices(cfg.RepoPath, "", sha)
			if err == nil {
				for _, s := range svcs {
					seen[s] = struct{}{}
				}
			}
		}

		for svc := range seen {
			pq.enqueue(svc, sha)
			log.Printf("webhook: queued %s@%s", svc, sha[:8])
		}

		w.WriteHeader(200)
	}
}

func verifyGiteaHMAC(secret string, body []byte, sig string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sig))
}
