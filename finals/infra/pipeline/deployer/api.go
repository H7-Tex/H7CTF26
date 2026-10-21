package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// authMiddleware enforces Bearer token on the team API.
func authMiddleware(next http.Handler, token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != token {
				http.Error(w, "forbidden", 403)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func registerAPIRoutes(mux *http.ServeMux, cfg *Config, st *State) {
	anvil := newAnvilClient(cfg)

	// GET /logs/<svc>?since=10m&follow=1
	mux.HandleFunc("/logs/", func(w http.ResponseWriter, r *http.Request) {
		svc := strings.TrimPrefix(r.URL.Path, "/logs/")
		if svc == "" {
			http.Error(w, "missing service", 400)
			return
		}
		since := r.URL.Query().Get("since")
		if since == "" {
			since = "10m"
		}
		composeFile := fmt.Sprintf("%s/%s/docker-compose.yml", cfg.ServiceRoot, svc)
		args := []string{"compose", "-p", cfg.ComposeProject, "-f", composeFile,
			"logs", "--timestamps", "--since", since}
		if r.URL.Query().Get("follow") == "1" {
			args = append(args, "-f")
		}
		args = append(args, svc)
		cmd := exec.Command("docker", args...)
		cmd.Stdout = w
		cmd.Stderr = w
		w.Header().Set("Content-Type", "text/plain")
		cmd.Run()
	})

	// GET /ps
	mux.HandleFunc("/ps", func(w http.ResponseWriter, r *http.Request) {
		out, _ := run("docker", "compose", "-p", cfg.ComposeProject, "ps", "--format", "json")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, out)
	})

	// GET /deploys
	mux.HandleFunc("/deploys", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		data, _ := json.MarshalIndent(st.Services, "", "  ")
		st.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	// POST /rollback/<svc>?target=prev|orig
	mux.HandleFunc("/rollback/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		svc := strings.TrimPrefix(r.URL.Path, "/rollback/")
		if svc == "" {
			http.Error(w, "missing service", 400)
			return
		}
		target := r.URL.Query().Get("target")
		if target == "" {
			target = "prev"
		}
		if target != "prev" && target != "orig" {
			http.Error(w, "target must be prev or orig", 400)
			return
		}

		// wait for quiet window (API-driven in prod, local-clock in mock)
		anvil.waitForQuietWindow(cfg)

		digest, err := rollbackService(cfg, svc, target)
		if err != nil {
			log.Printf("[%s] rollback %s failed: %v", svc, target, err)
			http.Error(w, err.Error(), 500)
			return
		}

		st.recordRollback(svc, target, digest)
		anvil.reportDeploy(cfg, svc, "rollback", digest)

		log.Printf("[%s] rolled back to %s", svc, target)
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "service": svc, "target": target, "digest": digest,
		})
	})

	// GET /health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		nsvc := len(st.Services)
		st.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "services": nsvc, "time": time.Now().UTC(),
		})
	})

	// GET /diff/<svc>?from=sha&to=sha
	mux.HandleFunc("/diff/", func(w http.ResponseWriter, r *http.Request) {
		svc := strings.TrimPrefix(r.URL.Path, "/diff/")
		from := r.URL.Query().Get("from")
		to := r.URL.Query().Get("to")
		if from == "" {
			s := st.svc(svc)
			from = s.PrevSHA
		}
		if to == "" {
			s := st.svc(svc)
			to = s.SHA
		}
		out, err := run("git", "-C", cfg.RepoPath, "diff", from, to, "--stat", "--", svc+"/")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, out)
	})

	// GET /volumes/<svc> - read-only volume listing
	mux.HandleFunc("/volumes/", func(w http.ResponseWriter, r *http.Request) {
		svc := strings.TrimPrefix(r.URL.Path, "/volumes/")
		// find named volumes for this service
		out, _ := run("docker", "compose", "-p", cfg.ComposeProject, "config", "--volumes")
		lines := strings.Split(out, "\n")
		var volumes []map[string]any
		for _, vol := range lines {
			vol = strings.TrimSpace(vol)
			if vol == "" || !strings.HasPrefix(vol, svc) {
				continue
			}
			// get the actual mount path via inspect
			mount, _ := run("docker", "volume", "inspect", "--format", "{{.Mountpoint}}", vol)
			volumes = append(volumes, map[string]any{
				"name":  vol,
				"mount": strings.TrimSpace(mount),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(volumes)
	})

	// POST /push - manual trigger (for testing / poll fallback)
	mux.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		var req struct {
			Service string `json:"service"`
			SHA     string `json:"sha"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Service == "" || req.SHA == "" {
			http.Error(w, "service and sha required", 400)
			return
		}
		pq.enqueue(req.Service, req.SHA)
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "queued": req.Service})
	})

	// GET /tick - current tick info (proxies Anvil when available)
	mux.HandleFunc("/tick", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !cfg.GateMock && cfg.InternalToken != "" {
			if ti, err := anvil.currentTick(); err == nil {
				now := time.Now()
				json.NewEncoder(w).Encode(map[string]any{
					"tick":       ti.Tick,
					"started_at": ti.StartedAt,
					"ends_at":    ti.EndsAt,
					"hold_from":  ti.HoldFrom,
					"quiet":      !now.Before(ti.HoldFrom) && now.Before(ti.EndsAt),
				})
				return
			}
		}
		// fallback: local-clock estimate
		tick := tickNumber(cfg)
		var offset int
		if !cfg.EventStart.IsZero() {
			offset = int(time.Since(cfg.EventStart).Seconds()) % cfg.TickS
		}
		json.NewEncoder(w).Encode(map[string]any{
			"tick": tick, "offset_s": offset,
			"quiet": offset >= cfg.QuietOffsetS,
		})
	})

	// stderr log capture (internal, not exposed to teams)
	_ = os.Stderr
}
