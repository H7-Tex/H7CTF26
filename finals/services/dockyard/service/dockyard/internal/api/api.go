package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/template"
	"time"

	"dockyard/internal/auth"
	"dockyard/internal/log"
	"dockyard/internal/registry"
)

type Server struct {
	DB       *sql.DB
	BlobRoot string
}

// RepoView is the template data for webhook watches.
// BUG (V1 store B): Secrets is included, so a template like {{.Secrets}} leaks DEPLOY_KEY.
type RepoView struct {
	Name       string
	Owner      string
	Visibility string
	Tag        string
	Digest     string
	PushedAt   time.Time
	Secrets    map[string]string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/users", s.handleRegister)
	mux.HandleFunc("POST /api/session", s.handleLogin)

	mux.HandleFunc("POST /api/repos", s.authMid(s.handleCreateRepo))
	mux.HandleFunc("GET /api/repos", s.authMid(s.handleListRepos))

	mux.HandleFunc("GET /api/repos/{ns}/{name}/secrets", s.handleGetSecrets)
	mux.HandleFunc("PUT /api/repos/{ns}/{name}/secrets/{key}", s.authMid(s.handleSetSecret))

	mux.HandleFunc("POST /api/repos/{ns}/{name}/watches", s.authMid(s.handleCreateWatch))
	mux.HandleFunc("GET /api/repos/{ns}/{name}/watches/{id}/deliveries", s.authMid(s.handleGetDeliveries))

	mux.HandleFunc("POST /api/tokens", s.authMid(s.handleCreateFineToken))

	mux.HandleFunc("GET /token", s.handleToken)

	mux.HandleFunc("GET /log/tree", s.handleLogTree)
	mux.HandleFunc("GET /log/entries/{n}", s.handleLogEntry)
	mux.HandleFunc("POST /log/keys", s.authMid(s.handleLogRegisterKey))
	mux.HandleFunc("POST /log/attest", s.authMid(s.handleLogAttest))

	mux.HandleFunc("GET /v2/{$}", s.handleV2Root)
	mux.HandleFunc("GET /v2/_catalog", s.handleCatalog)
	mux.HandleFunc("/v2/", s.handleV2)

	return mux
}

// --- context ---

type ctxKey string

const ctxUserKey ctxKey = "user"

func withUser(r *http.Request, u string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxUserKey, u))
}

func userFromCtx(r *http.Request) string {
	v := r.Context().Value(ctxUserKey)
	if v == nil {
		return ""
	}
	return v.(string)
}

// --- auth helpers ---

func bearerFromHeader(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func (s *Server) authMid(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerFromHeader(r)
		if tok == "" {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		c, err := auth.ParseToken(tok)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		next(w, withUser(r, c.Subject))
	}
}

func (s *Server) resolveUser(r *http.Request) (string, bool) {
	tok := bearerFromHeader(r)
	if tok != "" {
		if c, err := auth.ParseToken(tok); err == nil {
			return c.Subject, true
		}
	}
	u, p, ok := r.BasicAuth()
	if ok && u != "" {
		var hash string
		if err := s.DB.QueryRow(`SELECT password_hash FROM users WHERE username=?`, u).Scan(&hash); err == nil {
			if auth.CheckPassword(hash, p) == nil {
				return u, true
			}
		}
	}
	return "", false
}

// --- Registration / session ---

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	for _, c := range req.Username {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			http.Error(w, `{"error":"invalid username"}`, http.StatusBadRequest)
			return
		}
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	if _, err = s.DB.Exec(`INSERT INTO users(username,password_hash) VALUES(?,?)`, req.Username, hash); err != nil {
		http.Error(w, `{"error":"username taken"}`, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"username":%q}`, req.Username)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	var hash string
	if err := s.DB.QueryRow(`SELECT password_hash FROM users WHERE username=?`, req.Username).Scan(&hash); err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	if auth.CheckPassword(hash, req.Password) != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}
	tok, err := auth.SignToken(req.Username, nil)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":%q}`, tok)
}

// --- Repos ---

func (s *Server) handleCreateRepo(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	var req struct {
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if req.Visibility == "" {
		req.Visibility = "private"
	}
	parts := strings.SplitN(req.Name, "/", 2)
	if len(parts) != 2 || parts[0] != user {
		http.Error(w, `{"error":"name must be your-namespace/repo"}`, http.StatusBadRequest)
		return
	}
	if _, err := s.DB.Exec(`INSERT INTO repos(name,owner,visibility) VALUES(?,?,?)`, req.Name, user, req.Visibility); err != nil {
		http.Error(w, `{"error":"repo exists or internal error"}`, http.StatusConflict)
		return
	}
	s.DB.Exec(`INSERT OR IGNORE INTO repo_members(repo,username,role) VALUES(?,?,'admin')`, req.Name, user)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"name":%q,"visibility":%q}`, req.Name, req.Visibility)
}

func (s *Server) handleListRepos(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	rows, err := s.DB.Query(
		`SELECT name,visibility FROM repos WHERE owner=? OR visibility='public' OR name IN (SELECT repo FROM repo_members WHERE username=?)`,
		user, user,
	)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	defer rows.Close()
	type R struct {
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	}
	var repos []R
	for rows.Next() {
		var rr R
		rows.Scan(&rr.Name, &rr.Visibility)
		repos = append(repos, rr)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repos)
}

// --- Secrets ---

func (s *Server) handleGetSecrets(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	name := r.PathValue("name")
	repo := ns + "/" + name

	tok := bearerFromHeader(r)
	if tok != "" {
		c, err := auth.ParseToken(tok)
		if err == nil && c.Type == "fine" {
			for _, sc := range c.Scopes {
				if matchSecretScope(sc, repo) {
					s.writeSecrets(w, repo)
					return
				}
			}
		}
	}

	callerUser, ok := s.resolveUser(r)
	if !ok {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	var role string
	s.DB.QueryRow(`SELECT role FROM repo_members WHERE repo=? AND username=?`, repo, callerUser).Scan(&role)
	if role != "admin" {
		var owner string
		s.DB.QueryRow(`SELECT owner FROM repos WHERE name=?`, repo).Scan(&owner)
		if owner != callerUser {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
	}
	s.writeSecrets(w, repo)
}

// matchSecretScope checks if a fine-token scope grants secrets:read for repo.
// BUG (V2 store B): glob matching uses simple prefix so "sea*/*" matches "seawolf/..."
func matchSecretScope(scope, repo string) bool {
	if !strings.HasPrefix(scope, "secrets:read:") {
		return false
	}
	return globMatch(strings.TrimPrefix(scope, "secrets:read:"), repo)
}

// globMatch: * matches any sequence including '/'.
// Intentionally permissive - this is the bug surface.
func globMatch(pattern, s string) bool {
	if pattern == "*" || pattern == s {
		return true
	}
	star := strings.Index(pattern, "*")
	if star < 0 {
		return false
	}
	prefix, suffix := pattern[:star], pattern[star+1:]
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	rest := s[len(prefix):]
	if suffix == "" {
		return true
	}
	// recurse to handle multiple stars
	return globMatch(suffix, rest)
}

func (s *Server) writeSecrets(w http.ResponseWriter, repo string) {
	rows, err := s.DB.Query(`SELECT key,value FROM repo_secrets WHERE repo=?`, repo)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		m[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m)
}

func (s *Server) handleSetSecret(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	ns := r.PathValue("ns")
	name := r.PathValue("name")
	key := r.PathValue("key")
	repo := ns + "/" + name

	var owner string
	s.DB.QueryRow(`SELECT owner FROM repos WHERE name=?`, repo).Scan(&owner)
	if owner != user {
		var role string
		s.DB.QueryRow(`SELECT role FROM repo_members WHERE repo=? AND username=?`, repo, user).Scan(&role)
		if role != "admin" {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	s.DB.Exec(`INSERT OR REPLACE INTO repo_secrets(repo,key,value) VALUES(?,?,?)`, repo, key, req.Value)
	w.WriteHeader(http.StatusNoContent)
}

// --- Watches ---

func (s *Server) handleCreateWatch(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	ns := r.PathValue("ns")
	name := r.PathValue("name")
	repo := ns + "/" + name

	var vis string
	s.DB.QueryRow(`SELECT visibility FROM repos WHERE name=?`, repo).Scan(&vis)
	if vis == "" {
		http.Error(w, `{"error":"repo not found"}`, http.StatusNotFound)
		return
	}
	if vis == "private" {
		var role string
		s.DB.QueryRow(`SELECT role FROM repo_members WHERE repo=? AND username=?`, repo, user).Scan(&role)
		if role == "" {
			var owner string
			s.DB.QueryRow(`SELECT owner FROM repos WHERE name=?`, repo).Scan(&owner)
			if owner != user {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
		}
	}

	var req struct {
		URL      string `json:"url"`
		Template string `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Template == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	id := newID()
	s.DB.Exec(`INSERT INTO watches(id,repo,url,template,created_by) VALUES(?,?,?,?,?)`,
		id, repo, req.URL, req.Template, user)

	// fire test delivery immediately - attacker reads secrets from delivery log
	s.fireWatch(id, repo, "", "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"id":%q}`, id)
}

func (s *Server) handleGetDeliveries(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	ns := r.PathValue("ns")
	name := r.PathValue("name")
	watchID := r.PathValue("id")
	repo := ns + "/" + name

	var createdBy string
	s.DB.QueryRow(`SELECT created_by FROM watches WHERE id=? AND repo=?`, watchID, repo).Scan(&createdBy)
	if createdBy != user {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}

	rows, err := s.DB.Query(`SELECT id,rendered,status,created_at FROM deliveries WHERE watch_id=? ORDER BY created_at DESC LIMIT 50`, watchID)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	defer rows.Close()
	type D struct {
		ID        string `json:"id"`
		Rendered  string `json:"rendered"`
		Status    int    `json:"status"`
		CreatedAt int64  `json:"created_at"`
	}
	var deliveries []D
	for rows.Next() {
		var d D
		rows.Scan(&d.ID, &d.Rendered, &d.Status, &d.CreatedAt)
		deliveries = append(deliveries, d)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(deliveries)
}

func (s *Server) fireWatch(watchID, repo, tag, digest string) {
	var tmplStr, url string
	if err := s.DB.QueryRow(`SELECT template,url FROM watches WHERE id=?`, watchID).Scan(&tmplStr, &url); err != nil {
		return
	}

	var owner, vis string
	s.DB.QueryRow(`SELECT owner,visibility FROM repos WHERE name=?`, repo).Scan(&owner, &vis)

	secrets := map[string]string{}
	if rows, err := s.DB.Query(`SELECT key,value FROM repo_secrets WHERE repo=?`, repo); err == nil {
		for rows.Next() {
			var k, v string
			rows.Scan(&k, &v)
			secrets[k] = v
		}
		rows.Close()
	}

	view := RepoView{
		Name:       repo,
		Owner:      owner,
		Visibility: vis,
		Tag:        tag,
		Digest:     digest,
		PushedAt:   time.Now(),
		Secrets:    secrets,
	}

	var buf bytes.Buffer
	t, err := template.New("w").Parse(tmplStr)
	if err != nil {
		buf.WriteString("[template parse error]")
	} else if err := t.Execute(&buf, view); err != nil {
		buf.WriteString("[template execute error]")
	}
	rendered := buf.String()

	s.DB.Exec(`INSERT INTO deliveries(id,watch_id,rendered,status,created_at) VALUES(?,?,?,?,?)`,
		newID(), watchID, rendered, 200, time.Now().Unix())

	if url != "" {
		go http.Post(url, "application/json", strings.NewReader(rendered)) //nolint
	}
}

func (s *Server) fireAllWatches(repo, tag, digest string) {
	rows, err := s.DB.Query(`SELECT id FROM watches WHERE repo=?`, repo)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		s.fireWatch(id, repo, tag, digest)
	}
}

// --- Fine-grained tokens ---

func (s *Server) handleCreateFineToken(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	var req struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}

	// BUG (V2 store B): checks HasPrefix(pattern, user) not HasPrefix(pattern, user+"/")
	// so user "sea" can create scope "sea*/*" matching "seawolf/..."
	for _, sc := range req.Scopes {
		if !strings.HasPrefix(sc, "secrets:read:") {
			http.Error(w, `{"error":"unsupported scope"}`, http.StatusBadRequest)
			return
		}
		pattern := strings.TrimPrefix(sc, "secrets:read:")
		if !strings.HasPrefix(pattern, user) {
			http.Error(w, `{"error":"scope outside your namespace"}`, http.StatusForbidden)
			return
		}
	}

	id := newID()
	scopesJSON, _ := json.Marshal(req.Scopes)
	s.DB.Exec(`INSERT INTO fine_tokens(id,owner,name,scopes) VALUES(?,?,?,?)`, id, user, req.Name, string(scopesJSON))

	tok, err := auth.SignFineToken(user, req.Scopes)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"token":%q,"id":%q}`, tok, id)
}

// --- Docker token service ---

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	var user string
	if u, p, ok := r.BasicAuth(); ok {
		var hash string
		if err := s.DB.QueryRow(`SELECT password_hash FROM users WHERE username=?`, u).Scan(&hash); err != nil {
			http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
			return
		}
		if auth.CheckPassword(hash, p) != nil {
			http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
			return
		}
		user = u
	} else if tok := bearerFromHeader(r); tok != "" {
		c, err := auth.ParseToken(tok)
		if err != nil {
			http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
			return
		}
		user = c.Subject
	} else {
		http.Error(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`, http.StatusUnauthorized)
		return
	}

	r.ParseForm()
	var access []auth.AccessEntry
	for _, sc := range r.Form["scope"] {
		typ, name, actions, err := auth.ParseScope(sc)
		if err != nil || typ != "repository" {
			continue
		}
		var granted []string
		for _, a := range actions {
			if s.canAccess(user, name, a) {
				granted = append(granted, a)
			}
		}
		if len(granted) > 0 {
			access = append(access, auth.AccessEntry{Type: "repository", Name: name, Actions: granted})
		}
	}

	tok, err := auth.SignToken(user, access)
	if err != nil {
		http.Error(w, `{"errors":[{"code":"INTERNAL"}]}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"token":%q,"access_token":%q}`, tok, tok)
}

func (s *Server) canAccess(user, repo, action string) bool {
	var owner, vis string
	if err := s.DB.QueryRow(`SELECT owner,visibility FROM repos WHERE name=?`, repo).Scan(&owner, &vis); err != nil {
		parts := strings.SplitN(repo, "/", 2)
		return len(parts) == 2 && parts[0] == user
	}
	switch action {
	case "pull":
		if vis == "public" || owner == user {
			return true
		}
		var role string
		s.DB.QueryRow(`SELECT role FROM repo_members WHERE repo=? AND username=?`, repo, user).Scan(&role)
		return role != ""
	case "push":
		if owner == user {
			return true
		}
		var role string
		s.DB.QueryRow(`SELECT role FROM repo_members WHERE repo=? AND username=?`, repo, user).Scan(&role)
		return role == "admin" || role == "writer"
	}
	return false
}

// --- Transparency log ---

func (s *Server) handleLogTree(w http.ResponseWriter, r *http.Request) {
	head, err := log.GetTree(s.DB, auth.PrivateKeyRaw())
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(head)
}

func (s *Server) handleLogEntry(w http.ResponseWriter, r *http.Request) {
	var n int64
	fmt.Sscan(r.PathValue("n"), &n)
	e, err := log.GetEntry(s.DB, n)
	if err != nil || e == nil {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(e)
}

func (s *Server) handleLogRegisterKey(w http.ResponseWriter, r *http.Request) {
	user := userFromCtx(r)
	var req struct {
		Kid string `json:"kid"`
		Pub string `json:"pub_ed25519_b64"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Kid == "" || req.Pub == "" {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(req.Pub)
	if err != nil {
		http.Error(w, `{"error":"invalid pub key"}`, http.StatusBadRequest)
		return
	}
	if err := log.RegisterKey(s.DB, req.Kid, user, hex.EncodeToString(pubBytes)); err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleLogAttest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo   string `json:"repo"`
		Tag    string `json:"tag"`
		Digest string `json:"digest"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	if err := log.AppendAttestation(s.DB, req.Repo, req.Tag, req.Digest); err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// --- OCI v2 ---

func (s *Server) handleV2Root(w http.ResponseWriter, r *http.Request) {
	if tok := bearerFromHeader(r); tok != "" {
		if _, err := auth.ParseToken(tok); err == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{}`))
			return
		}
	}
	realm := "http://" + r.Host + "/token"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="dockyard"`, realm))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`))
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	user, _ := s.resolveUser(r)
	var rows *sql.Rows
	var err error
	if user != "" {
		rows, err = s.DB.Query(
			`SELECT name FROM repos WHERE visibility='public' OR owner=? OR name IN (SELECT repo FROM repo_members WHERE username=?)`,
			user, user,
		)
	} else {
		rows, err = s.DB.Query(`SELECT name FROM repos WHERE visibility='public'`)
	}
	if err != nil {
		http.Error(w, `{"errors":[{"code":"INTERNAL"}]}`, 500)
		return
	}
	defer rows.Close()
	var repos []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		repos = append(repos, n)
	}
	if repos == nil {
		repos = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{"repositories": repos})
}

// handleV2 dispatches /v2/<repo>/blobs/..., /v2/<repo>/manifests/..., /v2/<repo>/tags/list
func (s *Server) handleV2(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v2/")

	// segments to detect operation type
	segments := []string{"/blobs/uploads/", "/blobs/uploads", "/blobs/", "/manifests/", "/tags/list"}
	for _, seg := range segments {
		idx := strings.Index(path, seg)
		if idx < 0 {
			continue
		}
		repo := path[:idx]
		rest := path[idx+len(seg):]
		switch {
		case seg == "/blobs/uploads/" || seg == "/blobs/uploads":
			s.handleBlobUpload(w, r, repo, rest)
		case seg == "/blobs/":
			s.handleBlob(w, r, repo, rest)
		case seg == "/manifests/":
			s.handleManifest(w, r, repo, rest)
		case seg == "/tags/list":
			s.handleTagList(w, r, repo)
		}
		return
	}
	http.Error(w, `{"errors":[{"code":"NOT_FOUND"}]}`, http.StatusNotFound)
}

func (s *Server) ociAuth(r *http.Request, repo string, actions []string) bool {
	tok := bearerFromHeader(r)
	if tok == "" {
		return false
	}
	c, err := auth.ParseToken(tok)
	if err != nil {
		return false
	}
	var regAccess []registry.AccessEntry
	for _, a := range c.Access {
		regAccess = append(regAccess, registry.AccessEntry{Type: a.Type, Name: a.Name, Actions: a.Actions})
	}
	return registry.CheckAccess(regAccess, repo, actions)
}

func (s *Server) ociUnauth(w http.ResponseWriter, r *http.Request, repo string) {
	realm := "http://" + r.Host + "/token"
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="dockyard",scope="repository:%s:pull,push"`, realm, repo))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"errors":[{"code":"UNAUTHORIZED"}]}`))
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request, repo, digest string) {
	if !s.ociAuth(r, repo, []string{"pull"}) {
		s.ociUnauth(w, r, repo)
		return
	}
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	var size int64
	var bpath string
	err := s.DB.QueryRow(
		`SELECT b.size,b.path FROM blobs b JOIN blob_links l ON b.digest=l.digest WHERE l.repo=? AND b.digest=?`,
		repo, digest,
	).Scan(&size, &bpath)
	if err != nil {
		http.Error(w, `{"errors":[{"code":"BLOB_UNKNOWN"}]}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Docker-Content-Digest", digest)
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprint(size))
		w.WriteHeader(http.StatusOK)
		return
	}
	http.ServeFile(w, r, bpath)
}

func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request, repo, rest string) {
	if r.Method == http.MethodPost {
		if !s.ociAuth(r, repo, []string{"push"}) {
			s.ociUnauth(w, r, repo)
			return
		}
		q := r.URL.Query()
		mountDigest := q.Get("mount")
		digestParam := q.Get("digest")

		s.ensureRepo(repo, bearerSubject(r))

		if mountDigest != "" {
			// BUG (V1 store A): mount without checking pull permission on source repo
			ok, err := registry.Mount(s.DB, repo, mountDigest)
			if err != nil || !ok {
				uuid := newID()
				s.DB.Exec(`INSERT INTO uploads(uuid,repo,created_at) VALUES(?,?,?)`, uuid, repo, time.Now().Unix())
				loc := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uuid)
				w.Header().Set("Location", loc)
				w.Header().Set("Docker-Upload-UUID", uuid)
				w.WriteHeader(http.StatusAccepted)
				return
			}
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, mountDigest))
			w.Header().Set("Docker-Content-Digest", mountDigest)
			w.WriteHeader(http.StatusCreated)
			return
		}

		if digestParam != "" {
			digest, _, err := registry.StoreBlobFromReader(s.DB, s.BlobRoot, repo, r.Body, digestParam)
			if err != nil {
				http.Error(w, `{"errors":[{"code":"BLOB_UPLOAD_INVALID"}]}`, http.StatusBadRequest)
				return
			}
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
			w.Header().Set("Docker-Content-Digest", digest)
			w.WriteHeader(http.StatusCreated)
			return
		}

		uuid := newID()
		s.DB.Exec(`INSERT INTO uploads(uuid,repo,created_at) VALUES(?,?,?)`, uuid, repo, time.Now().Unix())
		loc := fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, uuid)
		w.Header().Set("Location", loc)
		w.Header().Set("Docker-Upload-UUID", uuid)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if r.Method == http.MethodPut {
		if !s.ociAuth(r, repo, []string{"push"}) {
			s.ociUnauth(w, r, repo)
			return
		}
		uuid := rest
		digestParam := r.URL.Query().Get("digest")
		if digestParam == "" {
			http.Error(w, `{"errors":[{"code":"DIGEST_INVALID"}]}`, http.StatusBadRequest)
			return
		}
		var uRepo string
		s.DB.QueryRow(`SELECT repo FROM uploads WHERE uuid=?`, uuid).Scan(&uRepo)
		if uRepo != repo {
			http.Error(w, `{"errors":[{"code":"BLOB_UPLOAD_UNKNOWN"}]}`, http.StatusNotFound)
			return
		}
		digest, _, err := registry.StoreBlobFromReader(s.DB, s.BlobRoot, repo, r.Body, digestParam)
		if err != nil {
			http.Error(w, `{"errors":[{"code":"BLOB_UPLOAD_INVALID"}]}`, http.StatusBadRequest)
			return
		}
		s.DB.Exec(`DELETE FROM uploads WHERE uuid=?`, uuid)
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, digest))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)
		return
	}

	http.Error(w, "", http.StatusMethodNotAllowed)
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request, repo, ref string) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !s.ociAuth(r, repo, []string{"pull"}) {
			s.ociUnauth(w, r, repo)
			return
		}
		var content []byte
		var ct, digest string
		err := s.DB.QueryRow(`SELECT content,content_type,digest FROM manifests WHERE repo=? AND ref=?`,
			repo, ref).Scan(&content, &ct, &digest)
		if err != nil {
			http.Error(w, `{"errors":[{"code":"MANIFEST_UNKNOWN"}]}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Docker-Content-Digest", digest)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Write(content)

	case http.MethodPut:
		if !s.ociAuth(r, repo, []string{"push"}) {
			s.ociUnauth(w, r, repo)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
		if err != nil {
			http.Error(w, `{"errors":[{"code":"MANIFEST_INVALID"}]}`, http.StatusBadRequest)
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/vnd.oci.image.manifest.v1+json"
		}
		digest := auth.DigestHex(body)
		s.ensureRepo(repo, bearerSubject(r))

		s.DB.Exec(`INSERT OR REPLACE INTO manifests(repo,ref,digest,content,content_type,created_at) VALUES(?,?,?,?,?,?)`,
			repo, ref, digest, body, ct, time.Now().Unix())
		s.DB.Exec(`INSERT OR REPLACE INTO manifests(repo,ref,digest,content,content_type,created_at) VALUES(?,?,?,?,?,?)`,
			repo, digest, digest, body, ct, time.Now().Unix())

		log.Append(s.DB, repo, ref, digest)
		s.fireAllWatches(repo, ref, digest)

		w.Header().Set("Location", fmt.Sprintf("/v2/%s/manifests/%s", repo, digest))
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTagList(w http.ResponseWriter, r *http.Request, repo string) {
	if !s.ociAuth(r, repo, []string{"pull"}) {
		s.ociUnauth(w, r, repo)
		return
	}
	rows, err := s.DB.Query(
		`SELECT ref FROM manifests WHERE repo=? AND ref NOT LIKE 'sha256:%' ORDER BY created_at DESC`,
		repo,
	)
	if err != nil {
		http.Error(w, `{"errors":[{"code":"INTERNAL"}]}`, 500)
		return
	}
	defer rows.Close()
	var tags []string
	for rows.Next() {
		var t string
		rows.Scan(&t)
		tags = append(tags, t)
	}
	if tags == nil {
		tags = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"name": repo, "tags": tags})
}

func (s *Server) ensureRepo(repo, owner string) {
	if owner == "" {
		return
	}
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] != owner {
		return
	}
	s.DB.Exec(`INSERT OR IGNORE INTO repos(name,owner,visibility) VALUES(?,?,'private')`, repo, owner)
	s.DB.Exec(`INSERT OR IGNORE INTO repo_members(repo,username,role) VALUES(?,?,'admin')`, repo, owner)
}

func bearerSubject(r *http.Request) string {
	tok := bearerFromHeader(r)
	if tok == "" {
		return ""
	}
	c, err := auth.ParseToken(tok)
	if err != nil {
		return ""
	}
	return c.Subject
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
