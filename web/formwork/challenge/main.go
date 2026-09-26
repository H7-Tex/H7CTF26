package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const team = "workspace"

var (
	pool *pgxpool.Pool
	tpl  *template.Template
)

type base struct {
	ID   string
	Name string
	Tbl  string
}

type field struct {
	FieldID  string
	ColIdent string
	Label    string
	Position int
}

type rollup struct {
	Fingerprint string
	Note        string
	ComputedAt  string
	Present     bool
}

type basePage struct {
	Base      base
	Fields    []field
	Records   []map[string]string
	Columns   []string
	Rollup    rollup
	SealError string
	Notice    string
}

type indexPage struct {
	Bases []base
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://app:app@127.0.0.1:5432/formwork"
	}
	ctx := context.Background()
	var err error
	pool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	for i := 0; i < 30; i++ {
		if err = pool.Ping(ctx); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("ping: %v", err)
	}

	tpl = template.Must(template.New("root").Parse(pageTemplates))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handleIndex)
	mux.HandleFunc("POST /bases", handleCreateBase)
	mux.HandleFunc("GET /bases/{id}", handleBase)
	mux.HandleFunc("POST /bases/{id}/fields", handleAddField)
	mux.HandleFunc("POST /bases/{id}/fields/{fid}/rename", handleRenameField)
	mux.HandleFunc("POST /bases/{id}/fields/{fid}/drop", handleDropField)
	mux.HandleFunc("POST /bases/{id}/records", handleAddRecord)
	mux.HandleFunc("POST /bases/{id}/seal", handleSeal)
	mux.HandleFunc("GET /api/bases/{id}/export", handleExport)
	mux.HandleFunc("POST /api/bases/{id}/import", handleImport)

	addr := ":8080"
	if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}
	log.Printf("formwork listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

var slugStrip = regexp.MustCompile(`[^a-z0-9_]+`)
var slugCollapse = regexp.MustCompile(`_+`)

func slugify(label string) string {
	s := strings.ToLower(strings.TrimSpace(label))
	s = strings.ReplaceAll(s, " ", "_")
	s = slugStrip.ReplaceAllString(s, "_")
	s = slugCollapse.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "field"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "f_" + s
	}
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

func quote(ident string) string {
	return pgx.Identifier{ident}.Sanitize()
}

func loadBase(ctx context.Context, id string) (base, error) {
	var b base
	err := pool.QueryRow(ctx, "SELECT id, name, tbl FROM bases WHERE id=$1 AND team=$2", id, team).
		Scan(&b.ID, &b.Name, &b.Tbl)
	return b, err
}

func loadFields(ctx context.Context, id string) ([]field, error) {
	rows, err := pool.Query(ctx, "SELECT field_id, col_ident, label, position FROM field_meta WHERE base_id=$1 ORDER BY position, field_id", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []field
	for rows.Next() {
		var f field
		if err := rows.Scan(&f.FieldID, &f.ColIdent, &f.Label, &f.Position); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func physicalColumns(ctx context.Context, tbl string) ([]string, error) {
	rows, err := pool.Query(ctx,
		"SELECT column_name FROM information_schema.columns WHERE table_name=$1 AND column_name<>'id' ORDER BY ordinal_position", tbl)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

func loadRecords(ctx context.Context, tbl string, cols []string) ([]map[string]string, error) {
	if len(cols) == 0 {
		return nil, nil
	}
	sel := make([]string, 0, len(cols))
	for _, c := range cols {
		sel = append(sel, quote(c))
	}
	q := fmt.Sprintf("SELECT %s FROM %s ORDER BY id DESC LIMIT 50", strings.Join(sel, ", "), quote(tbl))
	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		for i, c := range cols {
			if vals[i] == nil {
				m[c] = ""
			} else {
				m[c] = fmt.Sprintf("%v", vals[i])
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func loadRollup(ctx context.Context, id string) rollup {
	var r rollup
	var note, fp *string
	var ts *time.Time
	err := pool.QueryRow(ctx, "SELECT fingerprint, note, computed_at FROM base_rollup WHERE base_id=$1", id).
		Scan(&fp, &note, &ts)
	if err != nil {
		return r
	}
	r.Present = true
	if fp != nil {
		r.Fingerprint = *fp
	}
	if note != nil {
		r.Note = *note
	}
	if ts != nil {
		r.ComputedAt = ts.Format(time.RFC3339)
	}
	return r
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := pool.Query(ctx, "SELECT id, name, tbl FROM bases WHERE team=$1 ORDER BY created_at DESC", team)
	if err != nil {
		httpErr(w, err)
		return
	}
	defer rows.Close()
	var bs []base
	for rows.Next() {
		var b base
		rows.Scan(&b.ID, &b.Name, &b.Tbl)
		bs = append(bs, b)
	}
	render(w, "index", indexPage{Bases: bs})
}

func handleCreateBase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "Untitled Base"
	}
	id := newID()
	tbl := "b_" + id
	if _, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s (id bigserial PRIMARY KEY)", quote(tbl))); err != nil {
		httpErr(w, err)
		return
	}
	if _, err := pool.Exec(ctx, "INSERT INTO bases(id, team, name, tbl) VALUES ($1,$2,$3,$4)", id, team, name, tbl); err != nil {
		httpErr(w, err)
		return
	}
	http.Redirect(w, r, "/bases/"+id, http.StatusSeeOther)
}

func renderBase(w http.ResponseWriter, r *http.Request, sealErr, notice string) {
	ctx := r.Context()
	id := r.PathValue("id")
	b, err := loadBase(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fields, err := loadFields(ctx, id)
	if err != nil {
		httpErr(w, err)
		return
	}
	cols, err := physicalColumns(ctx, b.Tbl)
	if err != nil {
		httpErr(w, err)
		return
	}
	recs, err := loadRecords(ctx, b.Tbl, cols)
	if err != nil {
		httpErr(w, err)
		return
	}
	render(w, "base", basePage{
		Base:      b,
		Fields:    fields,
		Records:   recs,
		Columns:   cols,
		Rollup:    loadRollup(ctx, id),
		SealError: sealErr,
		Notice:    notice,
	})
}

func handleBase(w http.ResponseWriter, r *http.Request) {
	renderBase(w, r, "", "")
}

func handleAddField(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	b, err := loadBase(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		renderBase(w, r, "", "field label required")
		return
	}
	col := slugify(label)
	if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s text", quote(b.Tbl), quote(col))); err != nil {
		httpErr(w, err)
		return
	}
	pos := nextPosition(ctx, id)
	if _, err := pool.Exec(ctx, "INSERT INTO field_meta(base_id, field_id, col_ident, label, position) VALUES ($1,$2,$3,$4,$5)",
		id, newID(), col, label, pos); err != nil {
		httpErr(w, err)
		return
	}
	http.Redirect(w, r, "/bases/"+id, http.StatusSeeOther)
}

func handleRenameField(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	fid := r.PathValue("fid")
	b, err := loadBase(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var oldCol string
	if err := pool.QueryRow(ctx, "SELECT col_ident FROM field_meta WHERE base_id=$1 AND field_id=$2", id, fid).Scan(&oldCol); err != nil {
		http.NotFound(w, r)
		return
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		renderBase(w, r, "", "new label required")
		return
	}
	newCol := slugify(label)
	if newCol != oldCol {
		if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s", quote(b.Tbl), quote(oldCol), quote(newCol))); err != nil {
			httpErr(w, err)
			return
		}
	}
	if _, err := pool.Exec(ctx, "UPDATE field_meta SET col_ident=$1, label=$2 WHERE base_id=$3 AND field_id=$4",
		newCol, label, id, fid); err != nil {
		httpErr(w, err)
		return
	}
	http.Redirect(w, r, "/bases/"+id, http.StatusSeeOther)
}

func handleDropField(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	fid := r.PathValue("fid")
	b, err := loadBase(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var col string
	if err := pool.QueryRow(ctx, "SELECT col_ident FROM field_meta WHERE base_id=$1 AND field_id=$2", id, fid).Scan(&col); err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER TABLE %s DROP COLUMN IF EXISTS %s", quote(b.Tbl), quote(col))); err != nil {
		httpErr(w, err)
		return
	}
	pool.Exec(ctx, "DELETE FROM field_meta WHERE base_id=$1 AND field_id=$2", id, fid)
	http.Redirect(w, r, "/bases/"+id, http.StatusSeeOther)
}

func handleAddRecord(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	b, err := loadBase(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cols, err := physicalColumns(ctx, b.Tbl)
	if err != nil {
		httpErr(w, err)
		return
	}
	var names []string
	var placeholders []string
	var args []any
	n := 1
	for _, c := range cols {
		v := r.FormValue(c)
		if v == "" {
			continue
		}
		names = append(names, quote(c))
		placeholders = append(placeholders, "$"+strconv.Itoa(n))
		args = append(args, v)
		n++
	}
	if len(names) > 0 {
		q := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)", quote(b.Tbl), strings.Join(names, ", "), strings.Join(placeholders, ", "))
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			httpErr(w, err)
			return
		}
	}
	http.Redirect(w, r, "/bases/"+id, http.StatusSeeOther)
}

var sealLimiter = newLimiter(6, time.Minute)

func handleSeal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if _, err := loadBase(ctx, id); err != nil {
		http.NotFound(w, r)
		return
	}
	if !sealLimiter.allow() {
		renderBase(w, r, "seal is rate limited, wait a moment and retry", "")
		return
	}
	if _, err := pool.Exec(ctx, "SELECT compute_fingerprint($1)", id); err != nil {
		renderBase(w, r, "seal failed: "+err.Error(), "")
		return
	}
	renderBase(w, r, "", "base sealed")
}

type blueprintField struct {
	Label    string `json:"label"`
	ColIdent string `json:"col_ident"`
	Position int    `json:"position"`
}

type blueprint struct {
	Fields []blueprintField `json:"fields"`
}

func handleExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if _, err := loadBase(ctx, id); err != nil {
		http.NotFound(w, r)
		return
	}
	fields, err := loadFields(ctx, id)
	if err != nil {
		httpErr(w, err)
		return
	}
	bp := blueprint{}
	for _, f := range fields {
		bp.Fields = append(bp.Fields, blueprintField{Label: f.Label, ColIdent: f.ColIdent, Position: f.Position})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bp)
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	b, err := loadBase(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var bp blueprint
	if err := json.NewDecoder(r.Body).Decode(&bp); err != nil {
		http.Error(w, "invalid blueprint", http.StatusBadRequest)
		return
	}
	imported := 0
	for _, bf := range bp.Fields {
		col := bf.ColIdent
		if col == "" {
			col = slugify(bf.Label)
		}
		label := bf.Label
		if label == "" {
			label = col
		}
		if _, err := pool.Exec(ctx, fmt.Sprintf("ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s text", quote(b.Tbl), quote(col))); err != nil {
			http.Error(w, "import failed on a field", http.StatusBadRequest)
			return
		}
		if _, err := pool.Exec(ctx, "INSERT INTO field_meta(base_id, field_id, col_ident, label, position) VALUES ($1,$2,$3,$4,$5)",
			id, newID(), col, label, bf.Position); err != nil {
			http.Error(w, "import failed", http.StatusBadRequest)
			return
		}
		imported++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"imported": imported})
}

func nextPosition(ctx context.Context, id string) int {
	var pos *int
	pool.QueryRow(ctx, "SELECT max(position) FROM field_meta WHERE base_id=$1", id).Scan(&pos)
	if pos == nil {
		return 0
	}
	return *pos + 1
}

func render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func httpErr(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

type limiter struct {
	mu     sync.Mutex
	stamps []time.Time
	max    int
	window time.Duration
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window}
}

func (l *limiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	kept := l.stamps[:0]
	for _, t := range l.stamps {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	l.stamps = kept
	if len(l.stamps) >= l.max {
		return false
	}
	l.stamps = append(l.stamps, now)
	return true
}
