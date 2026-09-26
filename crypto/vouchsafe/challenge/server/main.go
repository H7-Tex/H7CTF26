package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type session struct {
	mu           sync.Mutex
	regChallenge []byte
	assertChal   []byte
	creds        map[string]*attResult
	credits      int
}

type server struct {
	store    *metadataStore
	rpID     string
	origin   string
	flag     string
	credits  int
	mu       sync.Mutex
	sessions map[string]*session
}

func main() {
	mdsPath := envOr("MDS_PATH", "/app/mds_blob.json")
	store, err := loadMDS(mdsPath)
	if err != nil {
		log.Fatalf("mds load: %v", err)
	}
	flag := os.Getenv("FLAG")
	if flag == "" {
		flag = "flag-not-provisioned"
	}
	os.Unsetenv("FLAG")
	s := &server{
		store:    store,
		rpID:     envOr("RP_ID", "vouchsafe.local"),
		origin:   envOr("ORIGIN", "https://vouchsafe.local"),
		flag:     flag,
		credits:  atoiOr(envOr("CREDITS", "60"), 60),
		sessions: map[string]*session{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("/assert/begin", s.handleAssertBegin)
	mux.HandleFunc("/assert/finish", s.handleAssertFinish)
	addr := ":" + envOr("PORT", "8080")
	log.Printf("passport listening on %s rp=%s", addr, s.rpID)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func (s *server) getSession(w http.ResponseWriter, r *http.Request) *session {
	c, err := r.Cookie("sid")
	var sid string
	if err == nil {
		sid = c.Value
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if sid != "" {
		if sess, ok := s.sessions[sid]; ok {
			return sess
		}
	}
	buf := make([]byte, 16)
	rand.Read(buf)
	sid = hex.EncodeToString(buf)
	sess := &session{creds: map[string]*attResult{}, credits: s.credits}
	s.sessions[sid] = sess
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true})
	return sess
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]interface{}{
		"service": "H7 Passport",
		"rpId":    s.rpID,
		"origin":  s.origin,
		"note":    "passwordless enrollment portal. standard staff register consumer passkeys. the admin console is gated to enterprise-attested authenticators.",
		"routes":  []string{"GET /register/begin", "POST /register/finish", "GET /assert/begin", "POST /assert/finish"},
	})
}

func (s *server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.credits <= 0 {
		writeJSON(w, 402, map[string]string{"error": "ledger credits exhausted"})
		return
	}
	sess.credits--
	ch := make([]byte, 32)
	rand.Read(ch)
	sess.regChallenge = ch
	writeJSON(w, 200, map[string]interface{}{
		"rpId":      s.rpID,
		"origin":    s.origin,
		"challenge": base64.RawURLEncoding.EncodeToString(ch),
		"pubKeyAlg": -7,
		"tiers":     []string{"standard", "enterprise"},
		"formats":   []string{"packed", "tpm", "android-key"},
		"credits":   sess.credits,
	})
}

func (s *server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	var body struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		malformed(w, "json")
		return
	}
	if sess.regChallenge == nil {
		reject(w, "attestation rejected")
		return
	}
	cdBytes, err := b64any(body.ClientDataJSON)
	if err != nil {
		malformed(w, "base64")
		return
	}
	attBytes, err := b64any(body.AttestationObject)
	if err != nil {
		malformed(w, "base64")
		return
	}
	cd, err := parseClientData(cdBytes)
	if err != nil {
		malformed(w, "clientData")
		return
	}
	if cd.Type != "webauthn.create" || cd.Origin != s.origin || !cd.challengeMatches(sess.regChallenge) {
		reject(w, "attestation rejected")
		return
	}
	decoded, err := cborDecode(attBytes)
	if err != nil {
		malformed(w, "cbor")
		return
	}
	att, ok := decoded.(map[interface{}]interface{})
	if !ok {
		malformed(w, "cbor")
		return
	}
	fmtName, _ := att["fmt"].(string)
	attStmt, _ := att["attStmt"].(map[interface{}]interface{})
	authDataBytes, _ := att["authData"].([]byte)
	if fmtName == "" || attStmt == nil || authDataBytes == nil {
		malformed(w, "cbor")
		return
	}
	ad, err := parseAuthData(authDataBytes, true)
	if err != nil {
		malformed(w, "authData")
		return
	}
	rpHash := sha256.Sum256([]byte(s.rpID))
	if !eq(ad.rpIDHash, rpHash[:]) || ad.flags&flagUP == 0 {
		reject(w, "attestation rejected")
		return
	}
	clientHash := sha256.Sum256(cdBytes)
	res, verr := verifyRegistration(s.store, fmtName, attStmt, ad, clientHash[:])
	if verr == errMalformed {
		malformed(w, "attestation")
		return
	}
	if verr != nil {
		reject(w, "attestation rejected")
		return
	}
	sess.creds[hex.EncodeToString(res.credID)] = res
	sess.regChallenge = nil
	writeJSON(w, 200, map[string]interface{}{
		"status":       "enrolled",
		"tier":         res.tier,
		"credentialId": base64.RawURLEncoding.EncodeToString(res.credID),
	})
}

func (s *server) handleAssertBegin(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.credits <= 0 {
		writeJSON(w, 402, map[string]string{"error": "ledger credits exhausted"})
		return
	}
	sess.credits--
	ch := make([]byte, 32)
	rand.Read(ch)
	sess.assertChal = ch
	writeJSON(w, 200, map[string]interface{}{
		"challenge": base64.RawURLEncoding.EncodeToString(ch),
		"credits":   sess.credits,
	})
}

func (s *server) handleAssertFinish(w http.ResponseWriter, r *http.Request) {
	sess := s.getSession(w, r)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	var body struct {
		CredentialID       string `json:"credentialId"`
		ClientDataJSON     string `json:"clientDataJSON"`
		AuthenticatorData  string `json:"authenticatorData"`
		Signature          string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		malformed(w, "json")
		return
	}
	if sess.assertChal == nil {
		reject(w, "assertion rejected")
		return
	}
	credRaw, err := b64any(body.CredentialID)
	if err != nil {
		malformed(w, "base64")
		return
	}
	cdBytes, err := b64any(body.ClientDataJSON)
	if err != nil {
		malformed(w, "base64")
		return
	}
	authDataBytes, err := b64any(body.AuthenticatorData)
	if err != nil {
		malformed(w, "base64")
		return
	}
	sig, err := b64any(body.Signature)
	if err != nil {
		malformed(w, "base64")
		return
	}
	cred, ok := sess.creds[hex.EncodeToString(credRaw)]
	if !ok {
		reject(w, "assertion rejected")
		return
	}
	cd, err := parseClientData(cdBytes)
	if err != nil {
		malformed(w, "clientData")
		return
	}
	if cd.Type != "webauthn.get" || cd.Origin != s.origin || !cd.challengeMatches(sess.assertChal) {
		reject(w, "assertion rejected")
		return
	}
	ad, err := parseAuthData(authDataBytes, false)
	if err != nil {
		malformed(w, "authData")
		return
	}
	rpHash := sha256.Sum256([]byte(s.rpID))
	if !eq(ad.rpIDHash, rpHash[:]) {
		reject(w, "assertion rejected")
		return
	}
	if ad.flags&flagUV == 0 {
		reject(w, "assertion rejected")
		return
	}
	if !verifyAssertion(cred.pubKey, authDataBytes, cdBytes, sig) {
		reject(w, "assertion rejected")
		return
	}
	sess.assertChal = nil
	if cred.tier != tierEnterprise {
		writeJSON(w, 200, map[string]interface{}{
			"status": "authenticated",
			"tier":   cred.tier,
			"detail": "admin console requires an enterprise-attested authenticator",
		})
		return
	}
	writeJSON(w, 200, map[string]interface{}{
		"status": "granted",
		"tier":   cred.tier,
		"flag":   s.flag,
	})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func malformed(w http.ResponseWriter, detail string) {
	writeJSON(w, 400, map[string]string{"error": "malformed request", "component": detail})
}

func reject(w http.ResponseWriter, msg string) {
	writeJSON(w, 403, map[string]string{"error": msg})
}

func b64any(s string) ([]byte, error) {
	if v, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return v, nil
	}
	if v, err := base64.URLEncoding.DecodeString(s); err == nil {
		return v, nil
	}
	if v, err := base64.StdEncoding.DecodeString(s); err == nil {
		return v, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func eq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var d byte
	for i := range a {
		d |= a[i] ^ b[i]
	}
	return d == 0
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func atoiOr(s string, d int) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return d
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return d
	}
	return n
}
