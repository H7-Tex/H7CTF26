package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
)

type mdsEntry struct {
	AAGUID              string   `json:"aaguid"`
	Description         string   `json:"description"`
	AttestationRootCert []string `json:"attestationRootCertificates"`
}

type mdsPayload struct {
	Legalheader string     `json:"legalHeader"`
	No          int        `json:"no"`
	Entries     []mdsEntry `json:"entries"`
}

type metadataStore struct {
	known map[string]bool
	roots []*x509.Certificate
}

func loadMDS(path string) (*metadataStore, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload mdsPayload
	body := raw
	if parts := strings.Split(string(raw), "."); len(parts) == 3 {
		dec, derr := base64.RawURLEncoding.DecodeString(parts[1])
		if derr == nil {
			body = dec
		}
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	store := &metadataStore{known: map[string]bool{}}
	for _, e := range payload.Entries {
		id := normalizeAAGUID(e.AAGUID)
		if id != "" {
			store.known[id] = true
		}
		for _, rc := range e.AttestationRootCert {
			der, derr := base64.StdEncoding.DecodeString(rc)
			if derr != nil {
				continue
			}
			cert, cerr := x509.ParseCertificate(der)
			if cerr == nil {
				store.roots = append(store.roots, cert)
			}
		}
	}
	return store, nil
}

func normalizeAAGUID(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, "-", ""))
	if len(s) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(s); err != nil {
		return ""
	}
	return s
}

func aaguidHex(b []byte) string {
	return hex.EncodeToString(b)
}
