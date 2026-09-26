package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

var policyOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61387, 2, 7, 4}

const (
	tierStandard   = "standard"
	tierEnterprise = "enterprise"
	policyBaseTag  = 7
)

var errRejected = errors.New("rejected")

type attResult struct {
	tier   string
	credID []byte
	pubKey *ecdsa.PublicKey
}

func verifyRegistration(store *metadataStore, fmtName string, attStmt map[interface{}]interface{}, ad *parsedAuthData, clientHash []byte) (*attResult, error) {
	if ad.coseKey == nil || ad.flags&flagAT == 0 {
		return nil, errMalformed
	}
	switch fmtName {
	case "packed":
		return verifyPacked(store, attStmt, ad, clientHash)
	case "tpm":
		return verifyPinnedFormat(store, attStmt, ad, clientHash)
	case "android-key":
		return verifyPinnedFormat(store, attStmt, ad, clientHash)
	}
	return nil, errMalformed
}

func verifyPacked(store *metadataStore, attStmt map[interface{}]interface{}, ad *parsedAuthData, clientHash []byte) (*attResult, error) {
	alg, _ := attStmt["alg"].(int64)
	sig, sok := attStmt["sig"].([]byte)
	if alg != -7 || !sok {
		return nil, errMalformed
	}
	x5cRaw, hasX5c := attStmt["x5c"].([]interface{})

	if !hasX5c {
		if !verifyPayloadSig(ad.coseKey, ad.raw, clientHash, sig) {
			return nil, errRejected
		}
		return &attResult{tier: tierStandard, credID: ad.credID, pubKey: ad.coseKey}, nil
	}

	certs, err := parseX5c(x5cRaw)
	if err != nil {
		return nil, errMalformed
	}
	leaf := certs[0]
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errMalformed
	}
	if !verifyPayloadSig(leafPub, ad.raw, clientHash, sig) {
		return nil, errRejected
	}

	aaguid := aaguidHex(ad.aaguid)
	if store.known[aaguid] {
		if !verifyChainToPinnedRoot(certs, store.roots) {
			return nil, errRejected
		}
		return &attResult{tier: tierStandard, credID: ad.credID, pubKey: ad.coseKey}, nil
	}

	anchor := certs[0]
	for _, c := range certs {
		if !verifySignedBy(c, anchor) {
			return nil, errRejected
		}
	}
	elevated, violation := policyDecision(leaf)
	if violation {
		return nil, errRejected
	}
	tier := tierStandard
	if elevated {
		tier = tierEnterprise
	}
	return &attResult{tier: tier, credID: ad.credID, pubKey: ad.coseKey}, nil
}

func verifyPinnedFormat(store *metadataStore, attStmt map[interface{}]interface{}, ad *parsedAuthData, clientHash []byte) (*attResult, error) {
	x5cRaw, hasX5c := attStmt["x5c"].([]interface{})
	if !hasX5c {
		return nil, errMalformed
	}
	certs, err := parseX5c(x5cRaw)
	if err != nil {
		return nil, errMalformed
	}
	sig, sok := attStmt["sig"].([]byte)
	if !sok {
		return nil, errMalformed
	}
	leaf := certs[0]
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errMalformed
	}
	if !verifyPayloadSig(leafPub, ad.raw, clientHash, sig) {
		return nil, errRejected
	}
	if !verifyChainToPinnedRoot(certs, store.roots) {
		return nil, errRejected
	}
	return &attResult{tier: tierStandard, credID: ad.credID, pubKey: ad.coseKey}, nil
}

func parseX5c(raw []interface{}) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, errMalformed
	}
	out := make([]*x509.Certificate, 0, len(raw))
	for _, item := range raw {
		der, ok := item.([]byte)
		if !ok {
			return nil, errMalformed
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errMalformed
		}
		out = append(out, cert)
	}
	return out, nil
}

func verifySignedBy(child, parent *x509.Certificate) bool {
	return parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature) == nil
}

func verifyChainToPinnedRoot(certs []*x509.Certificate, roots []*x509.Certificate) bool {
	for i := 0; i+1 < len(certs); i++ {
		if !verifySignedBy(certs[i], certs[i+1]) {
			return false
		}
	}
	top := certs[len(certs)-1]
	for _, r := range roots {
		if bytes.Equal(top.RawSubject, r.RawSubject) && bytes.Equal(top.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo) {
			return true
		}
		if verifySignedBy(top, r) {
			return true
		}
	}
	return false
}

func verifyPayloadSig(pub *ecdsa.PublicKey, authData, clientHash, sig []byte) bool {
	signed := append(append([]byte{}, authData...), clientHash...)
	digest := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

func policyDecision(leaf *x509.Certificate) (bool, bool) {
	var ext []byte
	found := false
	for _, e := range leaf.Extensions {
		if e.Id.Equal(policyOID) {
			ext = e.Value
			found = true
			break
		}
	}
	if !found {
		return false, false
	}
	var top asn1.RawValue
	if _, err := asn1.Unmarshal(ext, &top); err != nil {
		return false, false
	}
	if top.Class != asn1.ClassUniversal || top.Tag != asn1.TagSequence {
		return false, false
	}
	var elems []asn1.RawValue
	body := top.Bytes
	for len(body) > 0 {
		var rv asn1.RawValue
		rest, err := asn1.Unmarshal(body, &rv)
		if err != nil {
			return false, false
		}
		elems = append(elems, rv)
		body = rest
	}
	if len(elems) < 3 {
		return false, false
	}
	aaguidCount := intFromRaw(elems[1])
	if aaguidCount < 0 || aaguidCount > 32 {
		return false, false
	}
	fields := elems[3:]
	if boolAtTag(fields, policyBaseTag) {
		return false, true
	}
	privTag := policyBaseTag + aaguidCount
	return boolAtTag(fields, privTag), false
}

func boolAtTag(fields []asn1.RawValue, tag int) bool {
	for _, e := range fields {
		if e.Class == asn1.ClassContextSpecific && e.Tag == tag && !e.IsCompound {
			return len(e.Bytes) == 1 && e.Bytes[0] != 0x00
		}
	}
	return false
}

func intFromRaw(rv asn1.RawValue) int {
	var n int
	if _, err := asn1.Unmarshal(rv.FullBytes, &n); err != nil {
		return -1
	}
	return n
}
