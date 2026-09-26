package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

const (
	flagUP = 0x01
	flagUV = 0x04
	flagAT = 0x40
)

type parsedAuthData struct {
	rpIDHash  []byte
	flags     byte
	signCount uint32
	aaguid    []byte
	credID    []byte
	coseKey   *ecdsa.PublicKey
	raw       []byte
}

var errMalformed = errors.New("malformed")

func parseAuthData(b []byte, expectAT bool) (*parsedAuthData, error) {
	if len(b) < 37 {
		return nil, errMalformed
	}
	ad := &parsedAuthData{raw: b}
	ad.rpIDHash = b[0:32]
	ad.flags = b[32]
	ad.signCount = uint32(b[33])<<24 | uint32(b[34])<<16 | uint32(b[35])<<8 | uint32(b[36])
	rest := b[37:]
	if ad.flags&flagAT != 0 {
		if len(rest) < 18 {
			return nil, errMalformed
		}
		ad.aaguid = rest[0:16]
		credLen := int(rest[16])<<8 | int(rest[17])
		rest = rest[18:]
		if credLen < 0 || credLen > len(rest) {
			return nil, errMalformed
		}
		ad.credID = rest[0:credLen]
		rest = rest[credLen:]
		key, used, err := parseCOSEKey(rest)
		if err != nil {
			return nil, err
		}
		ad.coseKey = key
		_ = used
	} else if expectAT {
		return nil, errMalformed
	}
	return ad, nil
}

func parseCOSEKey(b []byte) (*ecdsa.PublicKey, int, error) {
	r := &cborReader{buf: b}
	v, err := r.decode()
	if err != nil {
		return nil, 0, errMalformed
	}
	m, ok := v.(map[interface{}]interface{})
	if !ok {
		return nil, 0, errMalformed
	}
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)
	crv, _ := m[int64(-1)].(int64)
	x, xok := m[int64(-2)].([]byte)
	y, yok := m[int64(-3)].([]byte)
	if kty != 2 || alg != -7 || crv != 1 || !xok || !yok {
		return nil, 0, errMalformed
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, 0, errMalformed
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, 0, errMalformed
	}
	return pub, r.pos, nil
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func parseClientData(b []byte) (*clientData, error) {
	var cd clientData
	if err := json.Unmarshal(b, &cd); err != nil {
		return nil, errMalformed
	}
	return &cd, nil
}

func (cd *clientData) challengeMatches(expected []byte) bool {
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil {
		got, err = base64.URLEncoding.DecodeString(cd.Challenge)
		if err != nil {
			return false
		}
	}
	if len(got) != len(expected) {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ expected[i]
	}
	return diff == 0
}

func verifyAssertion(pub *ecdsa.PublicKey, authData, clientDataJSON, sig []byte) bool {
	h := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), h[:]...)
	digest := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}
