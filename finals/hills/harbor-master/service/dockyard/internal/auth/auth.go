package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var privateKey ed25519.PrivateKey
var publicKey ed25519.PublicKey

const keyID = "dockyard-token-1"

// LoadOrGenKey loads the Ed25519 key from path, generating it if absent.
func LoadOrGenKey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate key: %w", err)
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(priv)), 0600); err != nil {
			return fmt.Errorf("write key: %w", err)
		}
		privateKey = priv
		publicKey = pub
		return nil
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("decode key: %w", err)
	}
	privateKey = ed25519.PrivateKey(raw)
	publicKey = privateKey.Public().(ed25519.PublicKey)
	return nil
}

// AccessEntry is one repository access grant in a token.
type AccessEntry struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

type Claims struct {
	jwt.RegisteredClaims
	Access []AccessEntry `json:"access,omitempty"`
	Type   string        `json:"type,omitempty"`
	Scopes []string      `json:"scopes,omitempty"`
}

// SignToken mints an Ed25519-signed JWT for the given subject and access list.
func SignToken(sub string, access []AccessEntry) (string, error) {
	now := time.Now()
	c := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "dockyard",
			Subject:   sub,
			Audience:  jwt.ClaimStrings{"dockyard"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		Access: access,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	t.Header["kid"] = keyID
	return t.SignedString(privateKey)
}

// SignFineToken mints a fine-grained token for glob secret scopes.
func SignFineToken(sub string, scopes []string) (string, error) {
	now := time.Now()
	c := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "dockyard",
			Subject:   sub,
			Audience:  jwt.ClaimStrings{"dockyard"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
		Type:   "fine",
		Scopes: scopes,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	t.Header["kid"] = keyID
	return t.SignedString(privateKey)
}

// ParseToken validates an Ed25519-signed JWT and returns the claims.
func ParseToken(tokenStr string) (*Claims, error) {
	c := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, c, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	}, jwt.WithAudience("dockyard"))
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ParseTokenUncheckedKid is like ParseToken but also trusts keys from the log.
// This is the TRUST ANCHOR bug (V3 stretch) placeholder - currently same as ParseToken.
func ParseTokenUncheckedKid(tokenStr string, extraKey ed25519.PublicKey) (*Claims, error) {
	return ParseToken(tokenStr)
}

// ErrBadPassword is returned when a password check fails.
var ErrBadPassword = errors.New("invalid password")

func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), 10)
	return string(b), err
}

func CheckPassword(hash, pw string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw))
}

// DigestHex returns the sha256 hex digest of data with "sha256:" prefix.
func DigestHex(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

// PublicKeyHex returns the hex-encoded public key.
func PublicKeyHex() string {
	return hex.EncodeToString(publicKey)
}

// PublicKey returns the raw public key.
func PublicKeyRaw() ed25519.PublicKey {
	return publicKey
}

// PrivateKeyRaw returns the raw private key for log signing.
func PrivateKeyRaw() ed25519.PrivateKey {
	return privateKey
}

// ParseScope parses a Docker token scope string "repository:ns/repo:pull,push".
// BUG (V2): NAME is taken literally with no OCI name validation.
// The comma-splitting of names happens in registry.go checkAccess.
func ParseScope(scope string) (typ, name string, actions []string, err error) {
	parts := strings.SplitN(scope, ":", 3)
	if len(parts) != 3 {
		err = fmt.Errorf("invalid scope: %q", scope)
		return
	}
	typ = parts[0]
	name = parts[1] // BUG: no OCI name validation here
	actions = strings.Split(parts[2], ",")
	return
}
