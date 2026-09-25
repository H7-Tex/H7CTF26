// Tollgate - internal API gateway admin-token validator.
// Feed it the 16-char admin token; on a valid token it prints the bootstrap secret.
// build: go build -ldflags="-s -w" -trimpath -o tollgate .
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"strings"
)

func check(tok []byte) bool {
	if len(tok) != 16 {
		return false
	}
	ok := true
	for i := 0; i < 4; i++ {
		w := binary.BigEndian.Uint32(tok[i*4 : i*4+4])
		got := bits.RotateLeft32(w^xorK[i], int(rot[i])) + addA[i]
		if got != target[i] {
			ok = false
		}
	}
	return ok
}

func unlock(tok []byte) string {
	sum := sha256.Sum256(tok)
	block, _ := aes.NewCipher(sum[:])
	out := make([]byte, len(blob))
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(out, blob)
	if n := int(out[len(out)-1]); n > 0 && n <= 16 { // strip PKCS7
		out = out[:len(out)-n]
	}
	return string(out)
}

func main() {
	var tok string
	if len(os.Args) > 1 {
		tok = os.Args[1]
	} else {
		fmt.Print("admin token: ")
		s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		tok = strings.TrimRight(s, "\r\n")
	}
	b := []byte(tok)
	if !check(b) {
		fmt.Println("access denied")
		os.Exit(1)
	}
	fmt.Println("access granted. bootstrap secret:", unlock(b))
}
