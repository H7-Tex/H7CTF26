# Tollgate - writeup

A stripped Go crackme. The point isn't a clever algorithm - it's reversing a stripped Go binary
(no symbols, Go's own calling convention and data layout) to find the `check` routine and read
the constants it uses.

## 1. Recon
`tollgate` is a stripped x86-64 Go binary (`go build -ldflags="-s -w" -trimpath`). It asks for an
`admin token:`; any wrong 16-char input prints `access denied`. `strings` shows `access granted.
bootstrap secret:` but **no flag** - it's encrypted in the data section.

Reversing stripped Go: there are no symbols, but the token check is a small self-contained
function that reads 16 bytes, does four blocks of the same arithmetic, ANDs the results, and
gates the success path. In a decompiler you'll spot `bits.RotateLeft32`, `encoding/binary`
big-endian loads, and four hard-coded 32-bit constants plus four rotate amounts and four
comparison targets.

## 2. The check
The token is 16 bytes = four big-endian `uint32` words. Each word `w[i]` is checked as:

```
rotl32(w[i] ^ xorK[i], rot[i]) + addA[i]  ==  target[i]
```

The four constant arrays sit contiguously in the Go data section (right before the ciphertext):

```
xorK   = 7c5afe6c 1ddf8cdb 9362ba25 a689a4ca
rot    = 22 12 3 20
addA   = b441f5cf 3fbcb9d9 10ceff09 7b7f535f
target = 824f1143 7bc67cb2 4a86f74e 5b3e302e
```

## 3. Invert it
Each word is fully invertible (subtract, rotate right, xor):

```
w[i] = rotr32((target[i] - addA[i]) & 0xffffffff, rot[i]) ^ xorK[i]
```

Pack the four words big-endian -> `H7-T0LLG4TE-KEY1`.

## 4. The secret
On a valid token the binary computes `sha256(token)` and AES-256-CBC-decrypts (zero IV, PKCS7) a
48-byte blob in the data section. Feed the recovered token to the binary, or decrypt offline.
`solution/solve.py` does it all off the handout: invert the four words to get the token, then a
decryption oracle (`sha256(token)` key, sliding 48-byte window, accept valid PKCS7 + `H7CTF{`)
locates and decrypts the blob - so you don't even need to know exactly where the blob sits.

`H7CTF{g0_str1pp3d_t0llg4t3_w0rd_r3v}`

## Build
`python3 challenge/gen.py` (emits `data.go`) then
`cd challenge && go build -ldflags="-s -w" -trimpath -o tollgate .`. `tollgate.zip` is the handout.

## Teaching / realism
Stripped Go binaries are everywhere in modern infra tooling and Go malware, and they reverse very
differently from C (fat runtime, pclntab, interface dispatch, length-prefixed strings). Warden
teaches VM obfuscation on an 8-bit machine; Tollgate teaches Go-binary reversing with 32-bit word
math and a different crypto tail (sha256/AES-256) - a deliberately distinct RE skill.
