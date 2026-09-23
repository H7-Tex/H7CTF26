# Trace Amounts

`hardware` / `hard` / on-demand per-team instance (docker, HTTP), dynamic flag.

A power side-channel challenge. A smart card runs AES-128; the player is given a batch of
power traces (one per encryption) with the known plaintexts, plus a secret the card
encrypted with its key. The card never exposes the key, but its power draw leaks the
Hamming weight of the round-1 S-box output. The player runs Correlation Power Analysis
(CPA) to recover the key byte-by-byte, then decrypts the secret to get the flag.

## Delivery
Per-team live instance. On launch the container generates a fresh AES key, a batch of
traces with per-byte S-box leakage plus noise, the matching plaintexts, and encrypts
`$FLAG` under the key. It serves `traces.npy`, `plaintexts.npy`, and `secret.enc` over
HTTP. Recover the key offline, decrypt, submit the flag.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/aes_sbox.py` : AES S-box + Hamming-weight table (shared by gen and solver).
- `challenge/gen.py` : the trace synthesizer (HW-of-S-box leakage + noise + AES-encrypt the flag).
- `challenge/serve.py` : instance entrypoint (generate + serve the three files).
- `challenge/Dockerfile` : the instance image (`h7ctf26/trace-amounts`, numpy + pycryptodome).
- `solution/solve.py` : reference solver (CPA per key byte, then AES-decrypt the secret).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/ta   # writes traces.npy, plaintexts.npy, secret.enc
python3 solution/solve.py /tmp/ta                      # -> recovers the key, decrypts the flag
```
Validated 8/8 across random keys/flags; CPA runs in ~4 s. The flag never appears in
`strings` of any file (only its AES ciphertext ships).

## The attack (spoiler)
Leakage model: at a fixed sample per key byte, power `~ HW(SBOX[plaintext_byte XOR
key_byte])` plus noise. CPA: for each of the 16 key bytes, and each of the 256 key-byte
hypotheses, compute the predicted Hamming weight across all traces and correlate it with
every time sample. The correct hypothesis produces a sharp correlation peak at the byte's
leakage sample. Concatenate the 16 recovered bytes -> the AES-128 key -> decrypt
`secret.enc` (ECB) -> the flag.

## Fairness / anti-agent notes
- Per-team dynamic flag; fresh key/traces each launch.
- Not `strings`-recoverable: only the AES ciphertext of the flag is shipped; the key
  exists only implicitly in the noisy power traces.
- Requires a real, implemented side-channel attack (CPA/DPA): a HW-leakage model, the
  correct AES intermediate (round-1 S-box output), and per-byte correlation across traces.
  There is no shortcut that isn't the attack.
- Real basis: correlation power analysis against unprotected AES in smart cards / crypto
  tokens, the canonical hardware side-channel.
