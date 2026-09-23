# Trace Amounts: intended solution

Launch the instance, download `traces.npy` / `plaintexts.npy` / `secret.enc`, then:
```
python3 solution/solve.py <dir-with-the-three-files>
```
Runs CPA to recover the AES-128 key, then decrypts `secret.enc` and prints the flag.

## Path (what a player does)
1. Load `traces.npy` (float32, N x T power traces) and `plaintexts.npy` (uint8, N x 16).
2. **Pick the attack point.** The classic CPA target on AES is the round-1 S-box output:
   `v = SBOX[plaintext_byte XOR key_byte]`. Unprotected hardware leaks roughly the Hamming
   weight of `v`.
3. **CPA per key byte.** For key byte `i`:
   - For each hypothesis `k` in 0..255, compute the model `HW(SBOX[pt[:,i] XOR k])` across
     all traces.
   - Correlate that length-N model vector against every column (time sample) of the traces
     (Pearson correlation).
   - The `k` that yields the largest peak correlation (at the sample where byte `i` leaks)
     is the correct key byte.
4. Concatenate the 16 recovered bytes into the AES-128 key.
5. Decrypt `secret.enc` with the key (AES-128-ECB, unpad PKCS7) -> the flag.

## Why there is no shortcut
The key is never in any file; it only shows up as a faint statistical dependence between
the plaintext-derived S-box Hamming weight and the power samples. Recovering it *is* the
side-channel attack: the right intermediate, a leakage model, and correlation over the
batch of traces. `strings`/grep find nothing but the AES ciphertext.
