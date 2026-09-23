# Trace Amounts: writeup

## The setup
A smart card runs AES-128 to authorize each tap. A current probe on its power line captured
a batch of authorizations: for each, the power trace (`traces.npy`) and the known plaintext
(`plaintexts.npy`). The card also encrypted a secret with its key (`secret.enc`). The key
lives in hardware and is never transmitted, but the card's power consumption depends on the
intermediate values it computes. This is the canonical hardware side channel: unprotected
AES leaks, and Correlation Power Analysis (CPA) turns that leak into the key.

## Why `strings` fails
No file contains the key or the flag. `secret.enc` is only the AES ciphertext of the flag,
and the key appears nowhere: it exists only as a faint statistical relationship between the
data the card handles and the power it draws. You recover it by doing the attack.

## Solve
1. **Model the leak.** For AES, the standard attack point is the round-1 S-box output
   `v = SBOX[plaintext_byte XOR key_byte]`, and unprotected hardware leaks about `HW(v)`
   (the Hamming weight).
2. **CPA, one key byte at a time.** For key byte `i` and each hypothesis `k` in 0..255,
   build the model vector `HW(SBOX[pt[:,i] XOR k])` over all N traces and correlate it,
   with Pearson correlation, against every time sample of the traces. The correct `k`
   produces a sharp correlation peak at the sample where byte `i` is processed; wrong
   guesses stay in the noise.
3. **Assemble + decrypt.** The 16 winning bytes are the AES-128 key. Decrypt `secret.enc`
   (AES-128-ECB, remove PKCS7 padding) to get the flag.

## Notes
- The traces are synthesized (a Hamming-weight leakage model plus Gaussian noise and a bit
  of background activity), but the attack is the real thing: the same CPA you would run on a
  ChipWhisperer capture. The reference solver recovers all 16 bytes from ~500 traces in a
  few seconds.
- Anti-agent: this is a genuine implemented side-channel attack (correct intermediate,
  leakage model, correlation over a batch). There is no path to the flag that isn't CPA.
- Real basis: correlation power analysis against unprotected AES in smart cards and crypto
  tokens, and the countermeasures (masking, hiding) that exist because of it.
