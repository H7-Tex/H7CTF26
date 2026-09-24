# Deep Freeze: intended solution

```
zstd -d memory.lime.zst
aeskeyfind memory.lime > keys.txt
python3 solve.py Q3_patient_records.pdf.locked keys.txt
```

## Path
1. **Confirm the incident in memory.** `vol -f memory.lime linux.pslist` (Volatility 3)
   shows a `python3` process that has no matching binary on the (now-dead) disk. Its
   `linux.proc.Maps` / `linux.malfind` show an anonymous heap holding the key material.
   This is the "process caught mid-run" the SOC preserved.
2. **Recover the AES key.** The ransomware never wiped its key, so the expanded AES-256
   key schedule is still resident. `aeskeyfind memory.lime` scans the image and prints the
   candidate keys (you'll get the real one plus false positives - that's expected).
3. **Decrypt.** `Q3_patient_records.pdf.locked` is AES-CBC with the IV as its first 16
   bytes. Try each candidate key: the correct one decrypts the ciphertext to a file
   beginning with `%PDF-`. Strip PKCS7 padding, open the PDF, read the recovery token.

The flag is the recovery token inside the decrypted PDF. It is never present in the locked
file or as plaintext in memory - it only appears once you find the key and decrypt.

## Notes for organizers
- Validated end-to-end on the real captured image: aeskeyfind returned 54 candidates, one
  decrypted the file to the PDF containing the flag.
- `solve.py` is the deterministic crypto core (test candidates -> decrypt). aeskeyfind and
  Volatility are the standard external tools the player runs; they are not reimplemented
  here on purpose (a player uses the real tools).
