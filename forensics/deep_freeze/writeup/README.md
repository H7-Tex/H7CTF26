# Deep Freeze: writeup

## The setup
A real Linux memory image (`memory.lime`, captured live with `avml`) from a workstation
caught mid-ransomware-encryption, plus one file the malware had just locked
(`Q3_patient_records.pdf.locked`). The machine was shut down after the acquisition, so the
malware process and its key are gone from disk - but the SOC preserved them by imaging RAM
first. That is the whole lesson: volatile evidence (here, the encryption key) survives only
in the memory image.

## Why `strings` fails
The `.locked` file is AES-CBC ciphertext; the flag lives in the plaintext PDF that only
exists after decryption. The memory image holds the *key*, not the flag. So there is
nothing to grep - you have to recover the key and decrypt.

## Solve
1. **Find the malware in memory.** `vol -f memory.lime linux.pslist` shows a running
   process with no corresponding on-disk binary (it's gone). `linux.malfind` /
   `linux.proc.Maps` show its anonymous heap - the "caught mid-run" state the acquisition
   captured.
2. **Recover the AES-256 key.** The ransomware never wiped its key, so the expanded key
   schedule is still resident. `aeskeyfind memory.lime` scans the image for AES key
   schedules and prints candidates (the real key plus some false positives).
3. **Decrypt.** `Q3_patient_records.pdf.locked` is AES-CBC with the IV as its first 16
   bytes. Test each candidate: the correct key decrypts the body to a `%PDF-` document.
   Strip PKCS7 padding, open the PDF - the recovery token inside is the flag.

## Notes
- Genuinely captured: a real `avml` image of a live VM, Volatility-3-parseable and
  aeskeyfind-scannable; the "malware" was a benign stager that only reproduced the
  footprint (encrypt one self-made document, keep the key resident).
- Anti-agent: a multi-GB real memory image + key-recovery-by-structure + cross-artifact
  decryption is the DFIR modality agents crater on; there is no shortcut that isn't the
  attack, and flag-by-decryption removes all guessing.
- Real basis: the canonical reason responders acquire RAM before pulling the plug -
  encryption keys, injected code, and network state live only in memory.
