# Deep Freeze

`forensics` / `hard` / static handout (real Linux memory image), static flag.

Memory-forensics flagship. A workstation was caught mid-ransomware-encryption and its RAM
acquired live (real `avml` capture) before shutdown; the malware process (and its key) are
gone from disk but still in the image. The player opens the image in Volatility 3, finds
the malware process, recovers the resident AES-256 key with `aeskeyfind`, and decrypts the
one handed-out `.locked` file to a PDF containing the flag. Flag-by-decryption: zero
guessing, and the flag exists nowhere until the key is recovered.

## Realism
This is a genuine artifact, not synthesized: a real Linux RAM image captured with `avml`
on a live VM whose (benign) stager reproduced only the forensic footprint of ransomware
caught mid-run - it AES-encrypted one document it created itself and kept the key resident,
nothing else. The image is fully Volatility-3-parseable and `aeskeyfind`-scannable.

## Files
- `challenge.yml` : definition (static flag, static handout).
- `stager/ransomware_footprint.py` : the benign stager run on the throwaway lab VM to
  produce the footprint (kept for reproducibility; NOT shipped to players).
- `solution/solve.py` : reference solver (test aeskeyfind candidates -> decrypt -> flag).
- `solution/README.md` : full intended path (Volatility -> aeskeyfind -> decrypt).
- `writeup/README.md` : full explanation.
- handout (hosted separately, NOT in git): `memory.lime.zst` (real RAM image, ~hundreds of
  MB compressed / 3 GB raw) + `Q3_patient_records.pdf.locked`.

## Flag model
The RAM image is one identical multi-GB artifact for the whole field (the forensics hosting
economy: capture once, ship statically), so this challenge uses a **static flag**. The
real barrier is the multi-GB download + a genuine memory-forensics chain; combined with
score decay that's the intended anti-share posture for a big-artifact challenge. (The
smaller-artifact forensics - network pcap, disk, Android - can instead be per-team dynamic,
generated on demand, like the hardware set.)

## Fairness / anti-agent notes
- Not `strings`-recoverable: the flag is only in the decrypted PDF; the `.locked` file and
  the memory image contain no plaintext flag.
- The moat is holding a multi-GB real memory image and recovering key material by structure
  (aeskeyfind on the resident AES schedule) then decrypting - a real DFIR chain across two
  artifacts (image + locked file), exactly the modality agents are weakest at.
- Flag-by-decryption = no guess-the-flag; a wrong key visibly fails (no `%PDF-`).
- Real basis: ransomware whose key is recoverable from a live-acquired RAM image, the
  canonical "why we image memory before pulling the plug" lesson.
