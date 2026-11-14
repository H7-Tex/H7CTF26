# Deep Freeze

**Category:** forensics  **Difficulty:** hard  **Author:** abu

> At 03:14 the ransomware reached St. Cascade General, and by the time responders made the nurses' station it was still chewing through patient files. They froze the workstation where it stood and only then cut the power.
>
> Catch a thief mid-reach and they are still holding what they grabbed.

Handout (hosted, too big for git): `memory.lime.zst` (live `avml` capture of a Linux VM) and `Q3_patient_records.pdf.locked`. URLs and hashes are in `challenge.yml`.

`stager/ransomware.py` is the harmless script I ran on the lab VM before taking the capture. It encrypts one document it created itself and keeps the key in memory. Nothing else.

## Solution

The locked file is AES-CBC ciphertext and the flag is inside the plaintext PDF, so grepping either artifact gets you nothing. The key is the thing that survived, because RAM was imaged before the power was cut.

```
zstd -d memory.lime.zst
vol -f memory.lime linux.pslist
```

There's a `python3` process with no matching binary on disk. `linux.proc.Maps` / `linux.malfind` show the anonymous heap it was working out of. That's the ransomware caught mid-run.

It never wiped its key, so the expanded AES-256 key schedule is still sitting in memory. `aeskeyfind` finds key schedules by structure:

```
aeskeyfind memory.lime > keys.txt
```

You get a pile of candidates (54 on this image, most of them false positives). The IV is the first 16 bytes of the `.locked` file. Try each key; the right one decrypts to something starting with `%PDF-`. Strip the PKCS7 padding and open the PDF. The recovery token in it is the flag.

```
python3 solution/solve.py Q3_patient_records.pdf.locked keys.txt
```

Flag: `H7CTF{bf3a8e98115450c654b4}`
