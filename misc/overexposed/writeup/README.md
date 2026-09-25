# Overexposed

**Category:** misc · **Difficulty:** hard

## Premise
A single handout file, `overexposed.png`, that renders as a dull "redacted" image. It is a
**polyglot**: valid as a PNG *and* valid as a ZIP at the same time. The flag is split into three
fragments, and each fragment is recovered by reading the same bytes as a different format — and
by refusing to trust the tool that reads it for you. This is the real "format confusion" /
parser-differential problem: two parsers, one byte-stream, two different truths.

## Recon
- `file overexposed.png` -> PNG image. It opens and renders (nothing useful in the pixels).
- `binwalk overexposed.png` / a hex look at the tail -> there's a ZIP end-of-central-directory
  record. The file is also an archive.
- `exiftool overexposed.png` -> a `part1` comment: the first fragment (stored as a compressed
  `zTXt` chunk, so `strings` misses it).

## The trap
`unzip overexposed.png` lists and extracts exactly one file, `readme.txt`:

```
This archive's directory lists one file. The directory is not the archive.
Members can exist without the index admitting them -- read the raw local headers.
And remember what you are looking at: a picture carries more than its pixels.
```

`binwalk -e` and Python's `zipfile` agree: one member. All three are **central-directory
driven** — they read the ZIP's table of contents and trust it. But a ZIP is really a sequence of
**local file headers** (each `PK\x03\x04` + metadata + data), followed by a central directory
that is *supposed* to index them. Nothing enforces that it indexes them all. Here, two members
(`part2.txt`, `part3.txt`) have complete local file headers in the byte-stream but are omitted
from the central directory, so every directory-driven tool is blind to them.

This is not a toy: mismatches between what the central directory advertises and what the local
headers actually contain are a real evasion class — the 2024 "concatenated ZIP" phishing wave
(different extractors disagree on contents) and the Android "Master Key" bug (signature verified
against one entry, a different entry installed) are the same idea.

## Exploit
Ignore the directory. Walk the raw bytes for `PK\x03\x04`, parse each local file header
(compression method at +8, compressed size at +18, name length at +26, extra length at +28,
name at +30), slice out the compressed data, and inflate it (raw deflate, `zlib.decompress(...,
-15)`). That yields `readme.txt`, `part2.txt`, and `part3.txt`.

Fragments:
- part1 (PNG zTXt): `p0lyg10t_`
- part2 (unlisted local header): `th3_1nd3x_l13s_`
- part3 (unlisted local header): `r34d_th3_r4w_byt3s`

`H7CTF{p0lyg10t_th3_1nd3x_l13s_r34d_th3_r4w_byt3s}`

`solution/solve.py` does all three reads and prints the flag.

## Why it's fair, not guessy
Every step is a signposted format fact, not a hunch: the PNG chunk is standard metadata; the ZIP
"there is more than the directory admits" is stated in the decoy and provable from the byte
layout; the recovery is deterministic parsing. No stego guessing, no tool-roulette. The flag is
never contiguous in the file and each fragment is compressed, so `strings`/`grep` and
directory-driven extractors cannot shortcut it.
