# Overexposed

**Category:** misc  **Difficulty:** medium  **Author:** abu

> The comms team blacked out the sensitive photo before it went public. Nothing left in the pixels, they swore.
>
> For a redaction, it reveals an awful lot.

Handout: `challenge/overexposed.png` (built by `challenge/gen.py`).

## Solution

`file` says PNG and it opens fine, a dark "redacted" box with nothing useful in the pixels. `binwalk` or a look at the tail of the file shows a ZIP end-of-central-directory record, so this is a PNG/ZIP polyglot. The flag is split into three pieces.

Part 1 is in the PNG itself. There's a compressed `zTXt` chunk with keyword `part1`, which is why `strings` misses it. `exiftool overexposed.png` or `Image.open(f).text` in PIL shows it: `06da61b`.

Now the ZIP side. `unzip overexposed.png` gives exactly one file, `readme.txt`:

```
This archive's directory lists one file. The directory is not the archive.
Members can exist without the index admitting them -- read the raw local headers.
And remember what you are looking at: a picture carries more than its pixels.
```

`binwalk -e` and Python's `zipfile` say the same thing, because they all read the central directory and trust it. But a ZIP is really a run of local file headers (`PK\x03\x04` + metadata + data) with a central directory at the end that is supposed to index them. Nothing forces it to index all of them. Here `part2.txt` and `part3.txt` have complete local headers in the bytes and are just left out of the directory.

So ignore the directory and walk the raw bytes. For each `PK\x03\x04`, read the compression method at +8, compressed size at +18, name length at +26, extra length at +28, name at +30, slice the data out and inflate it with `zlib.decompress(data, -15)`. That gives `part2.txt` = `5c60e08` and `part3.txt` = `7c87c9`.

```
python3 solution/solve.py challenge/overexposed.png
```

Flag: `H7CTF{06da61b5c60e087c87c9}`
