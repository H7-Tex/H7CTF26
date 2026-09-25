# Overexposed — reference solution

The handout `overexposed.png` is a **PNG + ZIP polyglot**. The flag is split into three
fragments, one per way of reading the file.

**part1 — as an image.** The PNG carries a compressed `zTXt` chunk with keyword `part1`.
`exiftool overexposed.png` (or `Image.open(f).text`) reveals it. Not visible to `strings`
because zTXt is deflate-compressed.

**part2, part3 — as an archive, against the grain.** `unzip overexposed.png` (and `binwalk -e`,
and Python's `zipfile`) extract only `readme.txt`. That's the trap: those tools trust the
**central directory**, the archive's table of contents — and nothing in the ZIP format forces
the directory to list every member. Two members (`part2.txt`, `part3.txt`) have real **local
file headers** in the bytes but are simply absent from the directory, so directory-driven tools
never see them. Scan the file for the local-header signature `PK\x03\x04`, parse each header,
and inflate the data.

Assemble: `H7CTF{` + part1 + part2 + part3 + `}`
= `H7CTF{p0lyg10t_th3_1nd3x_l13s_r34d_th3_r4w_byt3s}`.

## Run
```
python3 solve.py overexposed.png
```
