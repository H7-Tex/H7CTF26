# Paper Trail - solution

A deterministic metadata thread. Each step's output tells you exactly where to look next.

## 1. Seed: statement.pdf metadata
```
$ exiftool statement.pdf
Author   : Mara Chen
Keywords : editions, provenance, handle:mchen_prints
Creator  : printshop.social exporter
```
The handle `mchen_prints` (on printshop.social) is the pivot.

## 2. The matching export
The bundle has three `exports/*.json`; only `mchen_prints.json` matches the handle. Its **pinned**
post:
> "...they're baked into the print's own file. look at the metadata of my final print
> (gallery/final_print.jpg)."

## 3. The photo's metadata
```
$ exiftool gallery/final_print.jpg
Image Description : H7CTF{m3t4d4t4_g0ld3n_thr34d_0s1nt}
GPS Position      : 19.033 N, 72.826 E     # Mahalaxmi, Mumbai (confirming clue)
```

`H7CTF{m3t4d4t4_g0ld3n_thr34d_0s1nt}`

## Watch the decoys
`exiftool gallery/* | grep H7CTF` returns THREE `H7CTF{...}` strings - `sunset.jpg` and `studio.jpg`
carry fakes (`...n0t_th3_r34l_0n3...`, `...d3c0y...`). The pinned post is what tells you the real one
is in `final_print.jpg`. Grepping isn't enough; the thread is.
