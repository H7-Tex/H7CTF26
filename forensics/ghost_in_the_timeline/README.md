# Ghost in the Timeline

`forensics` / `medium` / static handout (real ext4 image, 20 MB), static flag.

Disk / anti-forensics. A real ext4 disk image where a "leaked" document has **backdated
mtime/atime** (the suspect's alibi) but a real, recent **ctime/crtime** (the tell), and a
**deleted** exfil archive sits recoverable in unallocated space. The player uses the
timestamp divergence to establish the real timeline, then carves and decompresses the
deleted ZIP to recover the flag.

## Realism
Genuinely built on the lab VM: a real `mkfs.ext4` image, populated over a loop mount, with
`touch -d` backdating the doc's mtime/atime (ctime auto-updates to now, exactly like a real
timestomp), and a real staged-then-`rm`'d deflated ZIP left in unallocated blocks. The
image opens in TSK / debugfs / autopsy / foremost like any acquired disk.

## Files
- `challenge.yml` : definition (static flag, small attachment handout).
- `stager/disk_stage.sh` : the exact script used to build the image on the lab VM (repro; NOT shipped).
- `solution/solve.py` : reference solver (carve the deleted ZIP from the image, unzip, flag).
- `solution/README.md` : full intended path (debugfs timestomp tell + carve/recover).
- `writeup/README.md` : full explanation.
- `handout/case_disk.img` : the real 20 MB ext4 image (Anvil attachment; kept in-repo for repro).

## Solve (spoiler)
`debugfs -R "stat .../roadmap.pdf"` shows mtime/atime = June (forged) vs ctime/crtime =
the real recent date. That points at recent deleted activity; carve the deleted
`q3_designs.zip` from unallocated space (foremost/extundelete/photorec, or solve.py) and
unzip -> the flag. Validated end-to-end (grep of the raw image finds no plaintext flag).

## Flag model
Small real static image -> Anvil attachment + static flag (anti-share = the forensic
effort + score decay). Could be made per-team dynamic (regenerate the image with a per-team
flag at launch) if we want it in the dynamic-flag set.

## Fairness / anti-agent notes
- Not `strings`-recoverable: the flag lives in a DEFLATE-compressed deleted ZIP; nothing
  readable on the raw image until you recover and decompress it.
- Two-artifact reasoning: the metadata (ctime vs mtime) tells you *when* and *that*
  something was deleted; the unallocated data is *what*. Neither alone gives the flag.
- Teaches a real reflex (ctime can't be forged with touch) + real recovery (ext4 doesn't
  wipe data blocks on delete).
- Real basis: timestomping anti-forensics + deleted-file recovery, core dead-box DFIR.
