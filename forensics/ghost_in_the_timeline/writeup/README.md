# Ghost in the Timeline: writeup

## The setup
A real ext4 disk image (`case_disk.img`) from a laptop in a leak investigation. The
suspect claims the leaked roadmap predates their access and that they deleted nothing - and
the file's timestamps agree with them. Forensics has to break both claims: the timestamps
were forged, and something was deleted.

## Why `strings` fails
The exfiltrated data is a DEFLATE-compressed ZIP that was deleted; the flag is not present
as plaintext anywhere on the image. `strings case_disk.img | grep H7CTF` returns nothing.
You have to (a) realize deleted activity exists, and (b) recover and decompress it.

## Solve
1. **Timestomp tell.** `debugfs -R "stat /home/jdoe/designs/roadmap.pdf" case_disk.img`
   (or istat / TSK) shows `mtime`/`atime` set to June but `ctime`/`crtime` at the real,
   recent date. `touch -d` can set mtime/atime, but `ctime` updates on any inode change and
   can't be set without moving the clock - so the June story is false and the file was
   really handled recently.
2. **Deleted activity.** That points to what happened around the real time: a
   `.cache/staging/q3_designs.zip` was created and `rm`'d. ext4 removes the directory entry
   but not the data blocks.
3. **Recover.** Carve the ZIP from unallocated space (`foremost -t zip -i case_disk.img`,
   `extundelete`, `photorec`, or the pure-python carver in `solve.py` that scans for the
   `PK\x03\x04 ... PK\x05\x06` structure), then unzip. The archive is the exfil manifest;
   its recovery token is the flag.

## Notes
- Genuinely built (real mkfs.ext4 + loop mount + touch-backdating + staged-then-deleted
  deflated zip); opens in TSK/autopsy/foremost like an acquired disk.
- Anti-agent: the metadata-vs-unallocated two-artifact reasoning, plus recovery of a
  compressed deleted file, is real dead-box DFIR - not a grep.
- Real basis: timestomping (a MITRE ATT&CK anti-forensics technique) and the fact that
  ext4 leaves deleted file data on disk until overwritten.
