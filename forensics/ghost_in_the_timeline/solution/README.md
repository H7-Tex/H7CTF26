# Ghost in the Timeline: intended solution

```
# (a) the timestomp tell
debugfs -R "stat /home/jdoe/designs/roadmap.pdf" case_disk.img   # or istat / fls+istat (TSK)
# (b) recover the deleted archive and read the flag
python3 solve.py case_disk.img          # pure-python carve; or use foremost/extundelete
```

## Path
1. **Expose the backdating.** `roadmap.pdf` has `mtime`/`atime` set to June (the alibi),
   but its `ctime` and `crtime` are the real, recent date. An attacker can set mtime/atime
   with `touch -d`, but `ctime` (inode-change time) updates whenever the inode is touched
   and can't be set without moving the system clock - so `ctime != mtime` is the proof the
   file was actually handled recently. That says: look for what really happened that day.
2. **Find the deleted activity.** Around the real ctime, a `.cache/staging/q3_designs.zip`
   was created and deleted (the engineer swore they deleted nothing). The directory entry
   is gone, but ext4 does not wipe the data blocks on delete.
3. **Recover it.** Carve the ZIP out of the image's unallocated space (`foremost -t zip`,
   `extundelete`, `photorec`, or the `solve.py` carver) and unzip it. The archive is a
   deflated exfil manifest whose recovery token is the flag.

## Why a grep fails
The archive is DEFLATE-compressed, so the flag is not plaintext anywhere on the image
(`strings case_disk.img | grep H7CTF` returns nothing). You must recover and decompress
the deleted file. The timestamp story is what points you at the deleted activity in the
first place - two artifacts (metadata + unallocated data) reasoned together.
