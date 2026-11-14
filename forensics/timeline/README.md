# Ghost in the Timeline

**Category:** forensics  **Difficulty:** medium  **Author:** abu

> An engineer stands accused of walking off with the product roadmap, and the alibi is tidy: the file predates their access, nothing was staged, nothing deleted, and every timestamp agrees.
>
> Timestamps are only as honest as whoever set them.

Handout: `case_disk.img`, a 20 MB ext4 image (hosted, URL and hash in `challenge.yml`). `stager/stage.sh` is the script that built it.

## Solution

Start with the file everyone is arguing about:

```
debugfs -R "stat /home/jdoe/designs/roadmap.pdf" case_disk.img
```

`mtime` and `atime` say June. `ctime` and `crtime` say much later. `touch -d` sets mtime/atime, but ctime updates on any inode change and you can't set it without moving the clock. So the June dates are forged and the file was handled recently. That's the alibi gone, and it tells you when to look.

Around that real time, `.cache/staging/q3_designs.zip` was created and then removed. The directory entry is gone, but ext4 doesn't wipe data blocks on delete, so the archive is still in unallocated space. Carve it with `foremost -t zip -i case_disk.img`, `extundelete`, `photorec`, or by scanning for `PK\x03\x04 ... PK\x05\x06`:

```
python3 solution/solve.py case_disk.img
```

The zip is deflated, which is why `strings case_disk.img | grep H7CTF` returns nothing. Unzip it; the exfil manifest inside has the recovery token, which is the flag.

Flag: `H7CTF{e211b7db9d4f5c9f0812}`
