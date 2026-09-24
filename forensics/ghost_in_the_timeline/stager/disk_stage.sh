#!/bin/bash
set +e
sudo apt-get install -y -qq e2fsprogs foremost zip unzip >/dev/null 2>&1
FLAG="H7CTF{gh0st_1n_th3_t1m3l1n3}"
IMG=/home/abu/case_disk.img
MP=/mnt/df_disk
rm -f $IMG
dd if=/dev/zero of=$IMG bs=1M count=20 status=none
mkfs.ext4 -q -F -L CASE-2026-0917 $IMG
sudo mkdir -p $MP
sudo mount -o loop $IMG $MP
sudo mkdir -p $MP/home/jdoe/designs $MP/home/jdoe/.cache/staging $MP/var/log

# ordinary content
echo "sprint planning notes, nothing sensitive" | sudo tee $MP/home/jdoe/designs/notes.txt >/dev/null
printf 'Sep 17 02:11:04 ws-jdoe sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/bin/zip\n' | sudo tee $MP/var/log/auth.log >/dev/null

# the "leaked" doc: mtime/atime backdated (the alibi), but ctime = now (the tell)
printf '%%PDF-1.4\n%% internal product roadmap - confidential\n' | sudo tee $MP/home/jdoe/designs/roadmap.pdf >/dev/null
sudo touch -d "2026-06-01 08:30:00" $MP/home/jdoe/designs/roadmap.pdf

# the REAL exfil: a DEFLATED zip holding the flag (padded so zip compresses it,
# so the flag is not plaintext on the raw image -> recovery is actually required)
{ echo "EXFIL MANIFEST :: Q3 product designs staging bundle";
  for i in $(seq 1 60); do echo "asset_$i designs/roadmap_part_$i.pdf sha256=$(head -c 16 /dev/urandom | xxd -p)"; done;
  printf 'recovery token: %s\n' "$FLAG";
  for i in $(seq 61 120); do echo "asset_$i designs/spec_part_$i.docx sha256=$(head -c 16 /dev/urandom | xxd -p)"; done;
} > /tmp/secret.txt
zip -q -9 -j /tmp/exfil.zip /tmp/secret.txt
sudo cp /tmp/exfil.zip $MP/home/jdoe/.cache/staging/q3_designs.zip
sync
sudo rm $MP/home/jdoe/.cache/staging/q3_designs.zip
sync; sync
sudo umount $MP
shred -u /tmp/secret.txt /tmp/exfil.zip 2>/dev/null

echo "=== roadmap.pdf timestamps (mtime backdated vs ctime/crtime = real) ==="
debugfs -R "stat /home/jdoe/designs/roadmap.pdf" $IMG 2>/dev/null | grep -iE "crtime|ctime|mtime|atime"
echo "=== flag NOT in plaintext on the image ==="
grep -ac "H7CTF" $IMG && echo "LEAK" || echo "clean (0)"
echo "=== recover deleted zip via foremost ==="
rm -rf /tmp/rec; foremost -q -t zip -i $IMG -o /tmp/rec >/dev/null 2>&1
ls -1 /tmp/rec/zip/ 2>/dev/null
for z in /tmp/rec/zip/*.zip; do unzip -p "$z" 2>/dev/null | grep -o "H7CTF{[^}]*}" && echo "  ^ RECOVERED"; done
echo "=== image size ==="; ls -lh $IMG
