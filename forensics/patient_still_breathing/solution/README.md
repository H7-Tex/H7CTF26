# The Patient Is Still Breathing: intended solution

Live SSH box; use `solution/solve.sh` as the reference walk (run it as `analyst`). The
chain is gated - each stage's output unlocks the next, so it can't be grepped or skipped.

## Path
1. **Foothold (flag v1).** The odd live process `[ci-worker/php-fpm]` (running as `ci`) is a
   shell the CI app spawned. It leads to the uploaded webshell
   `/var/www/html/ci/uploads/build_status.php`, which holds a base64 access token (**flag
   v1**) and the operator key `OP_KEY` (**K1**) - the key for the next stage.
2. **Cloaked implant (flag v2).** `/etc/ld.so.preload` shows a readdir-hook rootkit hiding
   `.sys_*` from `ls`. A process is running whose binary was deleted (`/proc/<pid>/exe ->
   .sys_agentd (deleted)`); its cmdline leaks the staging dir `/tmp/.sys_cache`. The dir's
   contents aren't hidden and open-by-path works, so read
   `/tmp/.sys_cache/agent.dat` and decrypt it with K1:
   `openssl enc -d -aes-256-cbc -pbkdf2 -k <K1> -in agent.dat` -> **flag v2** (+ it tells
   you the implant holds its key only in memory).
3. **Memory-only key (flag v3).** The implant keeps its session key **only in RAM** (not on
   disk, not in cmdline/environ). Dump the process memory
   (`sudo cat /proc/<pid>/maps` + read the mapped regions of `/proc/<pid>/mem`, or gcore),
   `strings | grep SESSIONKEY=` -> **SK**. `openssl ... -k <SK> -in exfil.enc` -> **flag v3**
   (+ the exfil manifest: the payment SDK was backdoored, and the closeout is sealed with
   the operator's source IP). Reboot the box and this key is gone - that's the point.
4. **Erased timeline (flag v4).** `auth.log` was cleaned of the operator's login, but the
   nginx access log still has the foothold hit - the real source IP; and the backdoored
   `payment-sdk-1.4.2.jar` has a faked `mtime` while its `ctime` matches the real
   intrusion. `openssl ... -k <that source IP> -in closeout.enc` -> **flag v4**.

## Why no shortcut
v2/v3/v4 are AES-CBC ciphertext keyed on the previous stage's finding (K1 -> SK -> real
IP), so `grep -r H7CTF /` yields nothing and you cannot reach a later flag first. The
memory-only key and the deleted-but-running binary exist only while the box is live.
