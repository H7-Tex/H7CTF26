# The Patient Is Still Breathing

**Category:** forensics  **Difficulty:** insane  **Author:** abu

> 03:14 - an alert fires on ci-runner-03, the build server behind our payment SDK. The box is live and the actor may still be on it; don't reboot, or whatever lives only in memory is gone. You have an analyst SSH shell with sudo.
>
> Reconstruct the intrusion and capture what a reboot would erase. Four flags, each leading to the next.

Per-team live box over SSH, four dynamic flags (`FLAG_V1`..`FLAG_V4`). The container needs `SYS_PTRACE` for the memory dump. Everything on it is a benign stand-in for the real thing; the staging scripts delete themselves after boot.

```
docker build -t patient:local challenge/
docker run -d --cap-add=SYS_PTRACE -p 127.0.0.1:2222:22 \
  -e FLAG_V1=... -e FLAG_V2=... -e FLAG_V3=... -e FLAG_V4=... \
  -e ANALYST_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" patient:local
ssh -p 2222 analyst@127.0.0.1
```

## Solution

The four stages are chained. v2, v3 and v4 are AES-CBC ciphertext keyed on whatever the previous stage gave you, so `grep -r H7CTF /` returns nothing and you can't skip ahead. `solution/solve.sh` walks the whole thing.

**v1, foothold.** `ps` shows a process calling itself `[ci-worker/php-fpm]` running as `ci`. It's a shell the CI app spawned, and it leads to the uploaded webshell at `/var/www/html/ci/uploads/build_status.php`. That file has a base64 token (flag 1) and the operator key `OP_KEY`, which we'll call K1.

**v2, cloaked implant.** `/etc/ld.so.preload` loads a readdir hook that hides anything named `.sys_*` from `ls`. It's file based, so `LD_PRELOAD=` doesn't turn it off. You don't need to remove it anyway. One process has a deleted binary (`/proc/<pid>/exe -> .sys_agentd (deleted)`) and its cmdline leaks `/tmp/.sys_cache`. Only the directory name is hidden, and opening by path works:

```
openssl enc -d -aes-256-cbc -pbkdf2 -k "$K1" -in /tmp/.sys_cache/agent.dat
```

That gives flag 2 and a note that the implant keeps its key in memory only.

**v3, the key that only lives in RAM.** The session key isn't on disk, in cmdline or in environ. Dump the readable regions from `/proc/<pid>/maps` out of `/proc/<pid>/mem` (or `gcore`) and grep for `SESSIONKEY=`. Decrypt `exfil.enc` with it for flag 3. The manifest says the payment SDK was backdoored and the closeout is sealed with the operator's source IP. Reboot the box and this key is gone, which is the whole point of the challenge.

**v4, erased timeline.** The operator's login was scrubbed from `auth.log`, but the nginx access log still has the request that hit the webshell, with the real source IP. The backdoored `payment-sdk-1.4.2.jar` also has a faked `mtime` while its `ctime` lines up with the intrusion. Decrypt `closeout.enc` with that IP as the passphrase for flag 4.

Flags are dynamic, one set per team.
