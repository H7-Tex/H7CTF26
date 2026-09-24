# The Patient Is Still Breathing: writeup

## The setup
A per-team live, compromised CI/build server (`ci-runner-03`) reached over SSH. The player
is the on-call IR analyst: the box is running and the actor may still be active, so the task
is live-response - reconstruct the intrusion and capture the volatile evidence before a
reboot destroys it. Four flags form a hard chain where each finding unlocks the next.

## Why there's no grep / no skipping
Flags v2, v3, v4 are AES-CBC ciphertext keyed on the previous stage's recovered secret
(webshell operator key -> in-memory session key -> real source IP). `grep -r H7CTF{ /`
finds nothing, and you cannot decrypt a later stage without having done the earlier one. The
key for stage 3 exists only in a running process's RAM, so it can't be recovered at all from
a dead image - you have to work the live box.

## Solve
1. **Foothold (v1).** A process masquerading as `[ci-worker/php-fpm]` runs as `ci`; it's a
   shell the CI app spawned. It points to the uploaded webshell
   `/var/www/html/ci/uploads/build_status.php`, which contains a base64 token (v1) and the
   operator key K1.
2. **Cloaked implant (v2).** `/etc/ld.so.preload` reveals a readdir-hook rootkit hiding
   `.sys_*`. A running process has a deleted binary (`/proc/<pid>/exe -> .sys_agentd
   (deleted)`), and its cmdline leaks `/tmp/.sys_cache`. Decrypt `agent.dat` there with K1
   -> v2.
3. **Memory-only key (v3).** Dump the implant's `/proc/<pid>/mem`, recover `SESSIONKEY=...`,
   decrypt `exfil.enc` -> v3 and the exfil manifest (backdoored payment SDK; closeout sealed
   with the operator's source IP).
4. **Erased timeline (v4).** The operator wiped their login from `auth.log`, but the nginx
   access log still shows the foothold request's source IP, and the backdoored artifact's
   `mtime` is faked while `ctime` matches the real intrusion. Decrypt `closeout.enc` with
   that IP -> v4.

## Notes
- Live per-team container over SSH; everything is a benign daemon reproducing a real
  forensic footprint - no actual malware. Needs SYS_PTRACE for the memory acquisition.
- Anti-agent by construction: a living system to drive (not an artifact to grep), a strict
  gated chain, and a crown-jewel secret that only exists in RAM.
- Real basis: this is the textbook reason responders acquire live before pulling the plug -
  in-memory keys, deleted-but-running implants, LD_PRELOAD rootkits, and multi-source log
  correlation are exactly modern Linux IR.
