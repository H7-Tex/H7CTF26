# The Patient Is Still Breathing

`forensics` / `hard` / live per-team instance (SSH), 4 gated dynamic flags. The forensics
capstone: live-response DFIR.

A per-team **live, compromised** Linux build server the player SSHes into (with sudo, as an
IR analyst) and must reconstruct + capture before a reboot wipes the volatile evidence.
Four flags in a hard dependency chain - each stage's finding decrypts the next, so nothing
can be grepped or solved out of order:
1. **v1 foothold** - the uploaded webshell (holds the token + the operator key K1).
2. **v2 cloaked implant** - defeat an `LD_PRELOAD` readdir rootkit, recover a deleted-but-
   running implant from `/proc`, decrypt its config with K1.
3. **v3 memory-only key** - dump the running implant's RAM for a session key that's on no
   disk, decrypt the exfil manifest. (Reboot = gone; this is the "why we don't pull the
   plug" flag.)
4. **v4 erased timeline** - the wiped-but-corroborated login (nginx log) + a `ctime`-vs-
   `mtime` timestomp give the real source IP, which unseals the closeout.

## Realism / why live
Real IR responders triage a *running* box before imaging, precisely to catch volatile
evidence (in-memory keys, deleted-but-running processes, live sockets). Everything here is a
benign daemon reproducing that footprint (inert webshell, a benign deleted-but-running
process holding a key, a real readdir-hook rootkit, a timestomp, a beacon note) - no real
malware. Structurally anti-agent: there is no artifact to download and grep; you must drive
a living system through multi-step live-response.

## Files
- `challenge.yml` : definition (4 named dynamic flags; live docker; SSH; needs SYS_PTRACE).
- `challenge/Dockerfile` + `entrypoint.sh` + `setup.sh` : build the live box; stage the
  intrusion at boot from the injected FLAG_V1..V4 (staging sources are wiped from the
  container after boot so players can't read the walkthrough).
- `challenge/rootkit.c` : the benign readdir-hook rootkit (hides `.sys_*` from `ls`).
- `challenge/implant.c` : the benign implant (session key resident in RAM only; binary
  deleted after launch).
- `solution/solve.sh` : reference walkthrough (all four gated stages).
- `writeup/README.md` : full explanation.

## Local test / validation
```
docker build -t patient:local challenge/
docker run -d --name p --cap-add=SYS_PTRACE -p 127.0.0.1:2222:22 \
  -e FLAG_V1=... -e FLAG_V2=... -e FLAG_V3=... -e FLAG_V4=... -e ANALYST_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" patient:local
ssh -i ~/.ssh/id_ed25519 -p 2222 analyst@127.0.0.1
```
Validated end-to-end: all 4 flags recovered exactly through the gated chain; `grep -r
H7CTF{` across the fs returns 0 (v1 base64, v2-4 ciphertext); staging sources removed;
real SSH login confirmed.

## Deploy notes (for the platform)
- **Delivery is real SSH, not HTTP** - route via the SSH bastion / L4 path (interactive SSH
  is a long-lived bidirectional session, so it is NOT affected by the raw-TCP half-close
  caveat that only bit one-shot flag delivery).
- The container **requires `SYS_PTRACE`** (Docker drops it by default) for the intended
  `/proc/<pid>/mem` acquisition.
- Per-team: inject the team's SSH public key as `ANALYST_PUBKEY` and the four named flags as
  `FLAG_V1..FLAG_V4`. On-demand per-team pod; a reboot/respawn re-stages cleanly, so it's
  un-brickable.

## Fairness / anti-agent notes
- No grep/skip: later flags are ciphertext keyed on earlier findings; you must do the stages
  in order.
- The crown-jewel flag (v3) is a key that exists only in a running process's memory - the
  live-response lesson, and structurally impossible to get from a static artifact.
- Real, teachable techniques throughout: /proc live triage, deleted-binary recovery,
  LD_PRELOAD rootkit detection, process-memory acquisition, timestomp detection, log
  correlation across sources.
