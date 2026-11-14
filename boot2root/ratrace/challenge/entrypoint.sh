#!/bin/sh
# instance entrypoint: seal the (optionally platform-injected) flags into place, then run sshd.
# NB: keep each default in its own var. Inlining "${USER_FLAG:-H7CTF{...}}" makes the shell close
# the expansion at the first '}' and append the second as a literal -> a stray trailing brace.
set -e
DEF_USER='H7CTF{14b8dba38cef51b37678}'
printf '%s\n' "${USER_FLAG:-$DEF_USER}" > /home/mel/user.txt
chown mel:mel /home/mel/user.txt
chmod 640 /home/mel/user.txt

DEF_ROOT='H7CTF{d635334c4a8563c01e1b}'
printf '%s\n' "${ROOT_FLAG:-$DEF_ROOT}" > /root/root.txt
chown root:root /root/root.txt
chmod 600 /root/root.txt

# host keys (generated at build); make sure privsep dir exists
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
