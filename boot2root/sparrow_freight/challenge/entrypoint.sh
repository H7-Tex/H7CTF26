#!/bin/sh
# instance entrypoint: seal the (optionally platform-injected) flags into place, then run sshd.
set -e
printf '%s\n' "${USER_FLAG:-H7CTF{sud0_gtf0b1n_2_us3r_5parr0w}}" > /home/mel/user.txt
chown mel:mel /home/mel/user.txt
chmod 640 /home/mel/user.txt

printf '%s\n' "${ROOT_FLAG:-H7CTF{p4th_h1j4ck_su1d_r00t_5parr0w}}" > /root/root.txt
chown root:root /root/root.txt
chmod 600 /root/root.txt

# host keys (generated at build); make sure privsep dir exists
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
