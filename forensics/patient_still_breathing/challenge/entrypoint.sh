#!/bin/bash
set -e
# stage the intrusion once per container life
if [ ! -f /root/.staged ]; then bash /opt/build/setup.sh; touch /root/.staged; fi

# the IR analyst account (responder has sudo for acquisition; flags are encrypted so
# sudo is no shortcut). per-team key injected via ANALYST_PUBKEY at deploy.
id analyst &>/dev/null || useradd -m -s /bin/bash analyst
echo "analyst:${ANALYST_PASSWORD:-analyst}" | chpasswd
usermod -aG sudo analyst
echo "analyst ALL=(ALL) NOPASSWD:ALL" >/etc/sudoers.d/analyst
chmod 440 /etc/sudoers.d/analyst
if [ -n "$ANALYST_PUBKEY" ]; then
  mkdir -p /home/analyst/.ssh
  echo "$ANALYST_PUBKEY" >/home/analyst/.ssh/authorized_keys
  chown -R analyst:analyst /home/analyst/.ssh
  chmod 700 /home/analyst/.ssh; chmod 600 /home/analyst/.ssh/authorized_keys
fi

cat >/etc/motd <<'MOTD'
============================================================
 ci-runner-03  (GreenBuild CI)   INCIDENT RESPONSE SHELL
 EDR alerted 03:14. The box is LIVE and the actor may still
 be active. DO NOT reboot - capture what is volatile first.
 Reconstruct the intrusion. You have sudo for acquisition.
============================================================
MOTD

mkdir -p /run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
# wipe the staging sources (walkthrough + malware source) now that everything is deployed
rm -rf /opt/build
exec /usr/sbin/sshd -D -e
