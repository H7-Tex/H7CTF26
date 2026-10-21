#!/usr/bin/env bash
# images/offline-mirror.sh - warm up offline mirror caches (run from atom before T-0 while NAT is up).
# takes 3-4 hours. run in a screen/tmux. requires mirror VM to be running and SSH-reachable.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

MIRROR_IP=10.60.202.10
SSH_KEY="${H7F_SSH_KEY:-~/.ssh/h7f-orga}"

s() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "ubuntu@$MIRROR_IP" "$@"; }

echo "==> mirror warm-up starting (this is the long one - expect 3-4 hours)"

# mount data volume (idempotent)
s "sudo bash -c 'lsblk | grep -q sdb && mount | grep -q sdb || { mkfs.ext4 -q /dev/sdb 2>/dev/null; mkdir -p /srv/cache && mount /dev/sdb /srv/cache && echo UUID=\$(blkid -s UUID -o value /dev/sdb) /srv/cache ext4 defaults,nofail 0 2 >> /etc/fstab; }'"
s "sudo mkdir -p /srv/cache/{apt,docker,pip,npm,files} && sudo chown -R ubuntu:ubuntu /srv/cache"

echo "==> 1/5: devpi (PyPI mirror)"
s "pip3 install -q devpi-server devpi-web"
s "devpi-init --serverdir /srv/cache/pip 2>/dev/null || true"
s "nohup devpi-server --serverdir /srv/cache/pip --port 3141 --host 0.0.0.0 &>/var/log/devpi.log & sleep 5"
s "devpi use http://10.60.202.10:3141 && devpi login root --password= && \
   devpi index -c root/pypi bases=root/pypi 2>/dev/null || true"
# prime common packages
s "pip3 install -q --index-url http://localhost:3141/root/pypi/+simple/ pwntools requests httpx flask"

echo "==> 2/5: verdaccio (npm mirror)"
s "docker run -d --name verdaccio -p 4873:4873 -v /srv/cache/npm:/verdaccio/storage \
   10.60.202.10:5001/verdaccio/verdaccio:latest 2>/dev/null || docker start verdaccio"
# prime common packages (pwnjs, axios, express)
s "npm --registry http://localhost:4873 install -g pwnjs 2>/dev/null || true"

echo "==> 3/5: docker registry mirror"
# start a pull-through registry on :5001
s "docker run -d --name registry \
   -p 5001:5000 \
   -v /srv/cache/docker:/var/lib/registry \
   -e REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io \
   -e REGISTRY_HTTP_ADDR=0.0.0.0:5000 \
   registry:2 2>/dev/null || docker start registry"
# pull challenge service images (list supplied by Finals-3)
CHALLENGE_IMAGES=(
  "ubuntu:24.04"
  "python:3.12-slim"
  "node:20-slim"
  "golang:1.22-bookworm"
  # finals-3: add service-specific images here
)
for img in "${CHALLENGE_IMAGES[@]}"; do
  s "docker pull $img && docker tag $img 10.60.202.10:5001/$img || true"
done
# push Gitea, Tulip, S4DFarm images
s "docker pull gitea/gitea:1.22-rootless && docker tag gitea/gitea:1.22-rootless 10.60.202.10:5001/gitea/gitea:1.22-rootless && docker push 10.60.202.10:5001/gitea/gitea:1.22-rootless || true"

echo "==> 4/5: apt-cacher-ng seed (common packages)"
# hit the cache with package downloads; caches tarballs for offline use
s "apt-get -o Acquire::http::Proxy=http://10.60.202.10:3142/ update -qq"
PKGS="build-essential gdb python3 python3-pip git docker.io \
      patchelf ncat tcpdump strace ltrace binutils file xxd curl wget jq \
      wireguard wireguard-tools nftables nginx"
s "apt-get -o Acquire::http::Proxy=http://10.60.202.10:3142/ install --download-only -y $PKGS || true"

echo "==> 5/5: wstunnel binary (for router cloud-init)"
WSTUNNEL_VER=9.10.0
s "mkdir -p /srv/cache/files"
s "curl -fsSL https://github.com/erebe/wstunnel/releases/download/v${WSTUNNEL_VER}/wstunnel_${WSTUNNEL_VER}_linux_amd64.tar.gz \
   -o /tmp/wstunnel.tar.gz && tar xzf /tmp/wstunnel.tar.gz -C /srv/cache/files/ wstunnel \
   && mv /srv/cache/files/wstunnel /srv/cache/files/wstunnel-linux-amd64 || true"

echo "==> mirror warm-up complete. disable NAT on mirror subnet next (cut default route in rt-mirror)."
echo "     ops/teardown-nat.sh will do this at T-0."
