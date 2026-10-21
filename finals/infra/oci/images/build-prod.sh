#!/usr/bin/env bash
# images/build-prod.sh - build golden h7f-prod image from a seed VM.
# run from atom (needs OCI CLI). creates a seed VM from IMG_UBUNTU, provisions it,
# creates a custom image, then terminates the seed VM.
# result: inv_set img.prod <OCID>; export H7F_IMG_PROD=<OCID> in env.sh before 60-fleet.sh.
set -euo pipefail
source "$(dirname "$0")/../lib.sh"

[[ -n ${C:-} ]] || { echo "H7F_COMPARTMENT_ID not set"; exit 1; }

SEED_IP_PRIV=10.60.200.250
NSG_INFRA=$(inv_get nsg.nsg-infra)

echo "==> launching seed VM for prod image..."
SEED_ID=$(launch seed-prod \
  "$(inv_get subnet.svc)" "$SEED_IP_PRIV" \
  2 12 "$IMG_UBUNTU" "$NSG_INFRA" \
  "$(dirname "$0")/../cloud-init/prod.yaml")

echo "seed VM: $SEED_ID  waiting for cloud-init..."
sleep 120  # rough wait; poll /health in real run

# provision via SSH from atom
SEED_PUBLIC_IP=$(oci compute vnic-attachment list \
  --compartment-id "$C" --instance-id "$SEED_ID" | q_data '.[0]."public-ip"')

ssh -i "${H7F_SSH_KEY:-~/.ssh/h7f-orga}" -o StrictHostKeyChecking=no \
  "ubuntu@${SEED_PUBLIC_IP}" bash -s <<'PROVISION'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# docker + buildkit
apt-get update -qq
apt-get install -y -q docker.io docker-buildx-plugin git curl jq

# cap BuildKit to 2 parallel jobs and 6 GB max cache
mkdir -p /etc/buildkit
cat > /etc/buildkit/buildkitd.toml <<'BKCFG'
[worker.oci]
  max-parallelism = 2
[registry."10.60.202.10:5001"]
  http = true
  insecure = true
[[worker.oci.gcPolicy]]
  keepBytes = 6442450944
  keepDuration = 0
BKCFG

systemctl enable docker

# deployer service (webhook handler + build + gate + promote)
mkdir -p /srv/deployer /srv/staging /srv/prod
cat > /srv/deployer/deployer.py <<'DEPLOYER'
#!/usr/bin/env python3
"""
minimal deployer: receives webhook from Gitea (:9000/hook/<repo>),
runs: git pull -> docker build (via buildctl) -> checker gate -> docker run (promote).
reads WEBHOOK_SECRET, CHECKER_GATE, REGISTRY from /srv/deployer/config.env.
"""
import os, subprocess, hmac, hashlib, json
from flask import Flask, request, abort

app = Flask(__name__)
cfg = dict(line.strip().split("=",1) for line in open("/srv/deployer/config.env") if "=" in line)

def verify(payload, sig):
    expected = "sha256=" + hmac.new(cfg["WEBHOOK_SECRET"].encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig or "")

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)

@app.route("/health")
def health():
    return "ok"

@app.route("/hook/<path:repo>", methods=["POST"])
def hook(repo):
    if cfg.get("GATE_BYPASS") != "1":
        sig = request.headers.get("X-Gitea-Signature","")
        if not verify(request.data, sig):
            abort(403)
    payload = request.get_json(force=True)
    branch = payload.get("ref","").split("/")[-1]
    if branch != "main":
        return "skip", 200
    # async deploy (non-blocking response to Gitea)
    import threading
    threading.Thread(target=deploy, args=(repo,), daemon=True).start()
    return "queued", 202

def deploy(repo):
    import requests as req, time
    work = f"/srv/staging/{repo}"
    gitea = cfg.get("GITEA_URL","http://10.60.201.30:3000")
    try:
        run(["git", "clone", "--depth=1", f"{gitea}/h7ctf/{repo}.git", work])
    except Exception:
        run(["git", "-C", work, "pull"])
    # build
    img = f"{cfg['REGISTRY']}/{repo}:latest"
    run(["docker", "build", "--network=host", "-t", img, work])
    # gate
    if cfg.get("GATE_BYPASS") != "1":
        r = req.post(f"{cfg['CHECKER_GATE']}/gate/{repo}", timeout=90)
        if r.status_code != 200:
            open(f"/var/log/deployer/{repo}.log","a").write(f"gate reject: {r.text}\n")
            return
    # promote
    run(["docker", "stop", repo], check=False)
    run(["docker", "run", "-d", "--rm", "--name", repo,
         "--net", "bridge", "--memory", "1g", "--cpus", "0.5",
         img])
    open(f"/var/log/deployer/{repo}.log","a").write(f"deployed {img} at {time.time()}\n")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
DEPLOYER
pip3 install -q flask requests
chmod +x /srv/deployer/deployer.py

# DOCKER-USER: block IMDS
iptables -N DOCKER-USER 2>/dev/null || true
iptables -I DOCKER-USER -d 169.254.169.254 -j DROP

# deployer systemd unit
cat > /etc/systemd/system/deployer.service <<'SVC'
[Unit]
Description=H7CTF deployer
After=docker.service
[Service]
ExecStart=/usr/bin/python3 /srv/deployer/deployer.py
EnvironmentFile=/srv/deployer/config.env
Restart=always
[Install]
WantedBy=multi-user.target
SVC
systemctl daemon-reload; systemctl enable deployer

# node_exporter: prod system metrics visible to own team's workbench on port 9100
NODE_EXP_VER=1.8.2
curl -fsSL "https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXP_VER}/node_exporter-${NODE_EXP_VER}.linux-amd64.tar.gz" \
  -o /tmp/ne.tar.gz && tar xzf /tmp/ne.tar.gz -C /usr/local/bin/ \
  --strip-components=1 "node_exporter-${NODE_EXP_VER}.linux-amd64/node_exporter" 2>/dev/null || true
cat > /etc/systemd/system/node_exporter.service <<'NE'
[Unit]
Description=Prometheus node_exporter
[Service]
ExecStart=/usr/local/bin/node_exporter --web.listen-address=0.0.0.0:9100
Restart=on-failure
[Install]
WantedBy=multi-user.target
NE

# log stream: serve Docker container logs + deployer log via HTTP on port 9101 (read-only)
# teams can: curl http://10.60.T.2:9101/logs/<service> to tail their own container logs
cat > /srv/deployer/logserver.py <<'LOGS'
#!/usr/bin/env python3
import subprocess, threading
from flask import Flask, Response, stream_with_context
app = Flask(__name__)

@app.route("/logs/<service>")
def stream_logs(service):
    if not service.replace("-","").replace("_","").isalnum():
        return "invalid", 400
    def gen():
        with subprocess.Popen(["docker","logs","--tail","200","-f",service],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as p:
            for line in p.stdout:
                yield line
    return Response(stream_with_context(gen()), mimetype="text/plain")

@app.route("/logs")
def list_logs():
    out = subprocess.run(["docker","ps","--format","{{.Names}}"],
                         capture_output=True, text=True).stdout
    return out or "no containers running\n", 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9101)
LOGS
cat > /etc/systemd/system/logserver.service <<'LS'
[Unit]
Description=H7CTF prod log stream
After=docker.service
[Service]
ExecStart=/usr/bin/python3 /srv/deployer/logserver.py
Restart=on-failure
[Install]
WantedBy=multi-user.target
LS

systemctl daemon-reload; systemctl enable node_exporter logserver

# swapfile
fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab

# chrony -> OCI NTP
apt-get install -y -q chrony
echo "server 169.254.169.123 iburst prefer" >> /etc/chrony/chrony.conf
systemctl enable chrony

# Notebook warm-up: pull the service images (Finals-3 supplies list)
# docker pull 10.60.202.10:5001/h7ctf-finals/service1:latest || true
# docker pull 10.60.202.10:5001/h7ctf-finals/service2:latest || true

# clean up
apt-get autoremove -y -q
apt-get clean
cloud-init clean --logs
rm -f /etc/machine-id /var/lib/dbus/machine-id
truncate -s 0 /etc/hostname
sync
PROVISION

echo "==> creating custom image h7f-prod from seed VM..."
IMAGE_ID=$(oci compute image create \
  --compartment-id "$C" \
  --instance-id "$SEED_ID" \
  --display-name h7f-prod \
  --wait-for-state AVAILABLE | q_data '.id')
inv_set img.prod "$IMAGE_ID"
echo "h7f-prod image: $IMAGE_ID"
echo "set H7F_IMG_PROD=$IMAGE_ID in env or shell before running 60-fleet.sh"

echo "==> terminating seed VM..."
oci compute instance terminate --instance-id "$SEED_ID" --force \
  --wait-for-state TERMINATED
inv_set vm.seed-prod ""

echo "prod image build complete."
