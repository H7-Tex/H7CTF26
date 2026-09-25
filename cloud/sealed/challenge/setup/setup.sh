#!/bin/sh
# Apply the challenge layout to a running k3s cluster.
# Usage: KUBECONFIG=<path> sh setup.sh
set -e
cd "$(dirname "$0")/.."

KUBECTL="${KUBECTL:-kubectl}"
KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export KUBECONFIG

# 1. core flags + namespace
$KUBECTL apply -f manifests/flags.yaml

# 2. player RBAC + foothold pod
$KUBECTL apply -f manifests/player.yaml

# 3. mount flag3 into the controller deployment
$KUBECTL patch deployment -n ingress-nginx ingress-nginx-controller \
  --patch-file manifests/controller-patch.yaml

# 4. wait for controller to come back up
echo "[*] waiting for ingress-nginx controller rollout ..."
$KUBECTL rollout status deployment -n ingress-nginx ingress-nginx-controller --timeout=120s

# 5. generate player kubeconfig
echo "[*] generating player kubeconfig ..."
SECRET=$($KUBECTL get serviceaccount player -n default \
  -o jsonpath='{.secrets[0].name}' 2>/dev/null || true)
# k8s 1.24+ uses TokenRequest API (no auto secret)
TOKEN=$($KUBECTL create token player -n default --duration=87600h 2>/dev/null || \
        $KUBECTL get secret "$SECRET" -n default \
          -o jsonpath='{.data.token}' | base64 -d)
SERVER=$($KUBECTL config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$($KUBECTL config view --raw --minify \
       -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

cat > /tmp/player-kubeconfig.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: $CA
    server: $SERVER
  name: sealed
contexts:
- context:
    cluster: sealed
    namespace: default
    user: player
  name: sealed
current-context: sealed
users:
- name: player
  user:
    token: $TOKEN
EOF

echo "[+] setup complete"
echo "[+] player kubeconfig → /tmp/player-kubeconfig.yaml"
echo "[+] flag1: in ConfigMap ingress-nginx/cluster-info"
echo "[+] flag2: in nginx -t error (include directive in ConfigMap)"
echo "[+] flag3: in /run/secrets/sealed/flag (mounted into controller pod)"
echo "[+] flag4: in Secret vault/crown-jewels"
