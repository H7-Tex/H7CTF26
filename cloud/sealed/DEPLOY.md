# Sealed — Deploy Notes

## Status

GATED on the sysbox pool (Finals' containerd sysctl spike). The challenge runs
as a single sysbox pod containing a full k3s cluster. Once the pool is unblocked,
build the OCI image and follow the steps below.

## Local validation (Docker, this machine)

```bash
# sealed-k3s is already running on the dev box:
docker ps | grep sealed-k3s

# Run the reference solver (needs port-forward + engine.so built):
cd cloud/sealed/challenge/exploit
docker run --rm -v $(pwd):/build alpine:3.19 \
  sh -c 'apk add gcc musl-dev; gcc -shared -fPIC -nostartfiles -o /build/engine.so /build/engine.c'

# Port-forward (in background):
kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller-admission 9443:443 &
python3 exploit.py
```

## Production image

Build a `rancher/k3s:v1.31.5-k3s1`-based image that on entrypoint:
1. Starts k3s (server, disable traefik+metrics-server+local-storage, kubelet eviction overrides)
2. Waits for node Ready
3. Applies ingress-nginx v1.11.4
4. Injects per-team flags (platform passes them as env vars: FLAG1, FLAG2, FLAG3)
5. Applies `challenge/manifests/flags.yaml` (substituting flag values)
6. Applies `challenge/manifests/player.yaml`
7. Patches controller with `challenge/manifests/controller-patch.yaml`
8. Generates player kubeconfig (TokenRequest API) → written to `/handout/player-kubeconfig.yaml`

The platform reads `/handout/player-kubeconfig.yaml` and delivers it to the player.

## k3s startup quirks (hard-won)

- `--disable traefik` — traefik conflicts with ingress-nginx
- eviction-hard kubelet args: `nodefs.available<800Mi,imagefs.available<800Mi,nodefs.inodesFree<2%`
  — without this, k3s evicts everything (default is 10% of host disk)
- Quote the args: `'--kubelet-arg=eviction-hard=...<...>'` — bare `<` is shell redirection

## Required ConfigMap settings

The challenge setup MUST include in `ingress-nginx-controller` ConfigMap:
```yaml
data:
  worker-processes: "1"
  http-snippet: "client_body_in_file_only on;"
```

`worker-processes: 1` keeps temp file numbering deterministic.
`client_body_in_file_only on` persists the uploaded .so to `/tmp/nginx/client-body/`.

## calico-system/node-certs

A TLS secret named `node-certs` in the `calico-system` namespace must exist (any self-signed
cert is fine). This is created by the challenge setup. It's referenced in the exploit's
`auth-tls-secret` annotation.

```bash
# Create a self-signed cert for calico-system/node-certs:
kubectl create namespace calico-system 2>/dev/null || true
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /tmp/tls.key -out /tmp/tls.crt \
  -subj "/CN=calico-node" 2>/dev/null
kubectl create secret tls node-certs -n calico-system \
  --cert=/tmp/tls.crt --key=/tmp/tls.key
```

## Anti-cheese

- Player SA cannot read Secrets (only configmaps/services/ingresses) → flag2/flag3 require the exploit
- Player SA cannot exec into pods → flag2 requires RCE, not direct kubectl exec
- Player SA cannot list secrets in vault namespace → flag3 requires stealing the SA token
- The `calico-system/node-certs` secret name is hinted in the cluster-info ConfigMap
- worker_processes=1 removes pid-brute-forcing concern entirely
- Temp file counter accumulates; players enumerate before+after their upload to find their file
