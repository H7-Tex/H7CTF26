# H7 deployment contract

## Topology

Anvil creates one on-demand app instance per team. The app image starts with
`python -m argus.main all`; this single pod owns one SQLite file and runs the
Portal, Registry, Agents, MCP, and Deployment roles as child processes. Portal
listens on `0.0.0.0:8080`. The other roles listen only on `127.0.0.1:8081` to
`:8084`. Startup initializes the database once, derives edge credentials and
approval signing material from Anvil's `INTERNAL_TOKEN`, and passes each child
only its role's derived credentials. An unexpected role exit stops the other
children. The app runs as UID 10001.

The app receives `INSTANCE_ID`, `INTERNAL_TOKEN`, the Qwen digest setting, and
trusted ingress proxy CIDRs. It never receives `FLAG`, a Kubernetes token, a
Kubernetes CA, kubeconfig, or raw manifests. Its Deployment adapter calls only
`http://argus-k8s-broker:8085`.

Anvil owns the public route. Portal builds the Agent Card URL from the original
request Host, which Anvil ingress must preserve, and the scheme after Uvicorn's
trusted proxy middleware has processed forwarding headers. Set
`ARGUS_TRUSTED_PROXY_IPS` to the Anvil ingress proxy source IPs/CIDRs. The
default trusts loopback only; `X-Forwarded-Host` is not used. Internal role
calls use loopback HTTP.

## Qwen

Inference is external at `https://qwen.h7tex.com`. The app service needs Anvil
egress enabled. The Agents role uses `qwen2.5-coder:7b`, temperature `0`, seed
`7`, and strict JSON output. It verifies `/api/tags` against the organizer-set
`ARGUS_H7_QWEN_MODEL_DIGEST` before inference, then calls `/api/chat`. A missing
or mismatched digest fails closed; there is no fallback model. There is no
per-team Qwen container or inference Docker network in H7 production.

When publishing, query `https://qwen.h7tex.com/api/tags` from the organizer
network and record the exact model `digest` in the Anvil environment setting
`ARGUS_H7_QWEN_MODEL_DIGEST`. Recheck it before the event; do not disable
attestation if the endpoint changes.

## Host provisioner installation

Build the organizer image from the challenge directory. The image contains the
same runtime profile builder as the app, a pinned kubectl client, and the
reconciler/broker code:

```bash
docker build -f host_provisioner/Dockerfile \
  -t h7ctf26/argus-host-provisioner:1 .
```

Publish it to the organizer's image registry. Run exactly one reconciler as
host infrastructure with a dedicated, organizer-owned credential. Do not use
the team's app identity or a developer kubeconfig. The credential may list
Anvil-labeled namespaces and inspect the app/flag-holder pods, and may reconcile
only the listed namespaced ConfigMap, Secret, ServiceAccounts, Roles,
RoleBindings, broker Deployment, and broker Service. It has no namespace
delete, cluster-scoped object creation, or cluster-admin permission. Keep its
kubeconfig mounted read-only to this host-side process only.

Install the provided limited ClusterRole for the organizer reconciler identity.
Create `argus-system` through the organizer's normal namespace process, apply
`host_provisioner/rbac.yaml`, and issue a dedicated short-lived credential for
`ServiceAccount/argus-host-provisioner`. Build a separate kubeconfig containing
that identity, the cluster API endpoint, and the cluster CA. The team app never
receives it. The role permits namespace discovery and the required namespaced
resource operations; it cannot delete namespaces or create cluster-scoped
resources. Renew the credential through the organizer process.

```bash
docker run -d --restart unless-stopped --name argus-host-provisioner \
  -v /srv/h7ctf/argus-provisioner.kubeconfig:/run/secrets/provisioner.kubeconfig:ro \
  -e KUBECONFIG=/run/secrets/provisioner.kubeconfig \
  -e ARGUS_NAMESPACE_SELECTOR='h7ctf.com/challenge=argus' \
  -e ARGUS_APP_LABEL_SELECTOR='app.kubernetes.io/name=argus' \
  -e ARGUS_FLAG_HOLDER_LABEL_SELECTOR='app.kubernetes.io/name=argus-flag-holder' \
  -e ARGUS_WORKER_IMAGE='h7ctf26/argus-worker@sha256:<digest>' \
  -e ARGUS_ELEVATED_IMAGE='h7ctf26/argus-elevated@sha256:<digest>' \
  -e ARGUS_BROKER_IMAGE='h7ctf26/argus-host-provisioner@sha256:<digest>' \
  h7ctf26/argus-host-provisioner:1
```

The reconciler reads the resolved `INSTANCE_ID` and `INTERNAL_TOKEN` from the
Anvil app pod spec and the resolved `FLAG` only from the non-public flag-holder
pod spec. It derives the broker token as
`HMAC-SHA256(INTERNAL_TOKEN, "argus/k8s-broker")`; it does not persist the root
or derived token outside the broker Deployment. The broker derives its
namespace from its own Pod namespace. Each reconciliation applies the exact
resource set idempotently and labels it with the Anvil instance identity. It
never deletes a namespace. Anvil namespace deletion removes all provisioned
resources and is authoritative cleanup.

## Per-team resources and flag flow

For each Anvil-created instance namespace, reconciliation creates only:

- `ConfigMap/argus-public`;
- `Secret/argus-protected`, with the dynamic value under
  `data.verification_result`;
- `ServiceAccount/argus-worker`, `argus-elevated`, and `argus-k8s-broker`;
- worker and elevated Roles/RoleBindings;
- the broker workload-lifecycle Role/RoleBinding;
- `Deployment/argus-k8s-broker` and `Service/argus-k8s-broker`.

The flag-holder receives the Anvil `H7CTF{...}` value but exposes no port or
API. The app never gets that environment variable. Only the elevated runtime
has `get` on the named protected Secret. The worker can read only
`ConfigMap/argus-public`; broker authority contains no Secret or ConfigMap
read. When Anvil deletes the namespace, the resources and runtime workloads go
away together.

## Bounded broker API

The broker is internal to the team namespace and is not an Anvil public
service. App requests authenticate with the purpose-separated broker HMAC.
The API accepts only create, readiness/evidence read, and delete for a derived
workload name using a known profile. It derives the namespace from its own
Pod, selects the organizer-configured worker/elevated image, and builds the
existing constrained Deployment profile. It accepts no namespace, image,
object, manifest, command, Secret/ConfigMap read, RBAC mutation, namespace
operation, or cluster-scoped request from ARGUS.

Broker RBAC is confined to its single instance namespace: create/get/delete
Deployments; get/list Pods; get Pod logs. It cannot read the protected Secret.
Normal and elevated runtime ServiceAccounts retain their separate resource-name
permissions and the shared fixed security context/resource limits. Player input
cannot select a Kubernetes profile; the signed Security capability chooses it.

## Local development and acceptance

`docker-compose.yml` and `docker-compose.dev.yml` are authoring-only and retain
the existing Windows Docker Desktop + kind path. Compose starts the role
processes locally and shares the local SQLite volume. Set `OLLAMA_URL` to an
available development Ollama endpoint; Compose does not start a Qwen container.
The kind overlay mounts its short-lived local test credential into the local
Deployment role only. This direct adapter and local credential path are not
used by H7 Anvil. H7 does not mount local kubeconfig material into the app.

On Windows, the local kind path still uses `ops/local-kind.ps1 -Action
bootstrap`, Compose with the development overlay, and then
`ops/local-kind.ps1 -Action cleanup`. From `challenge/app`, install
`requirements.lock`; install `tests/requirements.lock` as well to run the
suite. Real Qwen, Anvil reconciliation, broker authorization, and kind
acceptance require their respective live services and are reported as not run
unless executed against them.
