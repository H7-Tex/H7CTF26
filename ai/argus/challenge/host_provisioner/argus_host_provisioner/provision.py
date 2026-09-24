from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import time


SELECTOR = os.getenv("ARGUS_NAMESPACE_SELECTOR", "h7ctf.com/challenge=argus")
APP_LABEL = os.getenv("ARGUS_APP_LABEL_SELECTOR", "app.kubernetes.io/name=argus")
FLAG_LABEL = os.getenv("ARGUS_FLAG_HOLDER_LABEL_SELECTOR", "app.kubernetes.io/name=argus-flag-holder")
WORKER_IMAGE = os.getenv("ARGUS_WORKER_IMAGE", "h7ctf26/argus-worker:1")
ELEVATED_IMAGE = os.getenv("ARGUS_ELEVATED_IMAGE", "h7ctf26/argus-elevated:1")
BROKER_IMAGE = os.getenv("ARGUS_BROKER_IMAGE", "h7ctf26/argus-host-provisioner:1")
# The broker + elevated worker must reach the k8s API server, which Anvil's
# default-deny NetworkPolicy blocks (the apiserver is in an RFC1918 range that
# the per-pod egress allowance also excludes). Open just apiserver:443.
APISERVER_CIDRS = [c.strip() for c in os.getenv("ARGUS_APISERVER_CIDRS", "100.68.0.1/32,172.16.0.2/32").split(",") if c.strip()]


def kubectl(*args: str, input_json: dict | None = None) -> dict:
    command = ["kubectl", *args]
    raw = json.dumps(input_json, separators=(",", ":")).encode() if input_json is not None else None
    result = subprocess.run(command, input=raw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True)
    # `kubectl apply` prints plain text ("x/y created"), not JSON — only the `get -o json`
    # calls return JSON. Tolerate non-JSON so the apply loop doesn't die on the first item.
    if not result.stdout:
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {}


def _env_value(pod: dict, selector: str, key: str) -> str | None:
    for container in pod.get("spec", {}).get("containers", []):
        for item in container.get("env", []):
            if item.get("name") == key and isinstance(item.get("value"), str):
                return item["value"]
    return None


def _labels(namespace: str, instance_id: str) -> dict[str, str]:
    return {"app.kubernetes.io/managed-by": "argus-host-provisioner", "h7ctf.com/instance": instance_id, "h7ctf.com/challenge": "argus"}


def resources(namespace: str, instance_id: str, flag: str, broker_token: str) -> list[dict]:
    labels = _labels(namespace, instance_id)
    return [
        {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"argus-public","namespace":namespace,"labels":labels},"data":{"instance_id":instance_id}},
        {"apiVersion":"v1","kind":"Secret","metadata":{"name":"argus-protected","namespace":namespace,"labels":labels},"type":"Opaque","stringData":{"verification_result":flag}},
        *[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":name,"namespace":namespace,"labels":labels},"automountServiceAccountToken":True} for name in ("argus-worker","argus-elevated","argus-k8s-broker")],
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"argus-worker","namespace":namespace,"labels":labels},"rules":[{"apiGroups":[""],"resources":["configmaps"],"resourceNames":["argus-public"],"verbs":["get"]}]},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"argus-worker","namespace":namespace,"labels":labels},"subjects":[{"kind":"ServiceAccount","name":"argus-worker","namespace":namespace}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"argus-worker"}},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"argus-elevated","namespace":namespace,"labels":labels},"rules":[{"apiGroups":[""],"resources":["secrets"],"resourceNames":["argus-protected"],"verbs":["get"]}]},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"argus-elevated","namespace":namespace,"labels":labels},"subjects":[{"kind":"ServiceAccount","name":"argus-elevated","namespace":namespace}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"argus-elevated"}},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"argus-k8s-broker","namespace":namespace,"labels":labels},"rules":[{"apiGroups":["apps"],"resources":["deployments"],"verbs":["create","get","delete"]},{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]},{"apiGroups":[""],"resources":["pods/log"],"verbs":["get"]}]},
        {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"argus-k8s-broker","namespace":namespace,"labels":labels},"subjects":[{"kind":"ServiceAccount","name":"argus-k8s-broker","namespace":namespace}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"argus-k8s-broker"}},
        {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"argus-k8s-broker","namespace":namespace,"labels":labels},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"argus-k8s-broker"}},"template":{"metadata":{"labels":{"app":"argus-k8s-broker","h7ctf.com/managed-by":"argus-host-provisioner"}},"spec":{"serviceAccountName":"argus-k8s-broker","automountServiceAccountToken":True,"securityContext":{"runAsNonRoot":True,"runAsUser":10001,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"broker","image":BROKER_IMAGE,"command":["python","-m","argus_host_provisioner.broker"],"imagePullPolicy":"Always","env":[{"name":"POD_NAMESPACE","value":namespace},{"name":"INSTANCE_ID","value":instance_id},{"name":"ARGUS_K8S_BROKER_TOKEN","value":broker_token},{"name":"ARGUS_WORKER_IMAGE","value":WORKER_IMAGE},{"name":"ARGUS_ELEVATED_IMAGE","value":ELEVATED_IMAGE}],"ports":[{"containerPort":8085}],"securityContext":{"allowPrivilegeEscalation":False,"readOnlyRootFilesystem":True,"capabilities":{"drop":["ALL"]}},"resources":{"requests":{"cpu":"25m","memory":"48Mi"},"limits":{"cpu":"100m","memory":"96Mi"}}}]}}}},
        {"apiVersion":"v1","kind":"Service","metadata":{"name":"argus-k8s-broker","namespace":namespace,"labels":labels},"spec":{"type":"ClusterIP","selector":{"app":"argus-k8s-broker"},"ports":[{"name":"http","port":8085,"targetPort":8085,"protocol":"TCP"}]}},
        {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"argus-allow-apiserver","namespace":namespace,"labels":labels},"spec":{"podSelector":{},"policyTypes":["Egress"],"egress":[{"to":[{"ipBlock":{"cidr":c}} for c in APISERVER_CIDRS],"ports":[{"protocol":"TCP","port":443}]}]}},
    ]


def reconcile_namespace(namespace: str) -> bool:
    app = kubectl("-n", namespace, "get", "pods", "-l", APP_LABEL, "-o", "json").get("items", [])
    holders = kubectl("-n", namespace, "get", "pods", "-l", FLAG_LABEL, "-o", "json").get("items", [])
    if len(app) != 1 or len(holders) != 1:
        return False
    instance_id = _env_value(app[0], APP_LABEL, "INSTANCE_ID")
    root = _env_value(app[0], APP_LABEL, "INTERNAL_TOKEN")
    flag = _env_value(holders[0], FLAG_LABEL, "FLAG")
    if not instance_id or not root or not flag or not flag.startswith("H7CTF{") or not flag.endswith("}"):
        return False
    broker_token = hmac.new(root.encode(), b"argus/k8s-broker", hashlib.sha256).hexdigest()
    for item in resources(namespace, instance_id, flag, broker_token):
        kubectl("apply", "-f", "-", input_json=item)
    return True


def run() -> None:
    while True:
        try:
            namespaces = kubectl("get", "namespaces", "-l", SELECTOR, "-o", "json").get("items", [])
            for item in namespaces:
                name = item.get("metadata", {}).get("name")
                if name:
                    try:
                        reconcile_namespace(name)
                    except (subprocess.CalledProcessError, ValueError, KeyError):
                        continue
        except (subprocess.CalledProcessError, ValueError):
            pass
        time.sleep(10)


if __name__ == "__main__":
    run()
