import sys
from pathlib import Path


PROVISIONER = Path(__file__).parents[1] / "host_provisioner"
sys.path.insert(0, str(PROVISIONER))

from argus_host_provisioner import provision


def _pod(instance_id, token=None, flag=None):
    env = [{"name": "INSTANCE_ID", "value": instance_id}]
    if token is not None:
        env.append({"name": "INTERNAL_TOKEN", "value": token})
    if flag is not None:
        env.append({"name": "FLAG", "value": flag})
    return {"spec": {"containers": [{"env": env}]}}


def test_reconciliation_is_idempotent_and_keeps_dynamic_flag_in_protected_secret(monkeypatch):
    applied = []

    def fake_kubectl(*args, input_json=None):
        if args[:2] == ("-n", "argus-team-a") and "-l" in args:
            selector = args[args.index("-l") + 1]
            if selector == provision.APP_LABEL:
                return {"items": [_pod("team-a", "internal-root")]}
            if selector == provision.FLAG_LABEL:
                return {"items": [_pod("team-a", flag="H7CTF{dummy}")]}
        if args[:1] == ("apply",):
            applied.append(input_json)
            return {}
        raise AssertionError(args)

    monkeypatch.setattr(provision, "kubectl", fake_kubectl)
    assert provision.reconcile_namespace("argus-team-a") is True
    first = list(applied)
    applied.clear()
    assert provision.reconcile_namespace("argus-team-a") is True
    assert applied == first

    secret = next(item for item in first if item["kind"] == "Secret")
    assert secret["metadata"]["name"] == "argus-protected"
    assert secret["stringData"] == {"verification_result": "H7CTF{dummy}"}
    assert all(item["metadata"]["namespace"] == "argus-team-a" for item in first)
    assert not any(item["kind"] == "Namespace" for item in first)


def test_reconciler_does_not_provision_until_both_anvil_values_are_visible(monkeypatch):
    monkeypatch.setattr(
        provision,
        "kubectl",
        lambda *args, input_json=None: {"items": [_pod("team-a", token="root")]},
    )
    assert provision.reconcile_namespace("argus-team-a") is False


def test_worker_and_broker_rbac_do_not_read_protected_secret():
    objects = provision.resources("argus-team-a", "team-a", "H7CTF{dummy}", "broker-token")
    rules = {
        item["metadata"]["name"]: item.get("rules", [])
        for item in objects
        if item["kind"] == "Role"
    }
    worker = rules["argus-worker"]
    broker = rules["argus-k8s-broker"]
    elevated = rules["argus-elevated"]
    assert worker == [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["argus-public"], "verbs": ["get"]}]
    assert not any("secrets" in rule["resources"] for rule in broker)
    assert not any("secrets" in rule["resources"] for rule in worker)
    assert elevated == [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["argus-protected"], "verbs": ["get"]}]
    assert broker == [
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["create", "get", "delete"]},
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
        {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]},
    ]
