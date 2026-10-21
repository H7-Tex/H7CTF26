#!/usr/bin/env python3
"""
reset-api.py  -  H7CTF finals prod-box reset API (runs on ops VM, port 8090)
POST /reset/<team>         reset prod-T box (requires RESET_TOKEN bearer auth)
GET  /status/<team>        current instance state + deployer heartbeat
GET  /status               all teams summary

boot volume replacement keeps the instance OCID, VNIC and IP. the replaced volume
boots the golden h7f-prod image. we poll until RUNNING then wait for deployer
heartbeat on :9000/health before returning 200 to the caller.
"""
import os, subprocess, json, time, threading, requests
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
TOKEN = os.environ["RESET_TOKEN"]
N = int(os.environ.get("N", "15"))
SSH_KEY = os.environ.get("SSH_KEY", "/home/ubuntu/.ssh/id_ed25519")
IMG_PROD = os.environ.get("IMG_PROD", "")   # set after golden image is built

_locks: dict[int, threading.Lock] = {t: threading.Lock() for t in range(1, N+2)}
_state: dict[int, dict] = {}

def oci(*args):
    cmd = ["oci", "--auth", "instance_principal"] + list(args)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return json.loads(r.stdout) if r.stdout.strip() else {}

def inv_get(key):
    inv = json.load(open("/srv/ops/inventory.json"))
    return inv.get(key, "")

def prod_ip(t):
    return f"10.60.{t}.2"

def deployer_ok(t, timeout=120):
    url = f"http://{prod_ip(t)}:9000/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(5)
    return False

def do_reset(t: int) -> dict:
    """boot volume replacement reset for team T prod box."""
    instance_id = inv_get(f"vm.prod-{t:02d}")
    if not instance_id:
        raise ValueError(f"no instance OCID for team {t}")
    if not IMG_PROD:
        raise ValueError("IMG_PROD not set in environment")

    _state[t] = {"phase": "stopping", "started": time.time()}

    # 1. stop instance
    oci("compute", "instance", "action",
        "--instance-id", instance_id,
        "--action", "SOFTSTOP",
        "--wait-for-state", "STOPPED")
    _state[t]["phase"] = "stopped"

    # 2. get boot volume
    boot_vol = oci("compute", "boot-volume-attachment", "list",
                   "--compartment-id", os.environ.get("C", inv_get("compartment")),
                   "--availability-domain", os.environ.get("AD", "ljcT:AP-HYDERABAD-1-AD-1"),
                   "--instance-id", instance_id)
    bva_id = boot_vol["data"][0]["id"]
    old_bv_id = boot_vol["data"][0]["boot-volume-id"]

    # 3. replace boot volume with fresh one from golden image
    new_bv = oci("compute", "instance", "update",
                 "--instance-id", instance_id,
                 "--wait-for-state", "STOPPED",
                 # OCI doesn't support inline boot volume replacement; use detach+terminate+new flow
                 # actual path: detach current BV, create new BV from custom image, attach, start
                 )
    # real implementation: detach old BV, create new BV from image, attach, start
    oci("compute", "boot-volume-attachment", "detach",
        "--boot-volume-attachment-id", bva_id,
        "--wait-for-state", "DETACHED")

    new_bv_data = oci("compute", "boot-volume", "create",
                      "--availability-domain", os.environ.get("AD", "ljcT:AP-HYDERABAD-1-AD-1"),
                      "--compartment-id", os.environ.get("C", inv_get("compartment")),
                      "--image-id", IMG_PROD,
                      "--size-in-gbs", "150",
                      "--wait-for-state", "AVAILABLE")
    new_bv_id = new_bv_data["data"]["id"]
    _state[t]["phase"] = "new_volume_ready"

    oci("compute", "boot-volume-attachment", "attach",
        "--instance-id", instance_id,
        "--boot-volume-id", new_bv_id,
        "--wait-for-state", "ATTACHED")

    oci("compute", "instance", "action",
        "--instance-id", instance_id,
        "--action", "START",
        "--wait-for-state", "RUNNING")
    _state[t]["phase"] = "starting"

    # 4. wait for deployer heartbeat
    ok = deployer_ok(t)
    _state[t]["phase"] = "ready" if ok else "timeout"
    _state[t]["elapsed"] = round(time.time() - _state[t]["started"])

    # clean up old boot volume
    try:
        oci("compute", "boot-volume", "delete",
            "--boot-volume-id", old_bv_id,
            "--force", "--wait-for-state", "TERMINATED")
    except Exception:
        pass

    return _state[t]

def auth():
    hdr = request.headers.get("Authorization", "")
    if hdr != f"Bearer {TOKEN}":
        abort(401)

@app.route("/reset/<int:t>", methods=["POST"])
def reset_team(t):
    auth()
    if t < 1 or t > N+1:
        return jsonify({"error": "invalid team"}), 400
    lock = _locks[t]
    if not lock.acquire(blocking=False):
        return jsonify({"error": "reset already in progress"}), 409
    try:
        result = do_reset(t)
        return jsonify(result), (200 if result["phase"] == "ready" else 500)
    except Exception as e:
        _state[t] = {"phase": "error", "msg": str(e)}
        return jsonify(_state[t]), 500
    finally:
        lock.release()

@app.route("/status/<int:t>")
def status_team(t):
    auth()
    st = _state.get(t, {"phase": "unknown"})
    # live instance state
    try:
        inst = inv_get(f"vm.prod-{t:02d}")
        if inst:
            data = oci("compute", "instance", "get", "--instance-id", inst)
            st["lifecycle"] = data["data"]["lifecycle-state"]
    except Exception:
        pass
    return jsonify(st)

@app.route("/status")
def status_all():
    auth()
    return jsonify({t: _state.get(t, {"phase": "unknown"}) for t in range(1, N+2)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8090, threaded=True)
