#!/usr/bin/env python3
"""patch-matrix gate for an h7 finals service (CONTRACT.md section 8).

usage: gate.py <service-dir> [--keep] [--rounds N]

boots the service in its own compose project (no published ports, so gates run side
by side), runs the real checker against it over the enowars protocol, and checks:
clean rounds, restart resilience, exploits, the patch matrix, box isolation and the
compose rules. exit code 0 only when everything passes.
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import yaml

FLAG_REGEX = r"H7CTF\{[A-Z2-7]{32}\}"
MAX_CPUS = 1.5
MAX_MEM = 1 << 30


def mint() -> str:
    return "H7CTF{" + base64.b32encode(secrets.token_bytes(20)).decode() + "}"


def sh(*cmd, check=True, capture=True, cwd=None) -> str:
    r = subprocess.run(cmd, cwd=cwd, text=True, capture_output=capture)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{r.stderr or r.stdout}")
    return (r.stdout or "").strip()


class Gate:
    def __init__(self, root: str, rounds: int, keep: bool):
        self.root = os.path.abspath(root)
        self.cfg = yaml.safe_load(open(os.path.join(self.root, "gate.yml")))
        self.slug = os.path.basename(self.root.rstrip("/")).strip("_").replace("_", "-")
        self.rounds = rounds
        self.keep = keep
        self.id = secrets.token_hex(3)
        self.project = f"gate{self.id}"
        self.network = f"{self.project}_default"
        self.tmp = tempfile.mkdtemp(prefix=f"gate-{self.slug}-", dir=os.environ.get("GATE_TMP"))
        self.results: list[tuple[str, bool, str]] = []
        self.task_id = 1000
        self.round = 0
        self.checker_url = ""

    # docker plumbing

    def override(self, compose: str) -> str:
        cfg = json.loads(sh("docker", "compose", "-f", compose, "config", "--format", "json"))
        path = os.path.join(self.tmp, "override.yml")
        with open(path, "w") as f:
            f.write("services:\n")
            for name in cfg["services"]:
                f.write(f"  {name}:\n    ports: !reset []\n")
        return path

    def up(self, service_dir: str, project: str | None = None):
        compose = os.path.join(service_dir, "docker-compose.yml")
        sh("docker", "compose", "-p", project or self.project, "-f", compose, "-f", self.override(compose),
           "up", "-d", "--build", "--remove-orphans", capture=True)

    def down(self, project: str):
        sh("docker", "compose", "-p", project, "down", "-v", "--remove-orphans", check=False)

    def wait_service(self, timeout=60):
        svc, port = self.cfg["service"], int(self.cfg["port"])
        probe = f"import socket;socket.create_connection(('{svc}',{port}),2)"
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = subprocess.run(["docker", "exec", f"{self.project}-checker", "python3", "-c", probe],
                               capture_output=True)
            if r.returncode == 0:
                return
            time.sleep(1)
        raise RuntimeError(f"{svc}:{port} not reachable after {timeout}s")

    def start_checker(self):
        image = f"gate-checker-{self.slug}"
        sh("docker", "build", "-q", "-t", image, os.path.join(self.root, "checker"))
        sh("docker", "run", "-d", "--name", f"{self.project}-mongo", "--network", self.network, "mongo:7")
        sh("docker", "run", "-d", "--name", f"{self.project}-checker", "--network", self.network,
           "-e", f"MONGO_HOST={self.project}-mongo", "-p", "127.0.0.1::8000", image)
        port = sh("docker", "port", f"{self.project}-checker", "8000/tcp").splitlines()[0].rsplit(":", 1)[1]
        self.checker_url = f"http://127.0.0.1:{port}"
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(self.checker_url + "/service", timeout=3) as r:
                    return json.load(r)
            except (urllib.error.URLError, ConnectionError, OSError):
                time.sleep(1)
        raise RuntimeError("checker did not come up:\n" + sh("docker", "logs", f"{self.project}-checker", check=False))

    # the enowars protocol, the same messages the engine sends

    def task(self, method, variant=0, flag=None, chain=None, related=None, attack_info=None, timeout=30):
        self.task_id += 1
        msg = {
            "taskId": self.task_id, "method": method, "address": self.cfg["service"],
            "teamId": 1, "teamName": "gate", "currentRoundId": self.round,
            "relatedRoundId": related if related is not None else self.round,
            "flag": flag, "variantId": variant, "timeout": timeout * 1000, "roundLength": 120000,
            "taskChainId": chain or f"{method}_s1_r{self.round}_t1_i{variant}_{self.task_id}",
        }
        if method == "exploit":
            msg.update({"flag": None, "flagRegex": FLAG_REGEX,
                        "flagHash": hashlib.sha256(flag.encode()).hexdigest(), "attackInfo": attack_info})
        req = urllib.request.Request(self.checker_url, json.dumps(msg).encode(),
                                     {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout + 5) as r:
                return json.load(r)
        except Exception as e:  # noqa: BLE001 - any transport failure is a gate failure
            return {"result": "INTERNAL_ERROR", "message": f"gate transport: {e}"}

    def play_round(self, olds: list) -> tuple[list, list]:
        """one tick: putflag+getflag per store, noise pairs, havocs, and re-checks of old flags."""
        self.round += 1
        bad, placed = [], []
        for v in range(int(self.cfg["flag_stores"])):
            flag, chain = mint(), f"flag_s1_r{self.round}_t1_i{v}"
            r = self.task("putflag", v, flag, chain)
            if r["result"] != "OK":
                bad.append(f"putflag {v}: {r['result']} {r.get('message')}")
                continue
            placed.append((self.round, v, flag, chain, r.get("attackInfo")))
            r = self.task("getflag", v, flag, chain)
            if r["result"] != "OK":
                bad.append(f"getflag {v}: {r['result']} {r.get('message')}")
        for v in range(int(self.cfg.get("noise_variants", 0))):
            chain = f"noise_s1_r{self.round}_t1_i{v}"
            for method in ("putnoise", "getnoise"):
                r = self.task(method, v, chain=chain)
                if r["result"] != "OK":
                    bad.append(f"{method} {v}: {r['result']} {r.get('message')}")
                    break
        for v in range(int(self.cfg.get("havoc_variants", 0))):
            r = self.task("havoc", v)
            if r["result"] != "OK":
                bad.append(f"havoc {v}: {r['result']} {r.get('message')}")
        for tick, v, flag, chain, _ in olds:
            r = self.task("getflag", v, flag, chain, related=tick)
            if r["result"] != "OK":
                bad.append(f"old getflag r{tick} {v}: {r['result']} {r.get('message')}")
        return bad, placed

    def exploit(self, store: int) -> dict:
        flag, chain = mint(), f"flag_s1_r{self.round}_t1_i{store}_x{secrets.token_hex(2)}"
        put = self.task("putflag", store, flag, chain)
        if put["result"] != "OK":
            return {"result": "PUTFLAG_" + put["result"], "message": put.get("message")}
        r = self.task("exploit", store, flag, attack_info=put.get("attackInfo"))
        if r["result"] == "OK" and r.get("flag") != flag:
            return {"result": "WRONG_FLAG", "message": f"exploit returned {r.get('flag')}"}
        return r

    # checks

    def record(self, name, ok, detail=""):
        self.results.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail and not ok else ""), flush=True)

    def check_compose(self):
        cfg = json.loads(sh("docker", "compose", "-f", os.path.join(self.root, "service", "docker-compose.yml"),
                            "config", "--format", "json"))
        problems, cpus, mem = [], 0.0, 0
        for name, s in cfg["services"].items():
            if not s.get("cpus"):
                problems.append(f"{name}: no cpus cap")
            if not s.get("mem_limit"):
                problems.append(f"{name}: no mem_limit")
            cpus += float(s.get("cpus") or 0)
            mem += int(s.get("mem_limit") or 0)
            if s.get("privileged"):
                problems.append(f"{name}: privileged")
            if s.get("cap_add"):
                problems.append(f"{name}: cap_add")
            if s.get("network_mode") == "host" or s.get("pid") == "host":
                problems.append(f"{name}: host namespace")
            if s.get("restart") not in ("unless-stopped", "always"):
                problems.append(f"{name}: restart policy {s.get('restart')}")
            for vol in s.get("volumes", []):
                if vol.get("type") == "bind" or "docker.sock" in str(vol.get("source", "")):
                    problems.append(f"{name}: bind mount {vol.get('source')}")
        if cpus > MAX_CPUS:
            problems.append(f"cpus total {cpus} > {MAX_CPUS}")
        if mem > MAX_MEM:
            problems.append(f"mem total {mem >> 20}MiB > {MAX_MEM >> 20}MiB")
        self.record("compose rules", not problems, "; ".join(problems))

    def run(self) -> bool:
        print(f"gate {self.slug} (project {self.project})", flush=True)
        self.check_compose()
        self.check_allowlist()
        base = os.path.join(self.root, "service")
        try:
            self.up(base)
            info = self.start_checker()
            want = (int(self.cfg["flag_stores"]), int(self.cfg.get("noise_variants", 0)),
                    int(self.cfg.get("havoc_variants", 0)))
            got = (info.get("flagVariants"), info.get("noiseVariants"), info.get("havocVariants"))
            self.record("checker variants match gate.yml", got == want, f"checker {got}, gate.yml {want}")
            if info.get("exploitVariants", 0) < want[0]:
                self.record("one exploit per store", False, f"{info.get('exploitVariants')} exploits")
            self.wait_service()

            olds, failures = [], []
            for i in range(self.rounds):
                if i == self.rounds - 1:
                    sh("docker", "compose", "-p", self.project, "restart")
                    self.wait_service()
                bad, placed = self.play_round(olds)
                failures += [f"round {self.round}: {b}" for b in bad]
                olds = (olds + placed)[-4 * int(self.cfg["flag_stores"]):]
            self.record(f"clean service, {self.rounds} rounds incl. a restart", not failures, "; ".join(failures))

            for store in range(int(self.cfg["flag_stores"])):
                r = self.exploit(store)
                self.record(f"exploit store {store}", r["result"] == "OK", f"{r['result']} {r.get('message')}")

            for p in self.cfg.get("patches", []):
                self.check_patch(base, p)

            self.check_isolation(base)
        except Exception as e:  # noqa: BLE001
            self.record("gate run", False, str(e))
        finally:
            if not self.keep:
                for c in (f"{self.project}-checker", f"{self.project}-mongo"):
                    sh("docker", "rm", "-f", c, check=False)
                self.down(self.project)
                self.down(self.project + "b")
                shutil.rmtree(self.tmp, ignore_errors=True)
        failed = [r for r in self.results if not r[1]]
        print(f"{'PASS' if not failed else 'FAIL'}: {len(self.results) - len(failed)}/{len(self.results)} checks", flush=True)
        return not failed

    def patch_paths(self, patch: str) -> set[str]:
        out = sh("git", "apply", "-p1", "--numstat", patch, cwd=os.path.join(self.root, "service"))
        return {line.split("\t", 2)[2] for line in out.splitlines() if line.count("\t") >= 2}

    def check_allowlist(self):
        allowed = [a.rstrip("/") for a in self.cfg.get("patchable", [])]
        if not allowed:
            self.record("patchable allowlist", False, "gate.yml declares no patchable paths")
            return
        outside = []
        for p in self.cfg.get("patches", []):
            for path in self.patch_paths(os.path.join(self.root, p["file"])):
                if not any(path == a or path.startswith(a + "/") for a in allowed):
                    outside.append(f"{os.path.basename(p['file'])}: {path}")
        self.record("patches stay inside the patchable allowlist", not outside, "; ".join(outside))

    def check_patch(self, base: str, p: dict):
        name = os.path.basename(p["file"])
        work = os.path.join(self.tmp, "patched")
        shutil.rmtree(work, ignore_errors=True)
        shutil.copytree(base, work)
        try:
            sh("git", "apply", "-p1", os.path.join(self.root, p["file"]), cwd=work)
        except RuntimeError as e:
            self.record(f"patch {name}", False, f"does not apply: {e}")
            return
        self.up(work)
        self.wait_service()
        bad, _ = self.play_round([])
        if p["expect"] == "correct":
            self.record(f"patch {name}: checker stays OK", not bad, "; ".join(bad))
            for store in p.get("stores", []):
                r = self.exploit(store)
                self.record(f"patch {name}: exploit store {store} fails", r["result"] != "OK", "exploit still works")
        else:
            self.record(f"patch {name}: checker catches it", bool(bad), "checker stayed OK on a wrong patch")
        self.up(base)
        self.wait_service()

    def check_isolation(self, base: str):
        paths = self.cfg.get("secrets", [])
        if not paths:
            self.record("box isolation", False, "gate.yml lists no per-box secrets")
            return
        other = self.project + "b"
        self.up(base, other)
        time.sleep(5)
        svc, same = self.cfg["service"], []
        for path in paths:
            a = sh("docker", "compose", "-p", self.project, "exec", "-T", svc, "cat", path, check=False)
            b = sh("docker", "compose", "-p", other, "exec", "-T", svc, "cat", path, check=False)
            if not a or a == b:
                same.append(path)
        self.record("box isolation", not same, f"shared or missing: {', '.join(same)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("service_dir")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--keep", action="store_true", help="leave containers up for debugging")
    a = ap.parse_args()
    sys.exit(0 if Gate(a.service_dir, a.rounds, a.keep).run() else 1)


if __name__ == "__main__":
    main()
