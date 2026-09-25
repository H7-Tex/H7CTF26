#!/usr/bin/env python3
"""Public Domain -- reference solver. Walks the infrastructure-attribution chain end to end."""
import base64
import re
import subprocess
import sys
import tempfile
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"


def get(url, binary=False):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    data = urllib.request.urlopen(req, timeout=30).read()
    return data if binary else data.decode("utf-8", "replace")


def hop1_crtsh():
    # Start from the author (Abu) -> his domain abu.rocks -> Certificate Transparency.
    for q in ("%25.abu.rocks", "abu.rocks"):
        try:
            import json
            d = json.loads(get(f"https://crt.sh/?q={q}&output=json"))
            names = set()
            for row in d:
                names.update(row["name_value"].split("\n"))
            hits = sorted(n for n in names if n in ("clearpane.abu.rocks", "cdn-static-3.abu.rocks"))
            if hits:
                return hits
        except Exception as e:
            print(f"  crt.sh query {q} failed ({e}); retrying/alt", file=sys.stderr)
    return []


def favicon_hash(host):
    try:
        import mmh3
        return mmh3.hash(base64.encodebytes(get(f"https://{host}/favicon.ico", binary=True)))
    except Exception:
        return None


def main():
    print("[hop 1] Certificate Transparency for abu.rocks ...")
    hosts = hop1_crtsh()
    print("         CT names found:", hosts or "(crt.sh not indexed yet / unreachable)")

    print("[hop 2] cdn-static-3 shared stylesheet ...")
    css = get("https://cdn-static-3.abu.rocks/site.css")
    m = re.search(r"[\w.-]+\.h7tex\.com", css)
    halcyon = m.group(0)
    print("         leaked second front:", halcyon)
    fca, fcb = favicon_hash("cdn-static-3.abu.rocks"), favicon_hash(halcyon)
    print(f"         favicon mmh3: cdn-static-3={fca}  {halcyon}={fcb}  match={fca == fcb and fca is not None}")

    print("[hop 3] security.txt on the second front ...")
    sec = get(f"https://{halcyon}/.well-known/security.txt")
    email = re.search(r"Contact:\s*mailto:(\S+)", sec).group(1)
    print("         operator PGP contact:", email)

    print("[hop 4] Web Key Directory fetch of the operator key ...")
    home = tempfile.mkdtemp()
    subprocess.run(["gpg", "--homedir", home, "--batch", "--quiet",
                    "--auto-key-locate", "clear,wkd", "--locate-external-keys", email],
                   capture_output=True)
    out = subprocess.run(["gpg", "--homedir", home, "--list-keys", email],
                         capture_output=True, text=True).stdout
    flag = re.search(r"H7CTF\{[^}]+\}", out)
    print("         key UID:", re.search(r"uid.*", out).group(0).strip() if "uid" in out else "(none)")
    print()
    print("FLAG:", flag.group(0) if flag else "NOT FOUND")


if __name__ == "__main__":
    main()
