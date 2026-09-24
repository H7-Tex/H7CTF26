#!/usr/bin/env python3
"""Low and Slow reference solver: find the beacon by interval regularity, then
reassemble the DNS-tunnel exfil from the query names."""
import sys, re, base64, statistics
import warnings
warnings.filterwarnings("ignore")
from scapy.all import rdpcap, DNSQR, IP, TCP

EXFIL = "sync.cdn-telemetry-lab.net"


def solve(path):
    pk = rdpcap(path)

    # 1. beacon: regular-interval TCP connections to the C2 port (SYNs to :8443)
    syn_times = [float(p.time) for p in pk
                 if p.haslayer(TCP) and p[TCP].dport == 8443 and p[TCP].flags == "S"]
    beacon = None
    if len(syn_times) > 3:
        deltas = [b - a for a, b in zip(sorted(syn_times), sorted(syn_times)[1:])]
        beacon = (round(statistics.median(deltas), 1), len(syn_times))

    # 2. DNS-tunnel exfil: collect exfil query names, order by the 2-digit seq, decode
    chunks = {}
    for p in pk:
        if p.haslayer(DNSQR):
            q = p[DNSQR].qname.decode(errors="ignore").rstrip(".")
            m = re.match(r"^(\d\d)([a-z0-9]+)\." + re.escape(EXFIL) + r"$", q)
            if m:
                chunks[int(m.group(1))] = m.group(2)
    b32 = "".join(chunks[i] for i in sorted(chunks)).upper()
    b32 += "=" * (-len(b32) % 8)
    flag = None
    try:
        flag = base64.b32decode(b32).decode(errors="replace")
    except Exception:
        pass
    return beacon, flag


def main():
    beacon, flag = solve(sys.argv[1] if len(sys.argv) > 1 else "capture.pcap")
    print(f"[solve] beacon: ~{beacon[0]}s interval, {beacon[1]} check-ins to port 8443" if beacon else "[solve] no beacon found")
    print(f"[solve] FLAG = {flag}" if flag and flag.startswith("H7CTF{") else f"[solve] exfil decode: {flag}")


if __name__ == "__main__":
    main()
