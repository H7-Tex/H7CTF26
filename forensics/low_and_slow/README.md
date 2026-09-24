# Low and Slow

`forensics` / `medium` / static handout (real pcap, ~144 KB), static flag.

Network-DFIR. A real packet capture off a compromised subnet contains a scheduled C2
beacon and a DNS-tunnel exfiltration, hidden in ordinary office traffic. The player finds
the beacon by **interval regularity** (not a signature) and reassembles the **DNS-tunnel
exfil** from the query names to recover the flag.

## Realism
Genuinely captured with `tcpdump` on a lab VM running a benign traffic generator: a real
HTTP beacon on a fixed cadence to a local "C2" sink, a real DNS-tunnel exfil (base32(flag)
carried in sequentially-numbered subdomains, sent as real DNS queries), and real benign
noise (web + normal DNS). No malware - just the on-the-wire footprint. The pcap opens in
Wireshark/tshark/Zeek/scapy exactly like a real capture.

## Files
- `challenge.yml` : definition (static flag, small attachment handout).
- `stager/net_lab.py` : the benign traffic generator run on the lab VM (kept for repro; NOT shipped).
- `solution/solve.py` : reference solver (beacon-interval detection + DNS-tunnel reassembly, scapy).
- `solution/README.md` : full intended path.
- `writeup/README.md` : full explanation.
- `handout/capture.pcap` : the real capture (~144 KB) - shipped as an Anvil attachment.

## Solve (spoiler)
~19 HTTP check-ins to port 8443 at a steady ~8 s interval = the beacon (found by timing).
Repeated queries to `sync.cdn-telemetry-lab.net` with sequential high-entropy subdomains =
the DNS tunnel; strip the 2-digit sequence, order, concat, base32-decode -> the flag.
Validated end-to-end with `solution/solve.py`.

## Flag model
Small static real capture -> Anvil built-in attachment + static flag (anti-share =
analysis effort + score decay). Could be made per-team dynamic (regenerate the capture with
a per-team flag in a container at launch) if we want it to match the dynamic-flag set.

## Fairness / anti-agent notes
- Not `strings`-recoverable: the flag is base32, split across many DNS query names inside
  benign DNS noise; nothing readable until you identify the tunnel and decode.
- The beacon is invisible to signatures (plain HTTP GETs) - you find it by timing
  regularity, the anti-"grep the pcap" property.
- Two-artifact reasoning within one capture (the timing channel + the naming channel),
  the modality agents are weak at.
- Real basis: low-and-slow C2 beaconing + DNS exfiltration, the RITA/Zeek hunt workflow.
