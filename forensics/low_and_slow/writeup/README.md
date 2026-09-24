# Low and Slow: writeup

## The setup
A real `tcpdump` capture off a compromised office subnet (`capture.pcap`). For weeks
nothing alerted, yet data left the network. Two covert behaviours are hidden in ordinary
traffic: a scheduled C2 beacon, and a DNS-tunnel exfiltration. This is the classic
network-DFIR hunt: no signature fires, so you find the intrusion by behaviour.

## Why a grep / signature fails
The beacon is just plain HTTP GETs to a normal-looking endpoint - no payload signature to
match; you can only find it by its *timing*. The exfiltrated data is base32-encoded and
split across many DNS query names, interleaved with legitimate DNS lookups, so there is no
readable flag anywhere in the capture until you identify the tunnel and reassemble it.

## Solve
1. **Beacon by regularity.** Look at conversations/timing, not content. One destination
   (port 8443) is contacted about every 8 seconds with small jitter across ~19 check-ins -
   the textbook beacon tell. Wireshark IO graph / `Statistics > Conversations`, Zeek+RITA's
   connection-interval scoring, or a few lines of scapy over the SYN timestamps all surface
   it.
2. **The DNS tunnel.** Among benign DNS, one domain (`sync.cdn-telemetry-lab.net`) is
   queried repeatedly with long, high-entropy, sequentially-numbered subdomains
   (`00xxxx`, `01xxxx`, `02xxxx`, ...). Data is leaving in the query names.
3. **Reassemble.** Strip the 2-digit sequence prefix from each subdomain label, sort by it,
   concatenate the bodies, uppercase and pad, Base32-decode -> the exfiltrated secret, the
   flag.

## Notes
- Genuinely captured (tcpdump on a lab VM); opens in Wireshark/Zeek/scapy like any real
  capture. The "malware" was a benign generator reproducing only the footprint.
- Anti-agent: finding a beacon by timing and reassembling a chunked DNS tunnel out of noise
  is two-channel behavioural reasoning over a whole capture, not a one-shot grep.
- Real basis: low-and-slow beaconing + DNS exfiltration, exactly what behavioural NSM
  (Zeek/RITA/JA4) is built to catch.
