# Low and Slow: intended solution

```
python3 solve.py capture.pcap
```

## Path
1. **Find the beacon by regularity, not signature.** The malware check-ins are TCP
   connections to one destination on a fixed cadence. In Wireshark, a
   `Statistics -> Conversations` / IO-graph or a scapy script over the SYN timestamps
   shows one destination hit every ~8 seconds with small jitter - the classic beacon tell.
   (Zeek/RITA would score this by connection-interval consistency.) Here it's ~19 check-ins
   to port 8443.
2. **Spot the DNS tunnel.** Among ordinary DNS lookups, one domain
   (`sync.cdn-telemetry-lab.net`) is queried repeatedly with long, high-entropy,
   sequentially-numbered subdomains (`00...`, `01...`, `02...`). That is data leaving in
   the query names.
3. **Reassemble the exfil.** Strip the 2-digit sequence prefix from each subdomain label,
   order by it, concatenate the label bodies, uppercase, pad, and Base32-decode. The
   result is the exfiltrated secret - the flag.

## Why a naive grep fails
The beacon is invisible to signatures (it's just regular HTTP GETs); you find it by
*timing*. The flag never appears in the pcap as text - it is Base32, split across many DNS
query names in the middle of benign DNS noise. You have to identify the tunnel, order the
chunks, and decode.
