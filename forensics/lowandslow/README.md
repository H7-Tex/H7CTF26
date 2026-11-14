# Low and Slow

**Category:** forensics  **Difficulty:** medium  **Author:** abu

> Six weeks, not one alert, a clean bill of health on every dashboard that mattered. Then a partner asks why your unreleased designs are making the rounds.
>
> Something in here has been talking to the outside on a very patient schedule.

Handout: `handout/capture.pcap` (tcpdump on a lab VM; `stager/netlab.py` generated the traffic).

## Solution

Nothing in the capture looks malicious by content. The beacon is plain HTTP GETs, so you find it by timing instead. `Statistics > Conversations` or an IO graph in Wireshark, or a few lines of scapy over the SYN timestamps, shows one destination on port 8443 being hit every ~8 seconds with a little jitter, about 19 times. That's the check-in.

The data didn't leave over that channel though. Looking at DNS, one domain stands out among the normal lookups:

```
tshark -r capture.pcap -Y dns.flags.response==0 -T fields -e dns.qry.name | grep cdn-telemetry-lab
```

Every query to `sync.cdn-telemetry-lab.net` has a long, high-entropy subdomain with a two-digit counter in front (`00...`, `01...`, `02...`). Strip the counter, sort by it, join the bodies, uppercase, pad and base32-decode. That's the exfiltrated secret.

```
python3 solution/solve.py capture.pcap
```

Flag: `H7CTF{6787b86cc777f426b9c0}`
