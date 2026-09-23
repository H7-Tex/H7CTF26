# Zero-Day Highway

`hardware` / `hard` / on-demand per-team instance (docker, HTTP), dynamic flag.

A CAN bus capture from a connected vehicle's OBD-II port, delivered as a SocketCAN
candump log (`capture.log`, `(timestamp) can0 ID#DATA`). Most frames are routine
powertrain chatter (RPM, speed, etc.). Buried in it is a UDS diagnostic session: an
extended session, a SecurityAccess seed/key unlock, and then a ReadDataByIdentifier
whose response is the flag, returned as an ISO-TP multi-frame message on the ECU
response ID (0x7E8). The player has to follow the diagnostic session and reassemble the
ISO-TP frames to recover the flag.

## Delivery
Per-team live instance. On launch the container synthesizes a fresh capture with `$FLAG`
framed into the ISO-TP diagnostic response and serves `capture.log` over HTTP. Download
it, analyze offline, submit the flag.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/gen.py` : the capture synthesizer (noise traffic + UDS session + ISO-TP framing).
- `challenge/serve.py` : instance entrypoint (generate + serve `capture.log`).
- `challenge/Dockerfile` : the instance image (`h7ctf26/zero-day-highway`, stdlib only).
- `solution/solve.py` : reference solver (parse candump, reassemble the ISO-TP response).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/zdh     # writes /tmp/zdh/capture.log
python3 solution/solve.py /tmp/zdh                       # -> recovers the flag
```
Validated 20/20 across random flags, plus 8-char and 97-char flags; the flag never
appears in `strings` of the log. Players use can-utils / Wireshark / python-can.

## The session (spoiler)
Diagnostic addressing: tester 0x7E0, ECU 0x7E8. Sequence: DiagnosticSessionControl
(0x10 0x03) -> SecurityAccess requestSeed (0x27 0x01) -> sendKey (0x27 0x02, key = seed
XOR 0x5A, shown in the capture) -> ReadDataByIdentifier (0x22 0xF1A0). The ECU response
`0x62 0xF1 0xA0 <flag>` exceeds one CAN frame, so it is sent as ISO-TP: a First Frame
(PCI 0x1LLL) + Consecutive Frames (PCI 0x2N), with the tester sending a Flow Control
(0x30) in between. Reassemble First + Consecutive frames, strip the 3-byte
`62 F1 A0` header -> the flag.

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team capture (fresh noise + framing each launch).
- Not `strings`-recoverable: the flag is split byte-wise across many hex-encoded CAN
  frames, interleaved with noise traffic.
- Requires real automotive skill: reading a CAN log, recognizing the UDS diagnostic
  session in the noise, and reassembling ISO-TP multi-frame (First Frame + sequenced
  Consecutive Frames) in order. A naive grep finds nothing.
- Real basis: OBD-II/UDS diagnostics and ISO-TP transport, the same surface behind the
  well-known connected-vehicle CAN attacks.
