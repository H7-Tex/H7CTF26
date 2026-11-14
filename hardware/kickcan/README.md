# Kick the CAN

**Category:** hardware  **Difficulty:** medium  **Author:** abu

> We spliced into a car's wiring while it was in for service and let the recorder run. Most of the traffic is the usual engine gossip, but two boxes were having a far more private conversation.
>
> One of them said too much.

Per-team instance over HTTP that serves `capture.log`, a candump log (`(ts) can0 ID#DATA`).

## Solution

Most of the log is periodic powertrain broadcast. The interesting pair is the diagnostic one: tester on `0x7E0`, ECU on `0x7E8`.

```
grep -E 'can0 7E[08]#' capture.log
```

Reading the UDS session on those two IDs:

1. `10 03` DiagnosticSessionControl, extended session.
2. `27 01` SecurityAccess requestSeed, the ECU answers with a 4-byte seed.
3. `27 02` sendKey with `seed ^ 0x5A`, and the ECU says `67 02`. You don't need to break anything, the unlock is in the capture.
4. `22 F1 A0` ReadDataByIdentifier.

The response doesn't fit in one frame, so it comes back as ISO-TP on `0x7E8`:

- First Frame: high nibble `1`, the low nibble plus the next byte is the total length, then 6 data bytes.
- The tester sends a Flow Control (`30 ...`).
- Consecutive Frames: high nibble `2`, low nibble is the sequence number, 7 data bytes each.

Concatenate until you hit the length, strip the `62 F1 A0` header, and the rest is the flag.

```
python3 solution/solve.py <dir-with-capture.log>
```

Local test:

```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/zdh
python3 solution/solve.py /tmp/zdh
```

Flag is dynamic, per team.
