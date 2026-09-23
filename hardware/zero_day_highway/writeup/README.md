# Zero-Day Highway: writeup

## The setup
A SocketCAN candump capture (`capture.log`: `(timestamp) can0 ID#DATA`) taken off a
vehicle's OBD-II port. Most of it is routine powertrain broadcast traffic. Concurrently,
a diagnostic tool runs a UDS session against an ECU, and the ECU returns a protected data
record whose value is the flag. This mirrors the real connected-vehicle attack surface:
you sit on the CAN bus, watch the diagnostic exchange, and reconstruct what the ECU sends
back.

## Why `strings` / grep fails
The flag is not a contiguous string anywhere. It is the payload of a UDS
ReadDataByIdentifier response, and because it is longer than a single CAN frame's 7 data
bytes, it is transported as an ISO-TP multi-frame message: split byte-wise across a First
Frame and several Consecutive Frames, each hex-encoded, and interleaved with unrelated
noise frames on other IDs. You only see it after reassembly.

## Solve
1. **Isolate the diagnostic pair.** Tester requests are on 0x7E0, ECU responses on 0x7E8.
   Everything else is noise.
2. **Read the UDS session.** DiagnosticSessionControl (`0x10 0x03`) -> SecurityAccess
   requestSeed (`0x27 0x01`, ECU returns a 4-byte seed) -> sendKey (`0x27 0x02`, key =
   `seed XOR 0x5A`, present in the capture -> positive `0x67 0x02`) -> ReadDataByIdentifier
   (`0x22 0xF1A0`).
3. **Reassemble ISO-TP** on 0x7E8: First Frame (PCI high nibble `0x1`, total length in the
   low nibble + next byte, 6 payload bytes), then Consecutive Frames (PCI high nibble
   `0x2`, sequence in the low nibble, 7 payload bytes each) after the tester's Flow
   Control (`0x30`). Concatenate to the stated length.
4. Strip the 3-byte `62 F1 A0` header (positive ReadData response + DID). The remainder
   is the flag.

## Notes
- The capture is synthesized but is a valid candump log: can-utils (`candump -l` format),
  Wireshark's SocketCAN dissector, and python-can all read it. This is the "you don't
  need a car on the bench" point: the capture is virtual, the skill is real.
- Anti-agent: recognizing the UDS session inside the noise and reassembling ISO-TP in the
  right sequence is the human insight; a byte grep yields nothing.
- Real basis: OBD-II/UDS diagnostics over ISO-TP, the transport behind the well-known
  connected-vehicle CAN research.
