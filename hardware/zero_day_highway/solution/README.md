# Zero-Day Highway: intended solution

Launch the instance, download `capture.log`, then:
```
python3 solution/solve.py <dir-with-capture.log>
```
Parses the candump log, finds the ISO-TP response on the ECU ID, reassembles it, and
prints the flag.

## Path (what a player does)
1. Open `capture.log` (SocketCAN candump: `(ts) can0 ID#DATA`). Most IDs are periodic
   powertrain frames. Filter for the diagnostic pair: tester 0x7E0, ECU 0x7E8.
2. **Follow the UDS session** on 0x7E0/0x7E8:
   - `0x10 0x03` DiagnosticSessionControl (extended session).
   - `0x27 0x01` SecurityAccess requestSeed; the ECU returns a 4-byte seed.
   - `0x27 0x02` sendKey; the key is `seed XOR 0x5A` and is present in the capture, so
     the unlock is visible (positive response `0x67 0x02`).
   - `0x22 0xF1A0` ReadDataByIdentifier for the protected data record.
3. **Reassemble ISO-TP.** The ReadData response is larger than 7 bytes, so the ECU sends
   it as ISO-TP on 0x7E8:
   - First Frame: first byte high nibble `0x1`; low nibble + next byte = total length;
     6 payload bytes follow.
   - The tester sends a Flow Control frame (`0x30 ...`) to continue.
   - Consecutive Frames: high nibble `0x2`, low nibble = sequence number; 7 payload
     bytes each. Concatenate in order until you have `total` bytes.
4. The reassembled payload is `0x62 0xF1 0xA0` (positive ReadData response + DID) then
   the flag. Strip the 3-byte header -> the flag.

## Why a grep fails
The flag bytes are split across the data fields of several hex-encoded CAN frames, in
sequence, interleaved with unrelated noise frames. Nothing readable exists until you
reassemble the ISO-TP message.
