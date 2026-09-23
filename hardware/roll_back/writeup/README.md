# Roll Back: writeup

## The setup
Eight button presses of a cheap 433 MHz "rolling code" garage remote, captured as raw
complex baseband (`capture.cf32`: interleaved float32 I/Q, fs = 1 MHz). The receiver is
live: it rejects any code it has already seen, so replaying a captured press does
nothing. The name is the point: the code is supposed to roll unpredictably, but this
one does not.

## Solve
1. **Recognize OOK.** The amplitude switches on and off; the phase carries nothing. On-
   off keying. `|x|` is the envelope, so the carrier offset (+50 kHz here) does not even
   need to be removed. Eight bursts separated by long low gaps = eight presses.
2. **Decode PWM.** Each burst is a run of fixed-period bits; the high-pulse width sets
   the bit (short high = 0, long high = 1). That yields 48 bits per burst.
3. **Parse the frame.** 48 bits split as serial(24) | counter(16) | button(4) |
   checksum(4). Line up the eight frames: serial and button are constant, the counter
   steps up by a fixed amount each press, and the final nibble equals the sum of the
   other nibbles (a checksum). That is the whole protocol, recovered from the signal.
4. **Predict.** The counter is not encrypted, it just increments. Next code = same
   serial and button, counter = last + step, checksum recomputed.
5. **Unlock.** `POST /unlock {"code": "<12 hex>"}`. The receiver validates the serial,
   the checksum, and that the counter is a fresh value inside its forward window, then
   returns the flag.

## Why it is a real bug
Genuine rolling-code systems (KeeLoq and friends) encrypt the counter so the next code
is unpredictable without the device key. Plenty of cheap remotes fake it: a plaintext
or trivially-obfuscated counter, so anyone who can hear a few presses can extrapolate
the sequence. That is exactly the weakness here, and the capture/predict workflow
mirrors the RollJam class of attacks on real remotes.

## Notes
- The capture is synthesized in numpy but is a real OOK/PWM signal with AWGN; it opens
  and demodulates in inspectrum / URH / rtl_433-style tooling like a real recording.
- Anti-agent: the flag is not in the handout at all (it lives behind a correct live
  prediction), replay is rejected, and the 24-bit serial + checksum make guessing the
  endpoint infeasible without doing the RF work.
