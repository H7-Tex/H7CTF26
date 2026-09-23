# Roll Back: intended solution

Launch the instance, download `capture.cf32`, then:
```
python3 solution/solve.py <dir-with-capture.cf32> <instance-base-url>
```
Demodulates the OOK capture, decodes the frames, predicts the next code, and POSTs it
to `/unlock` to get the flag.

## Path (what a player does)
1. Load `capture.cf32` (interleaved float32, fs = 1 MHz). In inspectrum / URH the
   amplitude turns on and off: on-off keying. There are eight bursts separated by long
   gaps: eight button presses.
2. **Envelope demod.** OOK carries the data in amplitude, so `|x|` is the envelope
   regardless of the carrier offset. Threshold it to on/off.
3. **Decode the PWM bits.** Each bit is one fixed-length period; the width of the high
   pulse sets the bit (short high = 0, long high = 1). Read 48 bits per burst.
4. **Parse the frame.** 48 bits = serial(24) | counter(16) | button(4) | checksum(4).
   Across the eight presses the serial and button are constant; the counter increments
   by a fixed step; the last nibble is a checksum (the sum of the other nibbles).
5. **Predict the next code.** Take the last counter + the observed step, keep the same
   serial and button, recompute the checksum -> the code the remote would send next.
6. **Unlock.** `POST /unlock {"code": "<12 hex>"}`. The receiver checks the serial, the
   checksum, and that the counter is an unseen value in its forward window, then returns
   the flag.

## Why replay fails / why brute force fails
The receiver rejects any counter it has already seen, so replaying a captured press does
nothing: you must produce a *new*, valid, higher counter. And because the serial is
24-bit and the checksum must be correct, you cannot guess `/unlock` without first
demodulating the capture to learn the serial and the frame format.
