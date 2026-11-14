# Open Sesame

**Category:** hardware  **Difficulty:** hard  **Author:** abu

> A bargain-bin garage remote swears it fires a brand-new, unguessable code on every single press. We loitered in the driveway long enough to catch eight.
>
> Turns out "unguessable" and "unpredictable" are not the same word.

Per-team instance over HTTP. It serves `capture.cf32` (interleaved float32 I/Q, 1 MHz) and a live receiver at `POST /unlock`.

## Solution

Open the capture in inspectrum or URH and the amplitude just switches on and off: OOK. Eight bursts with long gaps between them, so eight button presses. Since the data is in the amplitude, `|x|` is the envelope and we don't even need to remove the +50 kHz carrier offset.

Each burst is fixed-period PWM bits, short high is 0 and long high is 1, 48 bits per press. Lining up the eight frames:

```
serial(24) | counter(16) | button(4) | checksum(4)
```

Serial and button never change, the counter goes up by the same step every press (1, 3, 5 or 7 depending on the instance), and the last nibble is the sum of the other nibbles. So the "rolling" code is a plaintext counter.

Replaying a captured press is rejected because the receiver remembers counters it has seen. But predicting the next one is easy: same serial and button, `last + step`, recompute the checksum, and send it.

```
POST /unlock {"code": "<12 hex>"}
```

The receiver checks serial, checksum and that the counter is fresh and inside its forward window, then hands back the flag. Real rolling-code systems like KeeLoq encrypt the counter; cheap ones often don't.

```
python3 solution/solve.py <dir-with-capture.cf32> <instance-url>
```

Flag is dynamic, per team, and only comes back from `/unlock`.
