# Radio Silence

**Category:** hardware  **Difficulty:** medium  **Author:** abu

> A single burst went out over the air next to a device nobody can name. No datasheet, no protocol notes, not so much as a label on the case.
>
> Whatever it said, it only said once. Read it back.

Per-team instance over HTTP that serves `capture.cf32` (interleaved float32 I/Q, 1 MHz).

## Solution

Nothing about the protocol is given, so everything has to be measured from the samples.

Throw it into inspectrum or URH. There's one burst, and in the spectrogram it hops between two tones around +35 kHz and +85 kHz. Two tones means 2-FSK, centred +60 kHz off DC (the usual tune offset to dodge the DC spike).

To get bits, take the instantaneous frequency and low-pass it, since the raw estimate is noisy:

```python
f = np.angle(x[1:] * np.conj(x[:-1])) * fs / (2 * np.pi)
```

Threshold at the midpoint between the two tones.

The burst starts with a `0xAA` preamble, so transitions there are one symbol apart: about 100 samples, so 10 kBaud. Don't just take the most common run length; fit the period across all the runs, otherwise the timing drifts over the ~300 symbols and the tail comes out wrong.

Sample at symbol centres and slide the phase until the sync word `0x2DD4` shows up. After it: one length byte, the payload, then a CRC-16/CCITT. If the CRC checks out, the payload is the flag.

```
python3 solution/solve.py <dir-with-capture.cf32>
```

Local test:

```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/su
python3 solution/solve.py /tmp/su
```

Flag is dynamic, per team.
