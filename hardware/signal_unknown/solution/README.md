# Signal, Unknown: intended solution

Launch the instance, download `capture.cf32`, then:
```
python3 solution/solve.py <dir-with-capture.cf32>
```
Loads the IQ, detects the burst, runs an FSK discriminator, recovers symbol timing,
finds the sync word, checks the CRC, prints the flag.

## Path (what a player does)
1. Load `capture.cf32` as interleaved float32 (complex64) at fs = 1 MHz. In inspectrum
   or URH, open the spectrogram.
2. **Identify the modulation.** The spectrogram shows the burst hopping between two
   discrete tones -> 2-FSK. The tones sit around +35 kHz and +85 kHz (centered +60 kHz
   off DC, the SDR tune offset).
3. **Discriminate.** Compute instantaneous frequency, `f[n] = angle(x[n]*conj(x[n-1]))
   * fs / 2pi`, then low-pass it (the raw estimate is noisy). Threshold at the midpoint
   of the two tone clusters -> one bit per sample.
4. **Symbol rate.** The `0xAA` preamble is a clean 1010 alternation; the spacing
   between transitions is one symbol. Here that is ~100 samples -> 10 kBaud. Estimate
   it precisely as a least-count fit over all transition runs (they are integer
   multiples of the symbol period), not just the modal run, or timing drifts over the
   ~300 symbols of the burst.
5. **Symbol + frame sync.** Sample at symbol centers; slide the sampling phase until
   the `0x2DD4` sync word appears in the bitstream.
6. **Parse.** After the sync: one length byte, then that many payload bytes (the flag),
   then CRC-16/CCITT. Verify the CRC, decode the payload -> the flag.

The point: nothing about the protocol is given. The whole solve is measuring the
signal's parameters from the signal itself, then doing textbook FSK demodulation.
