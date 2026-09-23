# Mic Drop: intended solution

Launch the instance, then:
```
python3 solution/solve.py http://<instance-base>/boardroom/index.m3u8
```
Pulls the live HLS stream with ffmpeg, runs a Goertzel AFSK demodulator over the audio,
and prints the flag.

## Path (what a player does)
1. Pull the HLS stream at `<base>/boardroom/index.m3u8` (VLC, mpv, `ffmpeg -i ... out.wav`,
   or fetch the `.ts` segments and concatenate). Capture ~10-15 s so you get a full loop.
2. Listen / look at the audio. Under the room ambience there is a modem "warble" that
   pulses between two tones: a voice-band FSK signal.
3. Identify it as AFSK: mark 1200 Hz, space 2200 Hz, 300 baud, 8N1, LSB-first, with a
   leading run of mark tones as a preamble. (You can confirm the two tones in any
   spectrogram.)
4. Demodulate: per bit period, compare energy at 1200 Hz vs 2200 Hz (Goertzel), recover
   the bit stream, then frame it (start bit 0, 8 data bits, stop bit 1) into bytes. The
   standard tool `minimodem -r 300 --mark 1200 --space 2200` decodes it directly too.
5. The decoded bytes contain `H7CTF{...}` -> the flag.

## Why a grep fails
The flag is never text in any file. It is a modulated audio waveform carried inside a
lossy HLS/AAC stream. You have to pull the stream, treat the audio as a signal, and
demodulate it. Because AFSK is a voice-band modem, it survives the lossy codec, but only
if you actually demodulate.
