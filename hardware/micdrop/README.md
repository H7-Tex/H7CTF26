# Mic Drop

**Category:** hardware  **Difficulty:** medium  **Author:** abu

> The boardroom's always-on AV bridge got quietly compromised, and it still dutifully streams the room its live feed. Whoever owns it now is riding that same feed to walk secrets out the door.
>
> Nobody in the meeting hears a thing wrong. That is rather the point.

Per-team instance that serves the room audio as HLS at `/boardroom/index.m3u8`.

## Solution

First pull the stream down. Anything works (VLC, mpv, fetching the `.ts` segments by hand), but ffmpeg is easiest. Grab around 15 seconds so you get a full loop:

```
ffmpeg -i http://<host>/boardroom/index.m3u8 -t 14 out.wav
```

It sounds like room ambience, but there's a quiet modem warble under it. A spectrogram shows it switching between two tones at 1200 and 2200 Hz. That's Bell 202 style AFSK: 300 baud, 8N1, LSB first, with a run of mark tone as preamble. A voice-band modem is built to survive lossy audio, so it comes through the AAC encoding fine.

minimodem decodes it directly:

```
minimodem --rx -f out.wav --mark 1200 --space 2200 300
```

Or do it yourself: per bit period, compare Goertzel energy at 1200 vs 2200 Hz, then frame start bit, 8 data bits, stop bit. The decoded bytes contain the flag.

```
python3 solution/solve.py http://<host>/boardroom/index.m3u8
```

Offline test without the stream:

```
FLAG='H7CTF{x}' python3 challenge/gen.py /tmp/md && python3 solution/solve.py /tmp/md/boardroom.wav
```

Flag is dynamic, per team.
