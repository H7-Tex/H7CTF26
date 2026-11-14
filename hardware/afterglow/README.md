# Afterglow

**Category:** hardware  **Difficulty:** hard  **Author:** abu

> A dead airport departure board came back from salvage with its controller flash still readable, so we dumped it. Boot the image and it comes up, flickers, and paints a crisp tag along the top calibration strip. It reads the same on every board we have tried, which is exactly why it is not the one you want.
>
> Read your unit's real tag off the panel.

Handout: `handout/afterglow.zip`. The per-team instance serves `panel.rom`, a 32 KiB bootable disk image for `qemu-system-i386`.

## Solution

Boot it:

```
qemu-system-i386 -drive format=raw,file=panel.rom
```

You get a crisp tag along the top, `H7CTF{ph0sph0r_burn_in_1985}`, and snow everywhere below it. The top tag is a decoy and it's the same on every instance. `strings` gives you a bootsplash line that just says `no service tag in rom, keep looking`. Recording the screen and averaging frames doesn't help either; the lower region is uniform 50/50 noise and integrates to nothing.

So it's a real-mode RE job. Sector 0 is an MBR that loads 63 sectors to `0000:8000` and jumps there. We disassembled the payload with `objdump -b binary -m i8086` (Ghidra in 16-bit mode works too). What it does:

1. Mode 13h with a grayscale palette.
2. Parses a `PDPX` header: width 256, flag height 32, 8 subfields, a 32-bit `seed`, 1024-byte planes.
3. Computes `rkey = derive(seed)` with some xor/multiply/shift mixing. From `rkey`, a 16-bit LFSR (taps `0xB400`) drives a Fisher-Yates shuffle that maps the 8 bit weights onto the 8 stored planes, plus a polarity bit and a `(dx, dy)` offset per plane.
4. Each plane is XORed with a 32-bit LCG keystream keyed by `rkey`.
5. It sits in standby waiting for a service code. If you type `rkey` and press enter, it de-XORs, un-inverts, un-shifts and weight-sums the planes and paints the real tag.

`rkey` is computed at boot but never stored anywhere, so you have to reimplement `derive`. From there either type the code into QEMU and read the panel, or rebuild the image offline. All three pieces (permutation, polarity, offsets) have to be right or you get garbage.

The seed is derived per team from the flag, so one team's service code is useless on another team's ROM.

```
python3 solution/solve.py panel.rom
```

The solver finds the header, rebuilds the schedule, writes `recovered.png` and OCRs the tag.

Flag is dynamic, per team. Don't submit the top-strip tag.
