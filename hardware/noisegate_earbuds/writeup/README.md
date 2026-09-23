# NoiseGate Earbuds: writeup

## The setup
A BLE link-layer capture (`capture.pcap`, linktype 251) of a pair of NoiseGate earbuds
powering on and pairing with their companion app. This mirrors a real IoT assessment:
you sit next to a device with a sniffer (nRF52 / Ubertooth / a phone HCI log), capture
the advertising and the GATT traffic, and reverse the in-house protocol from the packets.
There are two named flags with partial credit: v1 leaks, v2 needs the auth broken.

## Why `strings` fails
Both flags are obfuscated in the capture: v1 is XORed with the device's provisioning key,
v2 is XORed with a nonce-derived keystream. `strings capture.pcap` finds neither. What it
does find is a debug string (a diagnostic characteristic the developers left in), which
documents the obfuscation so nothing has to be guessed.

## Solve
1. **Find the earbuds.** Several devices advertise (Mi Band, JBL, Galaxy, and the
   NoiseGate Buds). Filter by device name. The NoiseGate advertisement carries
   manufacturer-specific data (company 0x0f39): a type byte then a 16-byte provisioning
   key.
2. **v1 (leak).** After connecting, the config characteristic (handle 0x0021) is read
   over an ATT Read Response and several Read Blob Responses. Reassemble the value in
   order, XOR with the provisioning key (repeated) -> flag v1.
3. **v2 (unlock).** The device notifies a 16-byte nonce on handle 0x0031, the app writes
   an auth response to 0x0032, and the device then notifies the encrypted vault on handle
   0x0033. The keystream is `sha256(provkey || nonce || byte(i))` for i = 0,1,..
   concatenated; XOR the vault ciphertext with it -> flag v2.
4. Decoy notifications on handles 0x0050 / 0x0051 and the other advertisers are noise.

## Notes
- The capture is synthesized with scapy but is a genuine BLE link-layer pcap: Wireshark
  dissects the advertising, ATT reads, and notifications natively. This is the "you don't
  need a BLE sniffer" point: the recording is virtual, the dissection skill is real.
- Anti-agent: neither flag is in the clear, and the work is protocol dissection among
  decoys (right device, right handles, multi-part reassembly, matching the auth
  sequence). The documented debug string keeps the crypto glue fair.
- Real basis: cheap BLE audio/IoT devices with weak "provisioning" keys in advertising
  data and home-grown app-layer auth over GATT.
