# Rollback: writeup

## The setup
Helios signs firmware with an LMS/WOTS+ hash-based signature (`lms.py`): a Merkle
tree of one-time WOTS+ leaves, the device trusts the Merkle root. The cardinal rule
of stateful hash-based signatures: **each one-time leaf signs exactly once.** The
notary tracks a counter; `POST /sign` uses the current leaf and advances it. A
maintenance `POST /rollback` resets that counter to 0.

## Why one-time signatures are one-time
WOTS+ signs each base-`w` digit `d_i` of the message hash as `H^{d_i}(sk_i)`, plus
a checksum whose digits move opposite to the message digits. From one signature you
cannot forge another message: raising a message digit (walk its chain forward)
lowers the checksum, which you cannot walk backward (that needs a hash preimage).
The checksum is what makes a single WOTS+ key safe.

## Why reuse breaks it
The rollback lets a single leaf sign many messages. With signatures on many
messages `m_1..m_k`, for each position `i` you learn `H^{d_i^{(j)}}(sk_i)` for many
digits `d_i^{(j)}`. Keep the value at the **lowest** digit seen at each position:

    known_i = H^{min_i}(sk_i),   min_i = min_j d_i^{(j)}

For a target message with digit `c_i` at position `i`, if `c_i >= min_i` you can
sign it as `H^{c_i - min_i}(known_i) = H^{c_i}(sk_i)`. As `k` grows, `min_i -> 0`
(you have seen digit 0 at that position, i.e. `sk_i` itself). With ~150 reused
signatures nearly every position reaches `min_i = 0`, so you can sign essentially
any message on that leaf: the leaf's private key is recovered.

## The forge
1. Reuse leaf 0: loop `rollback` then `sign` on distinct benign builds; record, per
   position, the chain value at the lowest digit.
2. Choose a backdoored firmware (the marker the notary refuses to sign). Grind a
   nonce so that every digit of `H(firmware)` is `>= min_i` (with `min_i` mostly 0
   this is the first try). Build the WOTS+ signature by chaining each `known_i`
   forward to `c_i`.
3. The leaf's position in the tree is unchanged, so leaf 0's Merkle auth path (from
   any collected signature) still connects to the real root. `POST /deploy` with the
   forged signature verifies and the device boots the backdoored firmware -> flag.

## Fix
Never reuse a leaf. Stateful signers must persist the counter across restarts and
maintenance and refuse to sign if it cannot advance; NIST SP 800-208 calls counter
reuse the primary operational risk of LMS/XMSS. A stateless scheme (SPHINCS+)
avoids the footgun entirely.

## Notes
- The attack needs no lattice or number theory, only hash-chain walking, but it is
  only feasible because the rollback permits many reuses; a single reuse (two
  signatures) is not enough to forge an arbitrary message at these parameters.
- Real basis: LMS/WOTS+ one-time-key reuse (RFC 8554, NIST SP 800-208).
