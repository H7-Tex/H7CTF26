#!/usr/bin/env python3
# Token-verify core for The Ladder graded challenge.
#
# The grader (internal role, holds GRADER_SECRET) mints one opaque token per tier and hands
# each tier ITS token over the internal net at boot. A tier serves its token as the value a
# successful exploit exfiltrates (the old /flag slot) — so popping tier k reveals token_k and
# nothing else: not GRADER_SECRET, not token_{k+1}. The player pops the LIVE tiers themselves
# (real pwn), collects the token_k's they cleared, and submits them. The grader VERIFIES the
# submitted tokens (recompute + constant-time compare) and reports depth = deepest valid k.
#
# No untrusted code runs in the grader; GRADER_SECRET never reaches a player-facing surface.
import hashlib, hmac, os

# rungs that ship (v3.4/CET deferred). Order defines depth: clearing tier index i (1-based)
# requires having cleared all below it in a real solve, but we score by the deepest valid token.
TIERS = ["v1.0", "v1.4", "v2.0", "v2.6", "v3.0"]
N = len(TIERS)


def _key() -> bytes:
    # GRADER_SECRET is the per-instance signing key Anvil injects (hex string, used as-is).
    s = os.environ.get("GRADER_SECRET", "")
    if not s:
        raise RuntimeError("GRADER_SECRET not set (grader role env)")
    return s.encode()


def mint(tier: str) -> str:
    # token_k = HMAC-SHA256(GRADER_SECRET, "tier:<name>") — deterministic, instance-bound,
    # unforgeable without the secret. Grader recomputes on verify (nothing stored).
    if tier not in TIERS:
        raise ValueError("unknown tier %r" % tier)
    return "H7T_" + hmac.new(_key(), ("tier:" + tier).encode(), hashlib.sha256).hexdigest()[:32]


def mint_all() -> dict:
    return {t: mint(t) for t in TIERS}


def depth(submitted: list) -> int:
    # deepest tier index (1..N) whose exact token appears in the submission; 0 if none.
    # constant-time compare per candidate so a wrong token can't be timing-probed.
    subs = [s.strip() for s in submitted if isinstance(s, str) and s.strip()]
    best = 0
    for i, t in enumerate(TIERS, start=1):
        want = mint(t)
        if any(hmac.compare_digest(want, s) for s in subs):
            best = i
    return best


def score(submitted: list) -> float:
    return depth(submitted) / N


if __name__ == "__main__":
    # self-test with a fixed secret
    os.environ["GRADER_SECRET"] = "deadbeef" * 8
    toks = mint_all()
    print("minted:", toks)
    assert depth([toks["v1.0"]]) == 1
    assert depth([toks["v2.6"]]) == 4
    assert depth([toks["v1.0"], toks["v2.0"], toks["v3.0"]]) == 5
    assert depth(["H7T_" + "0" * 32]) == 0          # forged token → 0
    assert depth([]) == 0
    assert abs(score([toks["v2.0"]]) - 0.6) < 1e-9
    print("tokens.py self-test OK")
