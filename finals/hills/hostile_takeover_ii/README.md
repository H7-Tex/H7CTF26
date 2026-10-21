# Hostile Takeover II: Treasury

Hill B -- the night hill (Sat 21:00 to Sun 07:00, 30-min rounds after midnight).

GENESIS DAO's treasury governance arena. Stage a governance takeover to seat your team
on the throne, and hold it across rounds.

---

## Bugs (D1-D5)

### D1 -- Flash-loan live votes (Governor.sol)

**Component:** `Governor.castVote`  
**Advisory:** Governor reads live delegated balance at vote time with no snapshot; a flash-borrower
has temporary supermajority.  
**Attack:** Borrow all 1,000,000 tokens from FlashLender, delegate to self, propose+castVote+execute
crown() in one callback, repay.  
**Correct patch:** Snapshot delegation power at proposal creation (ERC20Votes checkpoint pattern).  
**Wrong patch (caught):** Rate-limiting flashLoan calls -- the borrower still has quorum on the
single call; the checker's `havoc` variant sends a flash-loan-shaped tx and sees the limit.

---

### D2 -- delegateBySig nonce not consumed (GovToken.sol)

**Component:** `GovToken.delegateBySig`  
**Advisory:** The EIP-712 delegation signature nonce is verified but never incremented, making every
published signed delegation replayable indefinitely.  
**Attack:** Read `bot_delegation` from `/koth/info`. Call `delegateBySig` with the published sig --
nonce stays 0 each round. Bot's 600,000 votes delegate to you, giving you quorum. Propose+vote+execute.  
**Correct patch:** Add `nonces[signer]++` after the nonce check.  
**Wrong patch (caught):** Expiry set to `block.timestamp + 1` -- the sig still has nonce=0 each round
(nonce never incremented); the checker's delegation step replays a cached sig and sees it work.

---

### D3 -- Batch target allowlist only checks index 0 (Governor.sol)

**Component:** `Governor.proposeBatch`  
**Advisory:** The batch proposal allowlist check applies only to `targets[0]`; subsequent targets are
executed without a check.  
**Attack:** Propose a batch with `safeTarget.ping()` at index 0 (allowlisted) and `throne.crown()`
at index 1 (bypasses check). Borrow flash tokens for quorum votes.  
**Correct patch:** Check all targets against the allowlist in a loop.  
**Wrong patch (caught):** Blocking proposals that include `address(throne)` in any position -- the
checker's batch havoc includes an innocuous non-throne second target and sees the MUMBLE.

---

### D4 -- Vault inflation (StakingVault.sol + Governor.sol)

**Component:** `StakingVault`, `Governor.castVote`  
**Advisory:** First-depositor vault inflation attack: deposit 1 wei to receive 1 share, donate
flash-borrowed tokens to inflate totalAssets, gaining a vote weight > quorum from 1 share.  
**Attack:** Deploy attacker. Borrow 500,001 tokens from FlashLender. Deposit 1 wei (gets 1 share).
Transfer 500,001 tokens to vault (donation). `vault.getVotes(attacker) = 500,001e18 + 1 > quorum`.
Propose+vote+execute crown(). Redeem share (recovers 500,001e18 + 1 wei). Repay loan.  
**Correct patch:** Use virtual offset (add 1 share + 1 token initially) or take a snapshot at
proposal time.  
**Wrong patch (caught):** Requiring `assets >= 1 ether` in deposit -- a 2-ether first deposit
gives 2e18 shares, which still supports inflation with a sufficiently large donation.

---

### D5 -- Timelock predecessor not checked (Timelock.sol)

**Component:** `Timelock.executeBatch`  
**Advisory:** The timelock's predecessor dependency is computed in the operation hash but never
verified before execution; any operation executes regardless of predecessor state.  
**Attack:** Schedule a crown() batch with a random bytes32 as predecessor. Execute immediately (delay=0).
The predecessor check is missing, so it passes.  
**Correct patch:** Add `require(predecessor == bytes32(0) || done[predecessor], "predecessor not done")`.  
**Wrong patch (caught):** Making the predecessor field optional (ignored when zero) -- the check for
non-zero predecessors is still missing; the checker's havoc sends a non-zero predecessor and the
wrong patch still executes it.

---

## Reset behavior

`POST /koth/reset` (Bearer KOTH_ADMIN_TOKEN):
1. `Governor.rotateEpoch()` -- invalidates all pending proposals (epoch staleness check)
2. `Throne.abdicate()` -- clears `king`, `kingTag`, `since`
3. `StakingVault.reset(lenderAddr)` -- drains all assets back to FlashLender, resets totalShares to 0

After reset the vault is empty (totalShares = 0, totalAssets = 0) so D4 is live again next round.

---

## Checker codes

| Code | Feature |
|---|---|
| TREASURY-AUTH-01 | invalid koth token |
| TREASURY-AUTH-02 | missing rpc secret |
| TREASURY-AUTH-03 | verify service unavailable |
| TREASURY-AUTH-04 | rpc secret rejected |
| TREASURY-RPC-01  | per-IP rate limit |
| TREASURY-RPC-02  | per-token rate limit |
| TREASURY-RPC-03  | bad JSON body |
| TREASURY-RPC-04  | upstream RPC error |
| TREASURY-RESET-01 | cast send failure in reset |
| TREASURY-RESET-02 | unauthorized reset attempt |

---

## Unintended bug notes

- `setBotSig` is admin-only (the entrypoint holds the admin key). Open access would let any player
  wipe the published sig and close D2 for everyone -- that is griefing outside the Doors-and-Locks
  mechanic, which the contract bans. Players can read the sig directly from on-chain storage without
  needing the /koth/info endpoint.
- The Timelock `delay=0` means operations execute in the same block. This is intentional (D5 design).
- `transferOwner` was added to Governor so Setup can configure it. A team could call transferOwner
  if they could convince Governor's `owner` to do it -- but owner is the arena admin (SYS_KEY),
  so this is not a player-accessible path.
