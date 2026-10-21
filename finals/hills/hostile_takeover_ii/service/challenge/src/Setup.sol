// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GovToken.sol";
import "./FlashLender.sol";
import "./Governor.sol";
import "./Throne.sol";
import "./StakingVault.sol";
import "./Timelock.sol";

// Deploys the GENESIS DAO treasury arena and wires all modules.
// `admin` = the arena system key (rotates epoch, abdicates throne, resets vault).
//
// Token distribution (1_600_000 ether + 1 wei total supply):
//   - 1_000_000 ether -> FlashLender  (D1, D4 paths)
//   - 1 wei           -> d4Helper     (the 1-wei seed for D4 inflation attack)
//   - 600_000 ether   -> bot EOA      (set via setupBot(); D2 sig path)
//
// D2: governance bot has its own funded account (botKey from entrypoint).
//   The bot pre-delegated to itself; that signed delegation is published in /koth/info.
//   Because delegateBySig never increments the nonce, the sig is valid every round.
//
// D3: Governor.proposeBatch allowlists safeTarget as targets[0].
//   The batch exploit puts safeTarget at index 0 and crown() at index 1.
//
// D5: Timelock callable by anyone (schedule + execute).
//   Throne authorizes the Timelock to call crown().
contract Setup {
    GovToken public token;
    FlashLender public lender;
    Governor public governor;
    Throne public throne;
    StakingVault public vault;
    Timelock public timelock;
    SafeTarget public safeTarget;

    uint256 public constant LENDER_SUPPLY = 1_000_000 ether;
    uint256 public constant D4_SEED      = 1;             // 1 wei seed (inflation attack: 1 share, not 1e18)
    uint256 public constant BOT_SUPPLY   = 600_000 ether; // D2: bot pre-funds to exceed quorum after replay
    uint256 public constant QUORUM       = 500_001 ether;

    // D2: published bot delegation sig (set by entrypoint after bot setup)
    address public botAccount;
    address public botDelegatee;
    uint256 public botDelegateNonce;
    uint256 public botDelegateExpiry;
    uint8   public botDelegatev;
    bytes32 public botDelegater;
    bytes32 public botDelegates;

    // D4: address that gets the 1-wei seed for the inflation attack
    address public d4Helper;
    // arena operator: rotates epoch, abdicates throne, resets vault
    address public admin;

    constructor(address _admin, address _d4Helper) {
        admin    = _admin;
        d4Helper = _d4Helper;

        token = new GovToken(LENDER_SUPPLY + D4_SEED + BOT_SUPPLY, address(this));

        lender = new FlashLender(address(token));
        token.transfer(address(lender), LENDER_SUPPLY);

        // d4Helper gets 1 wei as the "first deposit" seed for D4
        token.transfer(_d4Helper, D4_SEED);
        // BOT_SUPPLY stays in Setup until setupBot() is called by entrypoint

        throne = new Throne(_admin);

        vault = new StakingVault(address(token), _admin);

        // D3: safeTarget allowlisted in batch proposals
        safeTarget = new SafeTarget();

        // Governor: Setup is temporary owner so it can call setVault/setAllowedTarget.
        // Single proposals (D1/D2) have no allowlist.
        // Batch proposals (D3) allowlist targets[0] only.
        governor = new Governor(address(token), address(throne), QUORUM, address(this), address(0));
        throne.setGovernor(address(governor));

        governor.setVault(address(vault));
        governor.setAllowedTarget(address(safeTarget), true);
        // hand governance admin to the arena operator
        governor.transferOwner(_admin);

        // D5: Timelock - anyone can schedule/execute (open timelock).
        // The predecessor check is the only guard on sensitive ops - and it's missing.
        timelock = new Timelock();
        throne.setTimelock(address(timelock));
    }

    // called by entrypoint once: distributes BOT_SUPPLY to the bot EOA so it can delegate
    function setupBot(address bot) external {
        require(msg.sender == admin, "only admin");
        require(botAccount == address(0), "bot already set");
        token.transfer(bot, BOT_SUPPLY);
    }

    // called by entrypoint after generating the bot key and sig; admin-only so players can't
    // overwrite the published delegation and grief D2 for everyone
    function setBotSig(
        address _bot,
        address _delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(msg.sender == admin, "only admin");
        botAccount = _bot;
        botDelegatee = _delegatee;
        botDelegateNonce = nonce;
        botDelegateExpiry = expiry;
        botDelegatev = v;
        botDelegater = r;
        botDelegates = s;
    }
}

// D3: innocuous allowlisted target. The batch exploit uses it as targets[0].
contract SafeTarget {
    event Pinged(address caller);
    function ping() external { emit Pinged(msg.sender); }
}
