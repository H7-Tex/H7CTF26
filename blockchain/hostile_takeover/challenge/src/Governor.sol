// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVotes {
    function getVotes(address) external view returns (uint256);
}

// Minimal on-chain governor. Two deliberate omissions vs a real DAO:
//  1. voting power is read LIVE at castVote (IVotes.getVotes), never snapshotted at the
//     proposal block -> flash-borrowed, same-tx-repaid tokens still count.
//  2. NO timelock -> propose + castVote + execute can all happen in one transaction.
// Together: a flash loan buys a controlling vote for one tx and executes immediately.
//
// The one guard that DOES matter here is the per-round epoch: a proposal is bound to the
// epoch it was created in, and execute() requires that epoch to still be current. The KotH
// reset rotates the epoch, so a proposal (or a replayed signed tx) from a prior round can no
// longer execute -> a static bot breaks each round and must re-read the epoch and re-build.
contract Governor {
    IVotes public immutable token;
    address public immutable throne;
    uint256 public immutable quorum;
    address public owner;               // rotates the epoch on round reset
    uint256 public epochNonce = 1;      // current round
    uint256 public proposalCount;

    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        uint256 epoch;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;

    constructor(address t, address thr, uint256 q, address admin) {
        token = IVotes(t);
        throne = thr;
        quorum = q;
        owner = admin;
    }

    function rotateEpoch() external {
        require(msg.sender == owner, "only owner");
        epochNonce++;
    }

    function propose(address target, bytes calldata data, uint256 epoch) external returns (uint256) {
        require(epoch == epochNonce, "stale epoch");
        uint256 id = ++proposalCount;
        proposals[id] = Proposal(target, data, 0, epoch, false);
        return id;
    }

    function castVote(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.epoch != 0 && !p.executed, "no proposal");
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        p.forVotes += token.getVotes(msg.sender);   // LIVE voting power (the bug)
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed, "executed");
        require(p.epoch == epochNonce, "stale epoch");
        require(p.forVotes >= quorum, "quorum not met");
        p.executed = true;
        (bool ok, ) = p.target.call(p.data);
        require(ok, "execution failed");
    }
}
