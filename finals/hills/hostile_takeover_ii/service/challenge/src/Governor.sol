// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVotes {
    function getVotes(address) external view returns (uint256);
}

// On-chain governor for the Treasury DAO.
//
// D1 BUG (live votes): castVote reads live token balance (no snapshot).
//   Flash-borrow the full supply, delegate to yourself, propose+vote+execute in one tx.
//
// D2 prereq: after replaying the bot's delegateBySig (nonce not consumed), the bot's
//   tokens are delegated to you. Combined with your own tokens, you exceed quorum.
//
// D3 BUG (batch target): proposeBatch/executeBatch allowlist only targets[0].
//   Put crown() at targets[1] to bypass the allowlist.
//
// D4 prereq: vault.getVotes contributes to castVote total.
//   After the inflation attack, vault.getVotes(you) > quorum.
//
// D5 is handled in Timelock.sol; this contract is not involved.
contract Governor {
    IVotes public immutable token;
    address public immutable throne;
    uint256 public immutable quorum;
    address public owner;
    uint256 public epochNonce = 1;

    // D4 addon: staking vault as additional vote source
    IVotes public vault;

    // batch allowlist (D3 path only)
    mapping(address => bool) public allowedTargets;

    uint256 public proposalCount;
    uint256 public batchCount;

    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        uint256 epoch;
        bool executed;
    }

    struct BatchProposal {
        address[] targets;
        bytes[] data;
        uint256 forVotes;
        uint256 epoch;
        bool executed;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => BatchProposal) internal _batches;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => mapping(address => bool)) public hasBatchVoted;

    event Proposed(uint256 indexed id, address target, uint256 epoch);
    event BatchProposed(uint256 indexed id, uint256 numTargets, uint256 epoch);
    event Voted(uint256 indexed id, address voter, uint256 weight);
    event Executed(uint256 indexed id);
    event BatchExecuted(uint256 indexed id, uint256 numTargets);

    constructor(address t, address thr, uint256 q, address admin, address _vault) {
        token = IVotes(t);
        throne = thr;
        quorum = q;
        owner = admin;
        if (_vault != address(0)) vault = IVotes(_vault);
    }

    function setVault(address v) external {
        require(msg.sender == owner, "only owner");
        vault = IVotes(v);
    }

    function setAllowedTarget(address t, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowedTargets[t] = ok;
    }

    function transferOwner(address newOwner) external {
        require(msg.sender == owner, "only owner");
        owner = newOwner;
    }

    function rotateEpoch() external {
        require(msg.sender == owner, "only owner");
        epochNonce++;
    }

    // --- single-target governance (D1 / D2 / D4 paths) ---
    // No allowlist: any target can be proposed. The bug is the vote accounting.

    function propose(address target, bytes calldata data, uint256 epoch) external returns (uint256) {
        require(epoch == epochNonce, "stale epoch");
        uint256 id = ++proposalCount;
        proposals[id] = Proposal(target, data, 0, epoch, false);
        emit Proposed(id, target, epoch);
        return id;
    }

    function castVote(uint256 id) external {
        Proposal storage p = proposals[id];
        require(p.epoch != 0 && !p.executed, "no proposal");
        require(!hasVoted[id][msg.sender], "already voted");
        hasVoted[id][msg.sender] = true;
        // D1/D4 BUG: reads live state -- flash-borrowed tokens AND inflated vault shares count
        uint256 w = token.getVotes(msg.sender);
        if (address(vault) != address(0)) {
            w += vault.getVotes(msg.sender);
        }
        p.forVotes += w;
        emit Voted(id, msg.sender, w);
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed, "executed");
        require(p.epoch == epochNonce, "stale epoch");
        require(p.forVotes >= quorum, "quorum not met");
        p.executed = true;
        (bool ok,) = p.target.call(p.data);
        require(ok, "execution failed");
        emit Executed(id);
    }

    // --- batch governance (D3 path) ---

    function proposeBatch(
        address[] calldata targets,
        bytes[] calldata data,
        uint256 epoch
    ) external returns (uint256) {
        require(targets.length >= 2 && targets.length == data.length, "need >= 2 targets");
        require(epoch == epochNonce, "stale epoch");
        // D3 BUG: only targets[0] is checked; targets[1..] are executed unchecked
        require(allowedTargets[targets[0]], "first target not allowed");
        uint256 id = ++batchCount;
        _batches[id] = BatchProposal(targets, data, 0, epoch, false);
        emit BatchProposed(id, targets.length, epoch);
        return id;
    }

    function castBatchVote(uint256 id) external {
        BatchProposal storage p = _batches[id];
        require(p.epoch != 0 && !p.executed, "no batch");
        require(!hasBatchVoted[id][msg.sender], "already voted");
        hasBatchVoted[id][msg.sender] = true;
        uint256 w = token.getVotes(msg.sender);
        if (address(vault) != address(0)) w += vault.getVotes(msg.sender);
        p.forVotes += w;
        emit Voted(id, msg.sender, w);
    }

    function executeBatch(uint256 id) external {
        BatchProposal storage p = _batches[id];
        require(!p.executed, "executed");
        require(p.epoch == epochNonce, "stale epoch");
        require(p.forVotes >= quorum, "quorum not met");
        p.executed = true;
        uint256 len = p.targets.length;
        for (uint256 i = 0; i < len; i++) {
            (bool ok,) = p.targets[i].call(p.data[i]);
            require(ok, "batch call failed");
        }
        emit BatchExecuted(id, len);
    }

    function getBatch(uint256 id) external view returns (
        address[] memory targets,
        bytes[] memory data,
        uint256 forVotes,
        uint256 epoch,
        bool executed
    ) {
        BatchProposal storage p = _batches[id];
        return (p.targets, p.data, p.forVotes, p.epoch, p.executed);
    }
}
