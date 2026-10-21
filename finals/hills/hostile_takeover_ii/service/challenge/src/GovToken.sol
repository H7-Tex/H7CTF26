// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Governance token with live delegation (no checkpointing -- intentional).
// D2 BUG: delegateBySig caches the EIP-712 domain at deploy and never consumes the nonce,
// so any published signed delegation can be replayed indefinitely each round.
contract GovToken {
    string public name = "Genesis Governance";
    string public symbol = "gGEN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => address) public delegates;
    mapping(address => uint256) public votes; // live delegated power

    // EIP-712 -- domain separator is computed ONCE at deploy and never updated.
    // On a round reset the chain state is cleared but this contract is redeployed,
    // so a sig valid in round N is also valid in round N+1 (same domain).
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant DELEGATION_TYPEHASH =
        keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");

    // nonce tracking -- but it is never incremented (D2 BUG)
    mapping(address => uint256) public nonces;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event DelegateChanged(address indexed delegator, address indexed from, address indexed to);
    event DelegateBySig(address indexed signer, address indexed delegatee, uint256 nonce);

    constructor(uint256 supply, address to) {
        totalSupply = supply;
        balanceOf[to] = supply;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256("1"),
            block.chainid,
            address(this)
        ));
    }

    // D2 path: replay any previously-published signed delegation.
    // nonces[signer] is read for the digest but never incremented after the call.
    function delegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= expiry, "expired");
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry))
        ));
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "invalid sig");
        // BUG: missing `nonces[signer]++` -- nonce is verified but not consumed
        require(nonce == nonces[signer], "bad nonce");
        emit DelegateBySig(signer, delegatee, nonce);
        _delegate(signer, delegatee);
    }

    function delegate(address to) external {
        _delegate(msg.sender, to);
    }

    function _delegate(address delegator, address delegatee) internal {
        address cur = delegates[delegator];
        delegates[delegator] = delegatee;
        emit DelegateChanged(delegator, cur, delegatee);
        _moveVotes(cur, delegatee, balanceOf[delegator]);
    }

    function _moveVotes(address from, address to, uint256 amt) internal {
        if (from != address(0)) votes[from] -= amt;
        if (to != address(0)) votes[to] += amt;
    }

    function getVotes(address a) external view returns (uint256) {
        return votes[a];
    }

    function _transfer(address from, address to, uint256 amt) internal {
        require(balanceOf[from] >= amt, "balance");
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        emit Transfer(from, to, amt);
        _moveVotes(delegates[from], delegates[to], amt);
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function approve(address sp, uint256 amt) external returns (bool) {
        allowance[msg.sender][sp] = amt;
        emit Approval(msg.sender, sp, amt);
        return true;
    }

    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amt, "allowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amt;
        _transfer(from, to, amt);
        return true;
    }
}
