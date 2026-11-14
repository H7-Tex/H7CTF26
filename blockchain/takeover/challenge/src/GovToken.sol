// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Governance token with delegation. Voting power = current delegated balance, tracked live.
// There is deliberately NO checkpointing / getPastVotes: getVotes() reads the live tally,
// so flash-borrowed tokens count the moment they are delegated. That is the bug the whole
// challenge turns on (real DAOs snapshot voting power at the proposal block).
contract GovToken {
    string public name = "Genesis Governance";
    string public symbol = "gGEN";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => address) public delegates;
    mapping(address => uint256) public votes; // live delegated voting power

    constructor(uint256 supply, address to) {
        totalSupply = supply;
        balanceOf[to] = supply;
    }

    function _moveVotes(address from, address to, uint256 amt) internal {
        if (from != address(0)) votes[from] -= amt;
        if (to != address(0)) votes[to] += amt;
    }

    function delegate(address to) external {
        address cur = delegates[msg.sender];
        delegates[msg.sender] = to;
        _moveVotes(cur, to, balanceOf[msg.sender]);
    }

    function getVotes(address a) external view returns (uint256) {
        return votes[a];
    }

    function _transfer(address from, address to, uint256 amt) internal {
        require(balanceOf[from] >= amt, "balance");
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
        _moveVotes(delegates[from], delegates[to], amt);
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function approve(address sp, uint256 amt) external returns (bool) {
        allowance[msg.sender][sp] = amt;
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
