// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The throne. `king` is the KotH seat.
// crown() can only be called by the Governor or the Timelock (both authorized governance paths).
// admin can abdicate (clear the seat) on round reset but cannot install a king.
// Crown transfer never calls the incumbent (no re-entrancy hook to an outgoing king).
contract Throne {
    address public governor;
    address public timelock;
    address public deployer;
    address public admin;
    address public king;
    bytes public kingTag;
    uint256 public since;

    event Crowned(address indexed king, bytes tag, uint256 since);

    constructor(address _admin) {
        deployer = msg.sender;
        admin = _admin;
    }

    function setGovernor(address g) external {
        require(msg.sender == deployer && governor == address(0), "set once");
        governor = g;
    }

    function setTimelock(address t) external {
        require(msg.sender == deployer && timelock == address(0), "set once");
        timelock = t;
    }

    function abdicate() external {
        require(msg.sender == admin, "only admin");
        king = address(0);
        kingTag = "";
        since = 0;
    }

    function crown(address newKing, bytes calldata tag) external {
        require(msg.sender == governor || msg.sender == timelock, "only governance");
        king = newKing;
        kingTag = tag;
        since = block.timestamp;
        emit Crowned(newKing, tag, since);
    }

    function currentTag() external view returns (bytes memory) {
        return kingTag;
    }
}
