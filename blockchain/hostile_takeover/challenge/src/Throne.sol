// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// The throne. `king` is the single shared storage slot that IS the King-of-the-Hill seat;
// `kingTag` is the holder's opaque team token (stored verbatim, echoed by the status bridge
// as the KotH holder). The only way to move the seat is for the Governor to execute a passed
// proposal that calls crown(): there is no access-control backdoor, so seizing the throne
// requires a genuine governance takeover.
contract Throne {
    address public governor;
    address public deployer;
    address public admin;      // arena system: can clear the seat on round reset (not crown)
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

    // round reset: clear the seat so the new round starts unheld. non-destructive: cannot
    // install a king (only the governor can), so it is not a scoring backdoor.
    function abdicate() external {
        require(msg.sender == admin, "only admin");
        king = address(0);
        kingTag = "";
        since = 0;
    }

    function crown(address newKing, bytes calldata tag) external {
        require(msg.sender == governor, "only governor");
        king = newKing;
        kingTag = tag;
        since = block.timestamp;
        emit Crowned(newKing, tag, since);
    }

    // status bridge reads these
    function currentTag() external view returns (bytes memory) {
        return kingTag;
    }
}
