// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Open timelock: anyone can schedule and execute batched operations.
// The Throne authorises this contract to call crown().
//
// D5 BUG (predecessor): executeBatch includes the `predecessor` in the operation hash,
// so providing a tampered predecessor creates a different id (safe). But executeBatch
// never checks whether the predecessor operation was actually executed first.
// Schedule a crown op with a fake/unexecuted predecessor and run it immediately.
contract Timelock {
    mapping(bytes32 => uint256) public timestamps; // id -> ready-at (0 = not queued)
    mapping(bytes32 => bool) public done;

    event CallScheduled(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data,
        bytes32 predecessor,
        uint256 delay
    );
    event CallExecuted(
        bytes32 indexed id,
        uint256 indexed index,
        address target,
        uint256 value,
        bytes data
    );
    event Cancelled(bytes32 indexed id);

    function hashOperationBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(targets, values, payloads, predecessor, salt));
    }

    // anyone can schedule operations (D5 open schedule)
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) external {
        require(targets.length > 0 && targets.length == values.length && targets.length == payloads.length, "bad args");
        bytes32 id = hashOperationBatch(targets, values, payloads, predecessor, salt);
        require(timestamps[id] == 0, "already scheduled");
        timestamps[id] = block.timestamp + delay;
        for (uint256 i = 0; i < targets.length; i++) {
            emit CallScheduled(id, i, targets[i], values[i], payloads[i], predecessor, delay);
        }
    }

    // anyone can execute once ready
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt
    ) external {
        bytes32 id = hashOperationBatch(targets, values, payloads, predecessor, salt);
        require(timestamps[id] != 0 && !done[id], "not scheduled or already done");
        require(block.timestamp >= timestamps[id], "not ready");
        // D5 BUG: missing predecessor check:
        //   require(predecessor == bytes32(0) || done[predecessor], "predecessor not done");
        done[id] = true;
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call{value: values[i]}(payloads[i]);
            require(ok, "call failed");
            emit CallExecuted(id, i, targets[i], values[i], payloads[i]);
        }
    }

    function cancel(bytes32 id) external {
        require(timestamps[id] != 0 && !done[id], "not cancellable");
        timestamps[id] = 0;
        emit Cancelled(id);
    }

    receive() external payable {}
}
