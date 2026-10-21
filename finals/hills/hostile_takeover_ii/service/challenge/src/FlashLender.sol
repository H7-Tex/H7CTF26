// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces.sol";

// Atomic flash loan of the governance token (D1 prerequisite).
// Borrow up to the full pool, delegate to yourself, vote, repay -- all in one callback.
contract FlashLender {
    IERC20 public immutable token;

    event FlashLoan(address indexed receiver, uint256 amount);

    constructor(address t) {
        token = IERC20(t);
    }

    function maxFlashLoan() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function flashLoan(uint256 amount, address receiver, bytes calldata data) external {
        uint256 before = token.balanceOf(address(this));
        require(amount <= before, "insufficient pool");
        require(token.transfer(receiver, amount), "lend");
        emit FlashLoan(receiver, amount);
        IFlashBorrower(receiver).onFlashLoan(amount, data);
        require(token.balanceOf(address(this)) >= before, "not repaid");
    }
}
