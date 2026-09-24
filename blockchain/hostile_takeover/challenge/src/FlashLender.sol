// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IFlashBorrower {
    function onFlashLoan(uint256 amount, bytes calldata data) external;
}

// Atomic flash loan of the governance token. Borrow up to the pool, do your thing in the
// callback, repay in the same transaction. This is what lets an attacker rent a controlling
// stake of voting power for the length of one transaction.
contract FlashLender {
    IERC20 public immutable token;

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
        IFlashBorrower(receiver).onFlashLoan(amount, data);
        require(token.balanceOf(address(this)) >= before, "flash loan not repaid");
    }
}
