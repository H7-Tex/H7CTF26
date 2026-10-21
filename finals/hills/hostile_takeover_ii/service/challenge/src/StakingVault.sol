// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./interfaces.sol";

// ERC-4626-like staking vault. Stake gGEN to receive sgGEN shares.
// Governor reads vault.getVotes() as additional voting power (asset-weighted).
//
// D4 BUG (vault inflation / first-depositor attack):
//   After a round reset, the vault is empty (totalShares = 0, totalAssets = 0).
//   Classic first-depositor sequence:
//     1. deposit(1 wei)              -> 1 share (1:1 on empty vault)
//     2. token.transfer(vault, N)    -> direct donation, no shares minted
//   Now: getVotes(you) = totalAssets() * sharesOf[you] / totalShares
//        = (N + 1 wei) * 1 / 1 = N + 1 wei > quorum
//   Nobody else can acquire shares: deposit(A) with A < N mints 0 shares (rounds down).
//   Repay the flash loan by withdrawing your single share after voting.
contract StakingVault {
    string public name = "Staked Genesis Governance";
    string public symbol = "sgGEN";
    uint8 public decimals = 18;

    address public immutable asset;  // GovToken
    address public admin;            // arena: can reset

    uint256 public totalShares;
    mapping(address => uint256) public sharesOf;

    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, uint256 assets, uint256 shares);
    event Reset();

    constructor(address _asset, address _admin) {
        asset = _asset;
        admin = _admin;
    }

    // IVotes-compatible: returns asset-weighted voting power
    // After inflation: 1 share controls N+1 tokens -> votes = N+1 ether > quorum
    function getVotes(address a) external view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) return 0;
        return totalAssets() * sharesOf[a] / supply;
    }

    function totalAssets() public view returns (uint256) {
        return IERC20(asset).balanceOf(address(this));
    }

    // shares = amount * totalShares / totalAssets  (rounds down -- inflation bug)
    // first depositor (totalShares=0): returns amount  (1:1)
    function previewDeposit(uint256 assets) public view returns (uint256) {
        uint256 supply = totalShares;
        if (supply == 0) return assets;
        uint256 ta = totalAssets();
        if (ta == 0) return assets;
        return assets * supply / ta;
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        require(assets > 0, "zero");
        shares = previewDeposit(assets);
        require(shares > 0, "zero shares -- vault inflated");
        require(IERC20(asset).transferFrom(msg.sender, address(this), assets), "transfer");
        totalShares += shares;
        sharesOf[receiver] += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    // redeem all shares of `owner`, return underlying assets
    function redeem(address owner, address receiver) external returns (uint256 assets) {
        require(msg.sender == owner, "only owner");
        uint256 shares = sharesOf[owner];
        require(shares > 0, "no shares");
        uint256 supply = totalShares;
        assets = totalAssets() * shares / supply;
        sharesOf[owner] = 0;
        totalShares -= shares;
        require(IERC20(asset).transfer(receiver, assets), "transfer");
        emit Withdraw(msg.sender, receiver, assets, shares);
    }

    // admin: clear all shares on round reset
    // returns all underlying to the flash lender pool so supply is preserved
    function reset(address returnTo) external {
        require(msg.sender == admin, "only admin");
        uint256 bal = IERC20(asset).balanceOf(address(this));
        if (bal > 0) require(IERC20(asset).transfer(returnTo, bal), "transfer");
        totalShares = 0;
        emit Reset();
    }
}
