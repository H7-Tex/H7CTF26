// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GovToken.sol";
import "./FlashLender.sol";
import "./Governor.sol";
import "./Throne.sol";

// Deploys the GENESIS DAO arena and wires it. `admin` (the arena/system key) owns the
// Governor so the KotH bridge can rotate the epoch on round reset. All the governance token
// supply sits in the flash-loan pool.
contract Setup {
    GovToken public token;
    FlashLender public lender;
    Governor public governor;
    Throne public throne;

    uint256 public constant SUPPLY = 1_000_000 ether;
    uint256 public constant QUORUM = 500_000 ether;

    constructor(address admin) {
        token = new GovToken(SUPPLY, address(this));
        lender = new FlashLender(address(token));
        token.transfer(address(lender), SUPPLY);
        throne = new Throne(admin);
        governor = new Governor(address(token), address(throne), QUORUM, admin);
        throne.setGovernor(address(governor));
    }
}
