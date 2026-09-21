module off_by_2_192::pool;

use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;

const E_OVERFLOW: u64 = 1;
const E_INSUFFICIENT: u64 = 2;
const E_NOT_SOLVED: u64 = 99;

public struct Pool has key {
    id: UID,
    reserve: Balance<SUI>,
    total_lp: u256,
    initial: u64,
}

public struct LP has key, store {
    id: UID,
    amount: u256,
}

// checked shift-left-by-64. flags overflow only when n > (0xffff_ffff_ffff_ffff << 192),
// but n << 64 already overflows u256 for any n >= (1 << 192): values in
// [1<<192, 0xffff..<<192] shift-truncate while overflow reports false.
public fun checked_shlw(n: u256): (u256, bool) {
    let mask = 0xffffffffffffffffu256 << 192;
    if (n > mask) {
        (0, true)
    } else {
        (n << 64, false)
    }
}

fun required_tokens(lp_amount: u256): u64 {
    let (v, overflow) = checked_shlw(lp_amount);
    assert!(!overflow, E_OVERFLOW);
    ((v >> 64) as u64)
}

public fun create(seed: Coin<SUI>, ctx: &mut TxContext): Pool {
    let val = coin::value(&seed);
    Pool { id: object::new(ctx), reserve: coin::into_balance(seed), total_lp: (val as u256), initial: val }
}

public fun share(pool: Pool) {
    transfer::share_object(pool);
}

// win check: aborts unless the reserve has been drained to under 1% of its initial size
public fun flag(pool: &Pool) {
    assert!(balance::value(&pool.reserve) * 100 <= pool.initial, E_NOT_SOLVED);
}

public fun add_liquidity(pool: &mut Pool, lp_amount: u256, payment: &mut Coin<SUI>, ctx: &mut TxContext): LP {
    let required = required_tokens(lp_amount);
    assert!(coin::value(payment) >= required, E_INSUFFICIENT);
    let deposit = coin::split(payment, required, ctx);
    balance::join(&mut pool.reserve, coin::into_balance(deposit));
    pool.total_lp = pool.total_lp + lp_amount;
    LP { id: object::new(ctx), amount: lp_amount }
}

public fun remove_liquidity(pool: &mut Pool, lp: LP, ctx: &mut TxContext): Coin<SUI> {
    let LP { id, amount } = lp;
    object::delete(id);
    let reserve_val = (balance::value(&pool.reserve) as u256);
    let out = ((reserve_val * amount / pool.total_lp) as u64);
    pool.total_lp = pool.total_lp - amount;
    coin::from_balance(balance::split(&mut pool.reserve, out), ctx)
}

public fun reserve_value(pool: &Pool): u64 {
    balance::value(&pool.reserve)
}
