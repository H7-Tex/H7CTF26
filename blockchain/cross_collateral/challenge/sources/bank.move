module cross_collateral::bank;

use std::type_name::{Self, TypeName};
use sui::bag::{Self, Bag};
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};

const E_INSUFFICIENT: u64 = 1;
const E_NOT_SOLVED: u64 = 99;

public struct Bank has key {
    id: UID,
    balances: Bag,
}

// a claim on `value` units of the bank. NOTE: it records an amount but not the asset type
// it was minted against.
public struct Voucher has key, store {
    id: UID,
    value: u64,
}

public fun create(ctx: &mut TxContext): Bank {
    Bank { id: object::new(ctx), balances: bag::new(ctx) }
}

public fun share(bank: Bank) {
    transfer::share_object(bank);
}

public fun create_and_share(ctx: &mut TxContext) {
    share(create(ctx));
}

public fun fund<T>(bank: &mut Bank, coin: Coin<T>) {
    let key = type_name::get<T>();
    if (bag::contains(&bank.balances, key)) {
        let bal: &mut Balance<T> = bag::borrow_mut(&mut bank.balances, key);
        balance::join(bal, coin::into_balance(coin));
    } else {
        bag::add<TypeName, Balance<T>>(&mut bank.balances, key, coin::into_balance(coin));
    }
}

public fun deposit<T>(bank: &mut Bank, coin: Coin<T>, ctx: &mut TxContext): Voucher {
    let value = coin::value(&coin);
    fund(bank, coin);
    Voucher { id: object::new(ctx), value }
}

public fun withdraw<T>(bank: &mut Bank, voucher: Voucher, ctx: &mut TxContext): Coin<T> {
    let Voucher { id, value } = voucher;
    object::delete(id);
    let key = type_name::get<T>();
    let bal: &mut Balance<T> = bag::borrow_mut(&mut bank.balances, key);
    assert!(balance::value(bal) >= value, E_INSUFFICIENT);
    coin::from_balance(balance::split(bal, value), ctx)
}

public fun balance_of<T>(bank: &Bank): u64 {
    let key = type_name::get<T>();
    if (bag::contains(&bank.balances, key)) {
        balance::value<T>(bag::borrow(&bank.balances, key))
    } else {
        0
    }
}

// win check: aborts unless the bank's holdings of asset T have been drained
public fun flag<T>(bank: &Bank) {
    assert!(balance_of<T>(bank) == 0, E_NOT_SOLVED);
}
