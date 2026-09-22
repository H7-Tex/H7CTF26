module cross_collateral::bank;

use std::type_name::{Self, TypeName};
use sui::bag::{Self, Bag};
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::table::{Self, Table};

const E_NOT_LISTED: u64 = 1;
const E_INSUFFICIENT: u64 = 2;
const E_NOT_SOLVED: u64 = 99;

public struct Bank has key {
    id: UID,
    balances: Bag,
    prices: Table<TypeName, u64>,
}

public struct Ticket has key, store {
    id: UID,
    asset: TypeName,
    value: u64,
}

public fun create(ctx: &mut TxContext): Bank {
    Bank { id: object::new(ctx), balances: bag::new(ctx), prices: table::new(ctx) }
}

public fun share(bank: Bank) {
    transfer::share_object(bank);
}

public fun create_and_share(ctx: &mut TxContext) {
    share(create(ctx));
}

public fun list<T>(bank: &mut Bank, price: u64, coin: Coin<T>) {
    let key = type_name::get<T>();
    table::add(&mut bank.prices, key, price);
    bag::add<TypeName, Balance<T>>(&mut bank.balances, key, coin::into_balance(coin));
}

public fun deposit<T>(bank: &mut Bank, coin: Coin<T>, ctx: &mut TxContext): Ticket {
    let key = type_name::get<T>();
    assert!(table::contains(&bank.prices, key), E_NOT_LISTED);
    let value = coin::value(&coin);
    let bal: &mut Balance<T> = bag::borrow_mut(&mut bank.balances, key);
    balance::join(bal, coin::into_balance(coin));
    Ticket { id: object::new(ctx), asset: key, value }
}

public fun withdraw<T>(bank: &mut Bank, ticket: Ticket, ctx: &mut TxContext): Coin<T> {
    let Ticket { id, asset, value } = ticket;
    object::delete(id);
    let out_key = type_name::get<T>();
    assert!(table::contains(&bank.prices, out_key), E_NOT_LISTED);
    let in_price = *table::borrow(&bank.prices, asset);
    let out_price = *table::borrow(&bank.prices, out_key);
    let out = (((value as u128) * (out_price as u128) / (in_price as u128)) as u64);
    let bal: &mut Balance<T> = bag::borrow_mut(&mut bank.balances, out_key);
    assert!(balance::value(bal) >= out, E_INSUFFICIENT);
    coin::from_balance(balance::split(bal, out), ctx)
}

public fun balance_of<T>(bank: &Bank): u64 {
    let key = type_name::get<T>();
    if (bag::contains(&bank.balances, key)) {
        balance::value<T>(bag::borrow(&bank.balances, key))
    } else {
        0
    }
}

public fun flag<T>(bank: &Bank) {
    assert!(balance_of<T>(bank) == 0, E_NOT_SOLVED);
}
