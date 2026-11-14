module cross_collateral::cheap;

use sui::coin::{Self, TreasuryCap};

public struct CHEAP has drop {}

fun init(witness: CHEAP, ctx: &mut TxContext) {
    let (treasury, metadata) = coin::create_currency(
        witness, 9, b"CHEAP", b"Cheap Token", b"a token nobody wants", option::none(), ctx,
    );
    transfer::public_freeze_object(metadata);
    transfer::public_transfer(treasury, ctx.sender());
}

public fun mint(treasury: &mut TreasuryCap<CHEAP>, amount: u64, recipient: address, ctx: &mut TxContext) {
    coin::mint_and_transfer(treasury, amount, recipient, ctx);
}
