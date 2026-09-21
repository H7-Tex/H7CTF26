# Cross Collateral — writeup

## The vulnerability

The bank stores balances per asset type (a `Bag` keyed by `TypeName`), and `deposit` /
`withdraw` are both generic over the asset type `T`:

```move
public fun deposit<T>(bank: &mut Bank, coin: Coin<T>, ctx): Voucher {
    let value = coin::value(&coin);
    fund(bank, coin);                       // adds to the T balance
    Voucher { id: object::new(ctx), value } // <-- records `value`, but NOT T
}

public fun withdraw<T>(bank: &mut Bank, voucher: Voucher, ctx): Coin<T> {
    let Voucher { id, value } = voucher;
    object::delete(id);
    // pays out `value` of WHATEVER T the caller names
    coin::from_balance(balance::split(bag::borrow_mut(&mut bank.balances, type_name::with_defining_ids<T>()), value), ctx)
}
```

The `Voucher` carries the *amount* but not the *type* it was minted against. `withdraw<T>` is
generic, so the caller chooses `T` freely, and the only thing tying a withdrawal to a deposit
is a bare `u64`. But a `u64` means completely different things across assets: 1,000,000 units
of a worthless token is not 1,000,000 units of SUI. The type that should have flowed from
deposit to withdrawal was dropped.

Move's type system is otherwise airtight here — the bug is precisely the *absence* of a type
parameter where one was needed. `Voucher` should have been `Voucher<phantom T>`.

## The exploit

You are funded with a large amount of a worthless token `CHEAP`:

1. `deposit<CHEAP>(1_000_000 CHEAP)` → `Voucher { value: 1_000_000 }`. Costs you nothing real.
2. `withdraw<SUI>(voucher)` → the bank splits `1_000_000` out of its **SUI** balance and hands
   it to you.

The bank's SUI reserve is gone; you funded it with a token no one wants. `sui move test`
proves it (`cross_type_drain`): seed 1,000,000 SUI, deposit 1,000,000 CHEAP, withdraw SUI,
reserve ends at 0.

## The fix

Bind the voucher to the deposited type:

```move
public struct Voucher<phantom T> has key, store { id: UID, value: u64 }

public fun deposit<T>(bank, coin: Coin<T>, ctx): Voucher<T> { ... }
public fun withdraw<T>(bank, voucher: Voucher<T>, ctx): Coin<T> { ... }
```

Now `withdraw<SUI>` only accepts a `Voucher<SUI>`, which only `deposit<SUI>` can mint — the
type flows end to end and the cross-asset redemption stops compiling.
