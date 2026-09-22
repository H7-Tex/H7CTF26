# Cross Collateral writeup

`priced cross-asset bank, with the conversion rate pointing the wrong way`

#### the setup

deposit any listed asset, get a `Ticket`, redeem it for any *other* listed asset at the bank's posted prices. so this is not the naive "untyped receipt" bug. the bank prices everything and converts between assets. trading junk up to SUI should cost you, not pay.

#### the bug

`withdraw` converts the ticket's value from its asset into the withdrawal asset, with the ratio inverted:

```move
let in_price  = *table::borrow(&bank.prices, asset);      // deposited asset
let out_price = *table::borrow(&bank.prices, out_key);    // asset you're taking
let out = value * out_price / in_price;                   // flipped
```

to convert `value` units of the deposited asset (price `in_price`) into `T` (price `out_price`), the honest math is `value * in_price / out_price`: value it in a common unit, then divide by the output's price. this does `out_price / in_price`. backwards.

with SUI listed at 1000 and CHEAP at 1, depositing `V` CHEAP and withdrawing SUI pays `V * 1000 / 1 = 1000V` SUI instead of the honest `V / 1000`. a million-x swing in your favour.

#### the play

funded with CHEAP: `deposit<CHEAP>(1000)` → `withdraw<SUI>(ticket)` → `1000 * 1000 / 1 = 1_000_000` SUI. the whole reserve for a bag of junk. `sui move test` proves it (SUI balance → 0).

#### the fix

`out = value * in_price / out_price`. price the input in a common unit first, *then* divide by the output's price, and never let a withdrawal exceed the deposit's honest value.
