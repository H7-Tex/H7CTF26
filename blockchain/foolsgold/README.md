# Fool's Gold

**Category:** blockchain (Sui Move)  **Difficulty:** easy  **Author:** abu

> crosscollateral is a multi-asset bank on sui: deposit any listed asset, then redeem it later for any other at the bank's posted prices. it holds a real reserve for its honest users.
>
> you're funded with a bag of a near-worthless listed token. leave with the bank's sui.

Provided: `challenge/sources/bank.move`, `challenge/sources/cheap.move`, `challenge/Move.toml`. Same setup as Tidepool: otter-sec's sui-ctf-framework (patched copy in `server/vendor/`, Sui `devnet-v1.49.0`, Rust 1.88). The server funds the bank with SUI listed at price 1000, lists CHEAP at price 1, mints you 1000 CHEAP, then runs `solution::solve(bank, cheap_coin)` and `bank::flag<SUI>(bank)`.

## Solution

Deposit gives you a `Ticket`, withdraw redeems it for any other listed asset. Trading junk up to SUI should cost a lot. Then we read `withdraw`:

```move
let in_price  = *table::borrow(&bank.prices, asset);      // what we deposited
let out_price = *table::borrow(&bank.prices, out_key);    // what we're taking
let out = value * out_price / in_price;
```

The ratio is upside down. Converting `value` of the input into the output should be `value * in_price / out_price`. With SUI at 1000 and CHEAP at 1, `V` CHEAP should get you `V / 1000` SUI. Instead you get `V * 1000`.

```move
let ticket = bank::deposit<CHEAP>(bank, cheap, ctx);
let loot = bank::withdraw<SUI>(bank, ticket, ctx);
```

1000 CHEAP turns into 1,000,000 SUI, the whole reserve.

```
cd solution/solve && sui move build
cat build/solution/bytecode_modules/solve.mv | nc <host> <port>
```

`sui move test` in `challenge/` shows the SUI balance going to 0.

Flag is dynamic per instance (`H7CTF{...}`).
