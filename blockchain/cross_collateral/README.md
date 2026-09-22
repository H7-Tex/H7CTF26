# Cross Collateral

`blockchain` `sui` `hard`

crosscollateral is a multi-asset bank. deposit any listed asset, get a ticket, redeem it later for any other listed asset, converted at the bank's posted prices. it holds a real SUI reserve.

you're funded with a bag of a worthless listed token. leave with the SUI.

#### connect
spin up an instance, connect to the endpoint. you get the package id, the shared `Bank` object, your worthless-token coins + gas, and a channel to send your solve tx. drain the SUI, grab the flag.

#### provided
- `challenge/sources/bank.move`
- `challenge/sources/cheap.move`
- `challenge/Move.toml`

#### notes
the bank prices every asset and converts between them, so trading junk up to SUI should cost you dearly, not pay. read the conversion, specifically which way the exchange rate points.
