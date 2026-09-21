# Cross Collateral

**Category:** blockchain (Sui / Move)
**Difficulty:** hard

CrossCollateral is a multi-asset bank. `deposit<T>` takes a `Coin<T>`, stores it under its
type, and hands you a `Voucher`. `withdraw<T>` takes a `Voucher` back and returns a `Coin<T>`
from the bank's holdings of that type. The bank keeps a healthy SUI reserve.

You are funded with a large amount of a worthless token. Walk away with the SUI reserve.

## Goal

Drain the bank's SUI. When it can't return its SUI holdings, the flag is yours.

## Connect

Launch an instance from the platform and connect to the endpoint. You get the published
package id, the shared `Bank` object id, your funded worthless-token coins and gas, plus a
channel to submit your solve transaction.

## Provided

- `challenge/sources/bank.move` — the bank module
- `challenge/Move.toml`

## Notes

Move's type system is doing its job everywhere you'd expect it to. The gap is one place where
a type *should* have been carried along and wasn't — a value that means one thing for the
asset you deposited and something very different for the asset you take out.
