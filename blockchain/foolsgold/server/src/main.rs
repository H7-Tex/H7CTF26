use std::env;
use std::error::Error;
use std::io::{Read, Write};
use std::mem::drop;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::str::FromStr;

use move_binary_format::file_format::CompiledModule;
use move_bytecode_source_map::utils::source_map_from_file;
use move_core_types::account_address::AccountAddress;
use move_core_types::language_storage::{StructTag, TypeTag};
use move_core_types::runtime_value::MoveValue;
use move_symbol_pool::Symbol;
use move_transactional_test_runner::framework::MaybeNamedCompiledModule;

use sui_types::Identifier;
use sui_ctf_framework::{NumericalAddress, SuiTF};
use sui_transactional_test_runner::{args::SuiValue, test_adapter::FakeID};

macro_rules! handle_err {
    ($stream:expr, $msg:expr, $err:expr) => {{
        let full = format!("[SERVER ERROR] {}: {}", $msg, $err);
        eprintln!("{}", full);
        let _ = $stream.write_all(full.as_bytes());
        drop($stream);
        return Err::<(), Box<dyn std::error::Error>>(full.into());
    }};
}

fn sui_type() -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::from_hex_literal("0x2").unwrap(),
        module: Identifier::from_str("sui").unwrap(),
        name: Identifier::from_str("SUI").unwrap(),
        type_params: Vec::new(),
    }))
}

fn cheap_type(chall_addr: AccountAddress) -> TypeTag {
    TypeTag::Struct(Box::new(StructTag {
        address: chall_addr,
        module: Identifier::from_str("cheap").unwrap(),
        name: Identifier::from_str("CHEAP").unwrap(),
        type_params: Vec::new(),
    }))
}

// Pull the first 0x-hex token out of a string (used to read an object's Owner).
fn first_hex_addr(s: &str) -> Option<AccountAddress> {
    let i = s.find("0x")?;
    let hex: String = s[i + 2..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    if hex.is_empty() {
        return None;
    }
    AccountAddress::from_hex_literal(&format!("0x{}", hex)).ok()
}

// Resolve an account's address via the owner of its gas coin. The framework's
// account_map only tracks named addresses, not the challenger/solver accounts,
// so get_account_address is useless here; view the account's gas coin and read
// its Owner instead. Prints the raw view so the Owner format is visible if the
// extraction needs adjusting.
async fn owner_addr(suitf: &mut SuiTF, gas: FakeID) -> Option<AccountAddress> {
    let v = match suitf.view_object(gas).await {
        Ok(Some(v)) => v,
        other => {
            eprintln!("[DBG] view {:?} returned {:?}", gas, other);
            return None;
        }
    };
    eprintln!("[DBG] view {:?} => {:#?}", gas, v);
    // Owner renders as "Account Address ( <token> )" where <token> is either a
    // 0x-hex address or a transactional-test-runner account NAME (e.g. "admin").
    let owner = v.get("Owner").and_then(|o| o.as_str())?;
    let token = owner
        .split('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .map(str::trim)
        .unwrap_or("");
    eprintln!("[DBG] {:?} owner token = {:?}", gas, token);
    if token.starts_with("0x") {
        return first_hex_addr(token);
    }
    // a named account/address -> resolve via the framework's named map
    let a = suitf.get_account_address(token);
    if a.is_none() {
        eprintln!("[DBG] get_account_address({:?}) = None", token);
    }
    a
}

async fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let named_addresses = vec![
        ("cross_collateral".to_string(), NumericalAddress::parse_str("0x0")?),
        ("solution".to_string(), NumericalAddress::parse_str("0x0")?),
        (
            "admin".to_string(),
            NumericalAddress::parse_str("0xfccc9a421bbb13c1a66a1aa98f0ad75029ede94857779c6915b44f94068b921e")?,
        ),
    ];

    let mut suitf = match SuiTF::initialize(
        named_addresses,
        Some(vec!["challenger".to_string(), "solver".to_string()]),
    ).await {
        Ok(a) => a,
        Err(e) => handle_err!(stream, "init failed", e),
    };

    // cheap::mint needs an AccountAddress recipient. The runner reports gas-coin
    // owners by NAME; only named-addresses (admin) resolve via get_account_address,
    // NOT the challenger/solver accounts. challenger=object(0,0) resolves (its
    // owner is the named "admin"); the "solver" account does NOT. So the whole
    // exploit runs under the CHALLENGER account: mint the exploit CHEAP to it and
    // sign solve with it. cross_collateral's flag only checks the bank's SUI is
    // drained (no privilege involved), so this is equivalent for the player.
    let player = "challenger".to_string();
    let player_addr = match owner_addr(&mut suitf, FakeID::Enumerated(0, 0)).await {
        Some(a) => a,
        None => handle_err!(stream, "resolve player addr", "view/parse failed"),
    };
    let challenger_addr = player_addr;
    let _ = writeln!(stream, "[SERVER] player({})={}", player, player_addr);

    // Publish bank + cheap (task 1). cheap::init runs here, minting a
    // TreasuryCap<CHEAP> to the challenger + freezing CoinMetadata.
    let mut mncp = Vec::new();
    for m in ["bank", "cheap"] {
        let mod_bytes = match std::fs::read(format!("./chall/build/cross_collateral/bytecode_modules/{}.mv", m)) {
            Ok(b) => b,
            Err(e) => handle_err!(stream, format!("read {}.mv", m), e),
        };
        let module = match CompiledModule::deserialize_with_defaults(&mod_bytes) {
            Ok(m) => m,
            Err(e) => return Err(Box::new(e)),
        };
        let source_map = source_map_from_file(Path::new(&format!("./chall/build/cross_collateral/debug_info/{}.json", m))).ok();
        mncp.push(MaybeNamedCompiledModule { named_address: Some(Symbol::from("cross_collateral")), module, source_map });
    }
    let chall_addr = match suitf.publish_compiled_module(mncp, Vec::new(), Some("challenger".to_string())).await {
        Ok(a) => a,
        Err(e) => handle_err!(stream, "publish challenge", e),
    };
    let _ = writeln!(stream, "[SERVER] challenge published at: {}", chall_addr);

    // The TreasuryCap<CHEAP> is an output of the publish command (task 1). Its
    // output index sits after the package + UpgradeCap + frozen metadata; PIN it
    // from the runner's "created: object(1,y)" lines (adjust y if mint fails).
    let treasury = FakeID::Enumerated(2, 2);

    // create_and_share() -> shared Bank (task 2 -> (2,0)).
    if let Err(e) = suitf.call_function(chall_addr, "bank", "create_and_share", Vec::new(), Vec::new(), Some("challenger".to_string())).await {
        handle_err!(stream, "create_and_share", e);
    }
    let bank_id = FakeID::Enumerated(3, 0);

    // Mint a distinct SUI reserve coin (task 3 -> (3,0)) via a name-signed split
    // (a gas coin can't double as an argument + gas payment).
    if let Err(e) = suitf.fund_account_named("challenger".to_string(), 1_000_000, "challenger".to_string()).await {
        handle_err!(stream, "fund sui reserve", e);
    }
    let sui_reserve = FakeID::Enumerated(4, 0);

    // list<SUI>(bank, price=1000, reserve): the SUI the solver will drain (task 4).
    if let Err(e) = suitf.call_function(
        chall_addr, "bank", "list",
        vec![SuiValue::Object(bank_id, None), SuiValue::MoveValue(MoveValue::U64(1000)), SuiValue::Object(sui_reserve, None)],
        vec![sui_type()],
        Some("challenger".to_string()),
    ).await {
        handle_err!(stream, "list<SUI>", e);
    }

    // Mint a tiny CHEAP coin to the challenger to register CHEAP's balance/price (task 5 -> (5,0)).
    if let Err(e) = suitf.call_function(
        chall_addr, "cheap", "mint",
        vec![SuiValue::Object(treasury, None), SuiValue::MoveValue(MoveValue::U64(1)), SuiValue::MoveValue(MoveValue::Address(challenger_addr))],
        Vec::new(),
        Some("challenger".to_string()),
    ).await {
        handle_err!(stream, "cheap::mint (list seed)", e);
    }
    let cheap_list = FakeID::Enumerated(6, 0);

    // list<CHEAP>(bank, price=1, tiny): so deposit<CHEAP> is allowed (task 6).
    if let Err(e) = suitf.call_function(
        chall_addr, "bank", "list",
        vec![SuiValue::Object(bank_id, None), SuiValue::MoveValue(MoveValue::U64(1)), SuiValue::Object(cheap_list, None)],
        vec![cheap_type(chall_addr)],
        Some("challenger".to_string()),
    ).await {
        handle_err!(stream, "list<CHEAP>", e);
    }

    // Mint 1000 CHEAP to the player: deposit 1000 CHEAP -> withdraw 1000*1000/1 =
    // 1_000_000 SUI (the inverted-ratio bug) drains the whole reserve (task 7 -> (7,0)).
    if let Err(e) = suitf.call_function(
        chall_addr, "cheap", "mint",
        vec![SuiValue::Object(treasury, None), SuiValue::MoveValue(MoveValue::U64(1000)), SuiValue::MoveValue(MoveValue::Address(player_addr))],
        Vec::new(),
        Some(player.clone()),
    ).await {
        handle_err!(stream, "cheap::mint (player)", e);
    }
    let cheap_solver = FakeID::Enumerated(8, 0);

    // Read + publish the player's solve module (task 8), signed by the solver.
    let mut buf = vec![0u8; 200_000];
    let n = match stream.read(&mut buf) {
        Ok(0) => handle_err!(stream, "no solution", "empty"),
        Ok(n) => n,
        Err(e) => handle_err!(stream, "read solution", e),
    };
    let sol_module = match CompiledModule::deserialize_with_defaults(&buf[..n].to_vec()) {
        Ok(m) => m,
        Err(e) => handle_err!(stream, "deserialize solution", e),
    };
    let mncp_sol = vec![MaybeNamedCompiledModule { named_address: Some(Symbol::from("solution")), module: sol_module, source_map: None }];
    let sol_addr = match suitf.publish_compiled_module(mncp_sol, vec!["cross_collateral".to_string()], Some(player.clone())).await {
        Ok(a) => a,
        Err(e) => handle_err!(stream, "publish solution", e),
    };
    let _ = writeln!(stream, "[SERVER] solution published at: {}", sol_addr);

    // solve(bank, cheap_coin) (task 9), signed by the solver.
    if let Err(e) = suitf.call_function(
        sol_addr, "solve", "solve",
        vec![SuiValue::Object(bank_id, None), SuiValue::Object(cheap_solver, None)],
        Vec::new(),
        Some(player.clone()),
    ).await {
        handle_err!(stream, "solve", e);
    }

    // flag<SUI>(bank) aborts unless the SUI reserve is drained (task 10).
    match suitf.call_function(
        chall_addr, "bank", "flag",
        vec![SuiValue::Object(bank_id, None)],
        vec![sui_type()],
        Some(player.clone()),
    ).await {
        Ok(_) => {
            if let Ok(flag) = env::var("FLAG") {
                let _ = writeln!(stream, "[SERVER] solved! {}", flag.trim());
            } else {
                let _ = writeln!(stream, "[SERVER] solved, but FLAG env not set");
            }
        }
        Err(_) => {
            let _ = writeln!(stream, "[SERVER] not solved: the bank still holds its SUI");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:1337")?;
    println!("[SERVER] listening on 1337");
    let local = tokio::task::LocalSet::new();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = local
                    .run_until(async move {
                        tokio::task::spawn_local(async {
                            if let Err(e) = handle_client(stream).await {
                                eprintln!("[SERVER] connection closed: {}", e);
                            }
                        })
                        .await
                        .unwrap();
                    })
                    .await;
            }
            Err(e) => println!("[SERVER] accept error: {}", e),
        }
    }
    drop(listener);
    Ok(())
}
