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

    if let Err(e) = suitf.call_function(chall_addr, "bank", "create_and_share", Vec::new(), Vec::new(), Some("challenger".to_string())).await {
        handle_err!(stream, "create_and_share", e);
    }
    let bank_id = FakeID::Enumerated(2, 0);

    let seed_coin = FakeID::Enumerated(0, 0);
    if let Err(e) = suitf.call_function(
        chall_addr, "bank", "fund",
        vec![SuiValue::Object(bank_id, None), SuiValue::Object(seed_coin, None)],
        vec![sui_type()],
        Some("challenger".to_string()),
    ).await {
        handle_err!(stream, "fund<SUI>", e);
    }

    let treasury = FakeID::Enumerated(1, 0);
    let solver_addr = "0x0";
    if let Err(e) = suitf.call_function(
        chall_addr, "cheap", "mint",
        vec![
            SuiValue::Object(treasury, None),
            SuiValue::MoveValue(serde_json::json!("1000000")),
            SuiValue::MoveValue(serde_json::json!(solver_addr)),
        ],
        Vec::new(),
        Some("challenger".to_string()),
    ).await {
        handle_err!(stream, "cheap::mint", e);
    }
    let cheap_coin = FakeID::Enumerated(4, 0);

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
    let sol_addr = match suitf.publish_compiled_module(mncp_sol, vec!["cross_collateral".to_string()], Some("solver".to_string())).await {
        Ok(a) => a,
        Err(e) => handle_err!(stream, "publish solution", e),
    };
    let _ = writeln!(stream, "[SERVER] solution published at: {}", sol_addr);

    if let Err(e) = suitf.call_function(
        sol_addr, "solve", "solve",
        vec![SuiValue::Object(bank_id, None), SuiValue::Object(cheap_coin, None)],
        Vec::new(),
        Some("solver".to_string()),
    ).await {
        handle_err!(stream, "solve", e);
    }

    match suitf.call_function(
        chall_addr, "bank", "flag",
        vec![SuiValue::Object(bank_id, None)],
        vec![sui_type()],
        Some("solver".to_string()),
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
