use std::env;
use std::error::Error;
use std::io::{Read, Write};
use std::mem::drop;
use std::net::{TcpListener, TcpStream};
use std::path::Path;

use move_binary_format::file_format::CompiledModule;
use move_bytecode_source_map::utils::source_map_from_file;
use move_core_types::account_address::AccountAddress;
use move_symbol_pool::Symbol;
use move_transactional_test_runner::framework::MaybeNamedCompiledModule;

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

async fn handle_client(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let named_addresses = vec![
        ("off_by_2_192".to_string(), NumericalAddress::parse_str("0x0")?),
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

    // publish the challenge module
    let mod_path = "./chall/build/off_by_2_192/bytecode_modules/pool.mv";
    let src_path = "./chall/build/off_by_2_192/debug_info/pool.json";
    let mod_bytes = match std::fs::read(mod_path) {
        Ok(b) => b,
        Err(e) => handle_err!(stream, "read pool.mv", e),
    };
    let module = match CompiledModule::deserialize_with_defaults(&mod_bytes) {
        Ok(m) => m,
        Err(e) => return Err(Box::new(e)),
    };
    let source_map = source_map_from_file(Path::new(src_path)).ok();
    let mncp = vec![MaybeNamedCompiledModule {
        named_address: Some(Symbol::from("off_by_2_192")),
        module,
        source_map,
    }];
    let chall_addr: AccountAddress = match suitf
        .publish_compiled_module(mncp, Vec::new(), Some("challenger".to_string()))
        .await
    {
        Ok(a) => a,
        Err(e) => handle_err!(stream, "publish challenge", e),
    };
    let _ = writeln!(stream, "[SERVER] challenge published at: {}", chall_addr);

    // seed + share the pool.
    // TODO(finals): `seed` must be a Coin<SUI> (~1_000_000) — source it from the challenger's
    // gas coin / a split; pin the FakeID on the real adapter object numbering.
    let seed_coin = FakeID::Enumerated(0, 0); // <-- ADAPTER-SPECIFIC, pin on run
    if let Err(e) = suitf
        .call_function(
            chall_addr,
            "pool",
            "create_and_share",
            vec![SuiValue::Object(seed_coin, None)],
            Vec::new(),
            Some("challenger".to_string()),
        )
        .await
    {
        handle_err!(stream, "create_and_share", e);
    }
    // the shared Pool object id after create_and_share:
    let pool_id = FakeID::Enumerated(2, 0); // <-- ADAPTER-SPECIFIC, pin on run

    // read + publish the player's solve module
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
    let mncp_sol = vec![MaybeNamedCompiledModule {
        named_address: Some(Symbol::from("solution")),
        module: sol_module,
        source_map: None,
    }];
    let sol_addr = match suitf
        .publish_compiled_module(mncp_sol, vec!["off_by_2_192".to_string()], Some("solver".to_string()))
        .await
    {
        Ok(a) => a,
        Err(e) => handle_err!(stream, "publish solution", e),
    };
    let _ = writeln!(stream, "[SERVER] solution published at: {}", sol_addr);

    // run the solve
    if let Err(e) = suitf
        .call_function(
            sol_addr,
            "solve",
            "solve",
            vec![SuiValue::Object(pool_id, None)],
            Vec::new(),
            Some("solver".to_string()),
        )
        .await
    {
        handle_err!(stream, "solve", e);
    }

    // validate: flag() aborts unless the reserve is drained
    match suitf
        .call_function(
            chall_addr,
            "pool",
            "flag",
            vec![SuiValue::Object(pool_id, None)],
            Vec::new(),
            Some("solver".to_string()),
        )
        .await
    {
        Ok(_) => {
            if let Ok(flag) = env::var("FLAG") {
                let _ = writeln!(stream, "[SERVER] solved! {}", flag.trim());
            } else {
                let _ = writeln!(stream, "[SERVER] solved, but FLAG env not set");
            }
        }
        Err(_) => {
            let _ = writeln!(stream, "[SERVER] not solved: the pool still holds its reserve");
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
