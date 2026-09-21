use perp_guard::{healthy, Ix, COUNT_OFF, HEADER, POS_SIZE, PRICE_SCALE, SEIZED_OFF};
use sol_ctf_framework::ChallengeBuilder;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};
use solana_system_interface::program as system_program;
use std::{
    error::Error,
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
    str::FromStr,
};

const OBLIGATION_BYTES: usize = 512_000;
const MAX_ROUNDS: usize = 256;
const P0: u64 = PRICE_SCALE as u64;
const P1: u64 = (PRICE_SCALE / 2) as u64;
const COLLATERAL: u64 = 1_000_000;
const DEBT: u64 = 800_000;

fn enc(program: Pubkey, data: Ix, metas: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: program, accounts: metas, data: borsh::to_vec(&data).unwrap() }
}

fn compute_budget(limit: u32) -> Instruction {
    let mut data = vec![2u8];
    data.extend_from_slice(&limit.to_le_bytes());
    Instruction {
        program_id: Pubkey::from_str("ComputeBudget111111111111111111111111111111").unwrap(),
        accounts: vec![],
        data,
    }
}

fn account_health(data: &[u8]) -> (u64, u128, u128) {
    let count = u64::from_le_bytes(data[COUNT_OFF..COUNT_OFF + 8].try_into().unwrap());
    let (mut c, mut d) = (0u128, 0u128);
    for i in 0..count as usize {
        let off = HEADER + i * POS_SIZE;
        c += u64::from_le_bytes(data[off..off + 8].try_into().unwrap()) as u128;
        d += u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()) as u128;
    }
    (count, c, d)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:1337")?;
    loop {
        let (stream, _) = listener.accept()?;
        tokio::spawn(async move {
            if let Err(e) = handle(stream).await {
                eprintln!("handler error: {e}");
            }
        });
    }
}

async fn handle(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut builder = ChallengeBuilder::try_from(socket.try_clone()?)?;

    let solve = builder.input_program()?;
    let program = builder
        .add_program("./perp_guard.so", Some(Pubkey::new_unique()))
        .ok_or("duplicate program")?;

    let admin = Keypair::new();
    let user = Keypair::new();
    let market = Keypair::new().pubkey();
    let obligation = Keypair::new().pubkey();

    writeln!(socket, "program: {}", program)?;
    writeln!(socket, "user: {}", user.pubkey())?;
    writeln!(socket, "market: {}", market)?;
    writeln!(socket, "obligation: {}", obligation)?;

    builder.builder.add_account(admin.pubkey(), Account::new(1_000_000_000, 0, &system_program::ID));
    builder.builder.add_account(user.pubkey(), Account::new(1_000_000_000, 0, &system_program::ID));
    builder.builder.add_account(market, Account::new(1_000_000_000, 128, &program));
    builder.builder.add_account(obligation, Account::new(10_000_000_000, OBLIGATION_BYTES, &program));

    let mut challenge = builder.build().await;

    challenge.run_ixs_full(
        &[enc(program, Ix::InitMarket { price: P0, reserve: COLLATERAL },
            vec![AccountMeta::new(market, false), AccountMeta::new_readonly(admin.pubkey(), true)])],
        &[&admin], &admin.pubkey()).await?;

    challenge.run_ixs_full(
        &[enc(program, Ix::InitObligation,
            vec![AccountMeta::new(obligation, false), AccountMeta::new_readonly(user.pubkey(), true)])],
        &[&user], &user.pubkey()).await?;

    challenge.run_ixs_full(
        &[enc(program, Ix::OpenPosition { collateral: COLLATERAL, debt: DEBT },
            vec![AccountMeta::new_readonly(market, false), AccountMeta::new(obligation, false), AccountMeta::new_readonly(user.pubkey(), true)])],
        &[&user], &user.pubkey()).await?;

    for _ in 0..MAX_ROUNDS {
        let player_ix = match challenge.read_instruction(solve) {
            Ok(ix) => ix,
            Err(_) => break,
        };
        if challenge
            .run_ixs_full(&[compute_budget(1_400_000), player_ix], &[&user], &user.pubkey())
            .await
            .is_err()
        {
            writeln!(socket, "a padding round reverted")?;
        }
    }

    challenge.run_ixs_full(
        &[enc(program, Ix::SetPrice { price: P1 },
            vec![AccountMeta::new(market, false), AccountMeta::new_readonly(admin.pubkey(), true)])],
        &[&admin], &admin.pubkey()).await?;

    let data = challenge.ctx.banks_client.get_account(obligation).await?.unwrap().data;
    let (count, total_c, total_d) = account_health(&data);
    let underwater = !healthy(total_c, total_d, P1 as u128);

    let liq = challenge
        .run_ix(enc(program, Ix::Liquidate,
            vec![AccountMeta::new_readonly(market, false), AccountMeta::new(obligation, false)]))
        .await;

    let seized = challenge.ctx.banks_client.get_account(obligation).await?.unwrap().data[SEIZED_OFF] == 1;

    writeln!(socket, "positions: {}  underwater: {}  liquidate_ok: {}  seized: {}",
        count, underwater, liq.is_ok(), seized)?;

    if underwater && liq.is_err() && !seized {
        let flag = std::env::var("FLAG")
            .or_else(|_| fs::read_to_string("flag.txt"))
            .unwrap_or_else(|_| "H7CTF{local_test_flag}".to_string());
        writeln!(socket, "the keeper ran out of gas. {}", flag.trim())?;
    } else {
        writeln!(socket, "the position was cleared. no flag.")?;
    }

    Ok(())
}
