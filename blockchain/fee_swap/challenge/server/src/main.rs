use fee_swap::{Ix, AUTH_SEED, DECIMALS};
use sol_ctf_framework::ChallengeBuilder;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    rent::Rent,
    signature::{Keypair, Signer},
};
use solana_system_interface::{instruction as system_instruction, program as system_program};
use spl_token_2022::{
    extension::{transfer_fee::instruction as fee_ix, ExtensionType, StateWithExtensions},
    instruction as token_ix,
    state::{Account as TokenAccount, Mint},
};
use std::{
    error::Error,
    fs,
    io::Write,
    net::{TcpListener, TcpStream},
};

const FEE_BPS: u16 = 500;
const RESERVE_B: u64 = 100_000_000;
const USER_A: u64 = 200_000_000;

fn tid() -> Pubkey {
    spl_token_2022::id()
}

fn enc(program: Pubkey, data: Ix, metas: Vec<AccountMeta>) -> Instruction {
    Instruction { program_id: program, accounts: metas, data: borsh::to_vec(&data).unwrap() }
}

fn account_space(fee_mint: bool) -> usize {
    let exts = if fee_mint { vec![ExtensionType::TransferFeeAmount] } else { vec![] };
    ExtensionType::try_calculate_account_len::<TokenAccount>(&exts).unwrap()
}

fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:1337")?;
    loop {
        let (stream, _) = listener.accept()?;
        std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("runtime: {e}");
                    return;
                }
            };
            if let Err(e) = rt.block_on(handle(stream)) {
                eprintln!("handler error: {e}");
            }
        });
    }
}

async fn handle(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut builder = ChallengeBuilder::try_from(socket.try_clone()?)?;
    let program = builder
        .add_program("./fee_swap.so", Some(Pubkey::new_unique()))
        .ok_or("duplicate program")?;
    let (authority, bump) = Pubkey::find_program_address(&[AUTH_SEED], &program);

    let user = Keypair::new();
    let mint_a = Keypair::new();
    let mint_b = Keypair::new();
    let vault_a = Keypair::new();
    let vault_b = Keypair::new();
    let user_a = Keypair::new();
    let user_b = Keypair::new();
    let pool = Keypair::new();

    builder.builder.add_account(user.pubkey(), Account::new(1_000_000_000, 0, &system_program::ID));

    let mut challenge = builder.build().await;
    let payer_kp = challenge.ctx.payer.insecure_clone();
    let payer = payer_kp.pubkey();

    // mint A: token-2022 with a transfer fee
    let a_space = ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::TransferFeeConfig]).unwrap();
    challenge.run_ixs_full(&[
        system_instruction::create_account(&payer, &mint_a.pubkey(), Rent::default().minimum_balance(a_space), a_space as u64, &tid()),
        fee_ix::initialize_transfer_fee_config(&tid(), &mint_a.pubkey(), Some(&payer), Some(&payer), FEE_BPS, u64::MAX)?,
        token_ix::initialize_mint2(&tid(), &mint_a.pubkey(), &payer, None, DECIMALS)?,
    ], &[&payer_kp, &mint_a], &payer).await?;

    // mint B: plain token-2022
    let b_space = ExtensionType::try_calculate_account_len::<Mint>(&[]).unwrap();
    challenge.run_ixs_full(&[
        system_instruction::create_account(&payer, &mint_b.pubkey(), Rent::default().minimum_balance(b_space), b_space as u64, &tid()),
        token_ix::initialize_mint2(&tid(), &mint_b.pubkey(), &payer, None, DECIMALS)?,
    ], &[&payer_kp, &mint_b], &payer).await?;

    for (acc, mint, owner, fee_mint) in [
        (&vault_a, mint_a.pubkey(), authority, true),
        (&vault_b, mint_b.pubkey(), authority, false),
        (&user_a, mint_a.pubkey(), user.pubkey(), true),
        (&user_b, mint_b.pubkey(), user.pubkey(), false),
    ] {
        let space = account_space(fee_mint);
        challenge.run_ixs_full(&[
            system_instruction::create_account(&payer, &acc.pubkey(), Rent::default().minimum_balance(space), space as u64, &tid()),
            token_ix::initialize_account3(&tid(), &acc.pubkey(), &mint, &owner)?,
        ], &[&payer_kp, acc], &payer).await?;
    }

    challenge.run_ixs_full(&[
        token_ix::mint_to(&tid(), &mint_a.pubkey(), &user_a.pubkey(), &payer, &[], USER_A)?,
        token_ix::mint_to(&tid(), &mint_b.pubkey(), &vault_b.pubkey(), &payer, &[], RESERVE_B)?,
    ], &[&payer_kp], &payer).await?;

    let pool_space: usize = 200;
    challenge.run_ixs_full(&[
        system_instruction::create_account(&payer, &pool.pubkey(), Rent::default().minimum_balance(pool_space), pool_space as u64, &program),
        enc(program, Ix::InitPool { bump }, vec![
            AccountMeta::new(pool.pubkey(), false),
            AccountMeta::new_readonly(vault_a.pubkey(), false),
            AccountMeta::new_readonly(vault_b.pubkey(), false),
            AccountMeta::new_readonly(mint_a.pubkey(), false),
            AccountMeta::new_readonly(mint_b.pubkey(), false),
        ]),
    ], &[&payer_kp, &pool], &payer).await?;

    writeln!(socket, "program: {}", program)?;
    writeln!(socket, "user: {}", user.pubkey())?;
    writeln!(socket, "authority: {}", authority)?;
    writeln!(socket, "pool: {}", pool.pubkey())?;
    writeln!(socket, "mint_a: {}", mint_a.pubkey())?;
    writeln!(socket, "mint_b: {}", mint_b.pubkey())?;
    writeln!(socket, "vault_a: {}", vault_a.pubkey())?;
    writeln!(socket, "vault_b: {}", vault_b.pubkey())?;
    writeln!(socket, "user_a: {}", user_a.pubkey())?;
    writeln!(socket, "user_b: {}", user_b.pubkey())?;
    writeln!(socket, "token_program: {}", tid())?;
    writeln!(socket, "reserve_b: {}", RESERVE_B)?;

    for _ in 0..8 {
        let ix = match challenge.read_instruction(program) {
            Ok(ix) => ix,
            Err(_) => break,
        };
        if challenge.run_ixs_full(&[ix], &[&user], &user.pubkey()).await.is_err() {
            writeln!(socket, "swap reverted")?;
        }
    }

    let data = challenge.ctx.banks_client.get_account(vault_b.pubkey()).await?.unwrap().data;
    let remaining = StateWithExtensions::<TokenAccount>::unpack(&data)?.base.amount;
    writeln!(socket, "vault_b remaining: {}", remaining)?;

    if remaining == 0 {
        let flag = std::env::var("FLAG")
            .or_else(|_| fs::read_to_string("flag.txt"))
            .unwrap_or_else(|_| "H7CTF{local_test_flag}".to_string());
        writeln!(socket, "reserve drained. {}", flag.trim())?;
    } else {
        writeln!(socket, "reserve not drained. no flag.")?;
    }

    Ok(())
}
