mod contract;
use crate::contract::contract::Contract;
#[allow(unused_imports)]
use log::{debug, error, info, log_enabled, Level};
use std::env;

#[tokio::main]
async fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("Not enough arguments. Usage: program platform logic_address [storage_address]");
    }

    let platform = &args[1];
    let logic_address = &args[2];
    let storage_address = args.get(3).unwrap_or(logic_address);
    info!("input contract logic address {}", logic_address);
    info!("input contract storage address {}", storage_address);
    info!("contract blockchain platform {}", platform);

    let mut input_contract = Contract::new(
        platform.to_string(),
        logic_address.to_string(),
        storage_address.to_string(),
        "".to_string(),
        16000000,
        "msg.sender".to_string(),
        "".to_string(),
        0,
    );
    if let Err(e) = input_contract.analyze().await {
        eprintln!("An error occurred during analysis: {}", e);
    };
}
