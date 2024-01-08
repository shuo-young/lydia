mod contract;
use std::env;

use crate::contract::contract::Contract;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let platform = &args[1];
    let logic_address = &args[2];
    let storage_address = &args[3];

    let storage_addr = if storage_address.is_empty() {
        logic_address
    } else {
        logic_address
    };

    println!("input contract address {}", logic_address);
    println!("contract blockchain platform {}", platform);

    let mut input_contract = Contract::new(
        platform.to_string(),
        logic_address.to_string(),
        storage_addr.to_string(),
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
