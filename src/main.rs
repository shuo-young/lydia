mod contract;
use crate::contract::contract::Contract;
mod graph;
use crate::graph::call_graph::CallGraph;
#[allow(unused_imports)]
use log::{debug, error, info, log_enabled, Level};
use std::env;
use std::time::Instant;

#[derive(Debug)]
struct Source {
    platform: String,
    logic_addr: String,
    storage_addr: String,
    func_sign: String,
    block_number: u64,
    caller: String,
    caller_func_sign: String,
    call_site: String,
    level: u32,
}

impl Source {
    pub fn new(
        platform: String,
        logic_addr: String,
        storage_addr: String,
        func_sign: String,
        block_number: u64,
        caller: String,
        caller_func_sign: String,
        call_site: String,
        level: u32,
    ) -> Source {
        Source {
            platform: platform,
            logic_addr: logic_addr,
            storage_addr: storage_addr,
            func_sign: func_sign,
            block_number: block_number,
            caller: caller,
            caller_func_sign: caller_func_sign,
            call_site: call_site,
            level: level,
        }
    }
}

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
    let start = Instant::now();

    let mut input_contract = Contract::new(
        platform.to_string(),
        logic_address.to_string(),
        storage_address.to_string(),
        "".to_string(), // which function to test, leave blank to test all functions
        16000000,
        "msg.sender".to_string(), // set caller
        "".to_string(),           // the call sites in this contract's function (intput)
        0,
    );
    if let Err(e) = input_contract.analyze().await {
        eprintln!("An error occurred during analysis: {}", e);
    };

    let func_sign_list = input_contract.get_func_sign_list();
    let external_call_in_func_signature = input_contract.get_external_call_in_func_signature();
    info!(
        "function signature list in contract {}: {:?}",
        logic_address, func_sign_list
    );
    info!(
        "external call in function signature: {:?}",
        external_call_in_func_signature
    );

    let external_call_in_func_signature = external_call_in_func_signature.clone();

    // let visited_contracts: Vec<String> = Vec::new();
    // let visited_funcs: Vec<String> = Vec::new();
    // let m_call_depth: u32 = 0;
    // let call_graph_str: String = String::new();

    // let mut contracts: Vec<HashMap<String, Contract>> = Vec::new();

    // let mut external_call_in_func_signature = mem::take(external_call_in_func_signature);
    if input_contract.is_createbin().clone() {
    } else {
        let mut max_call_depth: u32 = 0;
        for func_sign in external_call_in_func_signature.into_iter() {
            println!("{}", func_sign);
            let source = Source {
                platform: platform.to_string(),
                logic_addr: logic_address.clone(),
                storage_addr: storage_address.clone(),
                func_sign,
                block_number: 16000000,
                caller: "msg.sender".to_string(),
                caller_func_sign: "".to_string(),
                call_site: "".to_string(),
                level: 0,
            };
            let mut cross_contract_call_graph = CallGraph::new(platform.to_string());

            if let Err(e) = cross_contract_call_graph
                .construct_cross_contract_call_graph(source)
                .await
            {
                eprintln!("An error occurred during call graph construction: {}", e);
            };
            // cross_contract_call_graph.construct_cross_contract_call_graph(source);
            let call_graph_str = cross_contract_call_graph.get_output();
            println!("{}", call_graph_str);
        }
    }
    let duration = start.elapsed();
    info!("analyze contract {} consumes {:?}", logic_address, duration);
}
