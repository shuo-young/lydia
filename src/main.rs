mod contract;
mod flow;
mod outputter;
use crate::contract::contract::Contract;
use crate::flow::flow_analysis::FlowAnalysis;
mod graph;
use crate::graph::call_graph::CallGraph;
use crate::outputter::result_structure::{
    ExternalCall, OpCreation, Overlap, Result, SemanticFeatures,
};
#[allow(unused_imports)]
use log::{debug, error, info, log_enabled, Level};
use serde_json;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

const JSON_PATH: &str = "./output/";
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
    level: i32,
}

#[allow(unused_mut)]
#[allow(unused_variables)]
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

    let mut visited_contracts: HashSet<String> = HashSet::new();
    let mut visited_funcs: HashSet<String> = HashSet::new();

    let mut call_path: Vec<String> = Vec::new();
    let mut max_call_depth: i32 = 0;

    let mut contracts = HashMap::new();
    if input_contract.is_createbin().clone() {
    } else {
        for func_sign in external_call_in_func_signature.clone().into_iter() {
            // let mut contracts_mut = contracts.borrow_mut();
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
            let mut cross_contract_call_graph =
                CallGraph::new(platform.to_string(), &mut contracts);

            if let Err(e) = cross_contract_call_graph
                .construct_cross_contract_call_graph(source)
                .await
            {
                eprintln!("An error occurred during call graph construction: {}", e);
            };
            let call_graph_str: &str = cross_contract_call_graph.get_output();
            visited_contracts.extend(cross_contract_call_graph.get_visited_contracts().clone());
            visited_funcs.extend(cross_contract_call_graph.get_visited_funcs().clone());

            if cross_contract_call_graph.max_level > max_call_depth {
                max_call_depth = cross_contract_call_graph.max_level;
            }

            call_path.push(call_graph_str.to_string());
            println!("{}", call_graph_str);
        }
        info!("length of contracts: {}", contracts.len());
    }
    let mut result = Result {
        is_attack: false,
        warning: String::from("medium"),
        attack_matrix: HashMap::new(),
        analysis_loc: String::new(),
        platform: String::from("ETH"),
        block_number: 16000000, // Assuming block_number is provided elsewhere in the code
        time: None,
        semantic_features: SemanticFeatures {
            op_creation: OpCreation {
                op_multicreate: false,
                op_solecreate: false,
            },
            op_selfdestruct: false,
            op_env: false,
        },
        external_call: ExternalCall {
            externalcall_inhook: false,
            externalcall_infallback: false,
        },
        call_paths: Vec::new(),
        visited_contracts: Vec::new(),
        visited_contracts_num: 0,
        visited_funcs: Vec::new(),
        visited_funcs_num: 0,
        max_call_depth: 0,
        contract_funcsigs: Vec::new(),
        contract_funcsigs_external_call: Vec::new(),
        sensitive_callsigs: Vec::new(),
        overlap: Overlap {
            has_overlap: false,
            overlap_external_call: Vec::new(),
        },
        reentrancy_path_info: std::collections::HashMap::new(),
    };

    let mut detector = FlowAnalysis::new(
        &contracts,
        func_sign_list.clone(),
        external_call_in_func_signature,
        visited_contracts,
        visited_funcs,
    );

    let (res_bool, res) = detector.detect();
    result.is_attack = res_bool;
    result.attack_matrix = res;
    result.call_paths = call_path;
    result.max_call_depth = max_call_depth as u32;
    result.visited_contracts = detector.visited_contracts.clone().drain().collect();
    result.visited_contracts_num = result.visited_contracts.len();
    result.visited_funcs = detector.visited_funcs.clone().drain().collect();
    result.visited_funcs_num = result.visited_funcs.len();

    let serialized = serde_json::to_string_pretty(&result).unwrap();
    let mut file = File::create(format!("{}{}.json", JSON_PATH, logic_address)).unwrap();
    file.write(serialized.as_bytes()).unwrap();

    let duration = start.elapsed();
    info!("analyze contract {} consumes {:?}", logic_address, duration);
}
