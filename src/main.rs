mod contract;
mod flow;
mod outputter;
use crate::contract::contract::Contract;
use crate::flow::flow_analysis::FlowAnalysis;
mod graph;
use crate::graph::call_graph::CallGraph;
use crate::outputter::result_structure::{
    ExternalCall, OpCreation, Overlap, PathInfo, Result, SemanticFeatures,
};
use clap::{App, Arg};
#[allow(unused_imports)]
use log::{debug, error, info, log_enabled, Level};
use serde_json;
use std::collections::{HashMap, HashSet};

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
    let matches = App::new("Lydia")
        .version("1.0")
        .author("Shuo Yang <yangsh233@mail2.sysu.edu.cn>")
        .about("Finding Attacker Contracts with Malicious Intents")
        .arg(
            Arg::with_name("blockchain_platform")
                .short('b')
                .long("blockchain_platform")
                .value_name("PLATFORM")
                .help("The blockchain platform where the test contract is deployed")
                .takes_value(true)
                .default_value("ETH"),
        )
        .arg(
            Arg::with_name("logic_address")
                .short('l')
                .long("logic_address")
                .value_name("LOGIC_ADDR")
                .help("Contract address for storing business logic")
                .takes_value(true)
                .required(true), // Assume it's required as there is no default value
        )
        .arg(
            Arg::with_name("storage_address")
                .short('s')
                .long("storage_address")
                .value_name("STORAGE_ADDR")
                .help("Contract address for storing business data")
                .takes_value(true), // .default_value(""), // Assuming default is an empty string
        )
        .arg(
            Arg::with_name("block_number")
                .short('n')
                .long("block_number")
                .value_name("BLOCK_NUMBER")
                .help("Blockchain snapshot block number")
                .takes_value(true)
                .default_value("16000000"),
        )
        .get_matches();

    let platform = matches.value_of("blockchain_platform").unwrap();
    let logic_address = matches.value_of("logic_address").unwrap();
    let storage_address = matches.value_of("storage_address").unwrap_or(logic_address);
    let block_number = matches.value_of("block_number").unwrap();
    info!("input contract logic address {}", logic_address);
    info!("input contract storage address {}", storage_address);
    info!("contract blockchain platform {}", platform);
    let start = Instant::now();

    let mut input_contract = Contract::new(
        String::from(platform),
        String::from(logic_address),
        String::from(storage_address),
        "".to_string(), // which function to test, leave blank to test all functions
        block_number.parse::<u64>().unwrap(),
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

    let mut external_call_in_func_signature = external_call_in_func_signature.clone();

    let mut visited_contracts: HashSet<String> = HashSet::new();
    let mut visited_funcs: HashSet<String> = HashSet::new();

    let mut call_path: Vec<String> = Vec::new();
    let mut max_call_depth: i32 = 0;

    let is_createbin = input_contract.is_createbin().clone();

    let mut contracts = HashMap::new();
    if input_contract.is_createbin().clone() {
        let source = Source {
            platform: platform.to_string(),
            logic_addr: logic_address.to_string(),
            storage_addr: storage_address.to_string(),
            func_sign: "__function_selector__".to_string(),
            block_number: 16000000,
            caller: "msg.sender".to_string(),
            caller_func_sign: "".to_string(),
            call_site: "".to_string(),
            level: 0,
        };
        let mut cross_contract_call_graph = CallGraph::new(platform.to_string(), &mut contracts);

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

        call_path.push(format!("{}\n", call_graph_str));
        println!("{}", call_graph_str);
    } else {
        for func_sign in external_call_in_func_signature.clone().into_iter() {
            // let mut contracts_mut = contracts.borrow_mut();
            println!("call flow originated from function {}", func_sign);
            let source = Source {
                platform: platform.to_string(),
                logic_addr: logic_address.to_string(),
                storage_addr: storage_address.to_string(),
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
        block_number: 16000000,
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
        reentrancy_path_info: HashMap::new(),
    };

    let mut detector = FlowAnalysis::new(
        &contracts,
        func_sign_list.clone(),
        external_call_in_func_signature.clone(),
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

    result.semantic_features.op_creation.op_multicreate = detector.op_multicreate_analysis();
    result.semantic_features.op_creation.op_solecreate = detector.op_solecreate_analysis();
    result.semantic_features.op_selfdestruct = detector.op_selfdestruct_analysis();
    result.semantic_features.op_env = detector.tainted_env_call_arg();

    result.external_call.externalcall_inhook = detector.externalcall_inhook();
    result.external_call.externalcall_infallback = detector.externalcall_infallback();

    result.sensitive_callsigs = detector.get_sig_info().to_vec();
    result.contract_funcsigs = func_sign_list.to_vec();
    result.contract_funcsigs_external_call = external_call_in_func_signature.drain().collect();

    let (victim_callback_info, attack_reenter_info) = detector.get_reen_info();
    for (key, value) in victim_callback_info.iter() {
        result.reentrancy_path_info.insert(
            key.clone(),
            PathInfo {
                victim_call: value.clone(),
                attacker_reenter: attack_reenter_info.get(key).unwrap_or(&Vec::new()).to_vec(),
            },
        );
    }

    let sensitive_callsigs_set: HashSet<_> = result.sensitive_callsigs.iter().cloned().collect();
    let contract_funcsigs_external_call_set: HashSet<_> = result
        .contract_funcsigs_external_call
        .iter()
        .cloned()
        .collect();

    let overlap: Vec<_> = sensitive_callsigs_set
        .intersection(&contract_funcsigs_external_call_set)
        .cloned()
        .collect();

    if !overlap.is_empty() {
        result.overlap.has_overlap = true;
        for item in overlap {
            result.overlap.overlap_external_call.push(item);
        }
    }

    // level warning
    if result.semantic_features.op_creation.op_multicreate
        || result.semantic_features.op_creation.op_solecreate
        || result.semantic_features.op_selfdestruct
        || result.semantic_features.op_env
    {
        result.warning = "high".to_string();
    }
    // just has overlap, lift the warning
    if result.overlap.has_overlap {
        result.warning = "high".to_string();
    }

    if result.external_call.externalcall_inhook || result.external_call.externalcall_infallback {
        result.warning = "high".to_string();
    }

    if is_createbin {
        result.analysis_loc = "createbin".to_string();
    } else {
        result.analysis_loc = "runtimebin".to_string();
    }

    let duration = start.elapsed();
    result.time = format!(
        "{}.{:09} seconds",
        duration.as_secs(),
        duration.subsec_nanos()
    )
    .into();
    println!("{:?}", result);
    let mut res: HashMap<String, Result> = HashMap::new();
    res.insert(logic_address.to_string(), result);

    let serialized = serde_json::to_string_pretty(&res).unwrap();
    let mut file = File::create(format!("{}{}.json", JSON_PATH, logic_address)).unwrap();
    file.write(serialized.as_bytes()).unwrap();

    info!("analyze contract {} consumes {:?}", logic_address, duration);
}
