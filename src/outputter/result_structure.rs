use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Result {
    pub is_attack: bool,
    pub warning: String,
    pub attack_matrix: HashMap<String, bool>,
    pub analysis_loc: String,
    pub platform: String,
    pub block_number: u64,
    pub time: Option<String>,
    pub semantic_features: SemanticFeatures,
    pub external_call: ExternalCall,
    pub call_paths: Vec<String>,
    pub visited_contracts: Vec<String>,
    pub visited_contracts_num: usize,
    pub visited_funcs: Vec<String>,
    pub visited_funcs_num: usize,
    pub max_call_depth: u32,
    pub contract_funcsigs: Vec<String>,
    pub contract_funcsigs_external_call: Vec<String>,
    pub sensitive_callsigs: Vec<String>,
    pub overlap: Overlap,
    pub reentrancy_path_info: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct SemanticFeatures {
    pub op_creation: OpCreation,
    pub op_selfdestruct: bool,
    pub op_env: bool,
}

#[derive(Serialize, Deserialize)]
pub struct OpCreation {
    pub op_multicreate: bool,
    pub op_solecreate: bool,
}
#[derive(Serialize, Deserialize)]
pub struct ExternalCall {
    pub externalcall_inhook: bool,
    pub externalcall_infallback: bool,
    // pub hooks_focused: Vec<String>,
}
#[derive(Serialize, Deserialize)]
pub struct Overlap {
    pub has_overlap: bool,
    pub overlap_external_call: Vec<String>,
}
