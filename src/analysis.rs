//! Analysis orchestration module
//! 
//! This module provides high-level coordination of the analysis pipeline.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use log::info;

use crate::config::{defaults, AnalysisSource, Config};
use crate::contract::contract::Contract;
use crate::error::{LydiaError, LydiaResult};
use crate::flow::flow_analysis::FlowAnalysis;
use crate::graph::call_graph::CallGraph;
use crate::outputter::result_structure::{
    ExternalCall, OpCreation, Overlap, PathInfo, Result as AnalysisResult, SemanticFeatures,
};

/// Analysis engine that orchestrates the entire analysis pipeline
pub struct AnalysisEngine {
    config: Config,
}

/// Holds the results of contract analysis
pub struct ContractAnalysisResult {
    pub func_sign_list: Vec<String>,
    pub external_call_in_func_signature: HashSet<String>,
    pub is_createbin: bool,
}

/// Holds the results of call graph analysis
pub struct CallGraphAnalysisResult {
    pub call_paths: Vec<String>,
    pub visited_contracts: HashSet<String>,
    pub visited_funcs: HashSet<String>,
    pub max_call_depth: i32,
    pub contracts: HashMap<String, Contract>,
}

impl AnalysisEngine {
    /// Create a new analysis engine with the given configuration
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    /// Run the complete analysis pipeline
    pub async fn analyze(&self) -> LydiaResult<AnalysisResult> {
        let start_time = Instant::now();
        
        info!("Starting analysis for contract: {}", self.config.logic_address);
        info!("Platform: {}, Block: {}", self.config.platform, self.config.block_number);

        // Step 1: Analyze the input contract
        let contract_result = self.analyze_contract().await?;
        
        // Step 2: Build call graphs
        let call_graph_result = self.build_call_graphs(&contract_result).await?;
        
        // Step 3: Perform flow analysis
        let mut analysis_result = self.perform_flow_analysis(&contract_result, &call_graph_result).await?;
        
        // Step 4: Finalize results
        self.finalize_results(&mut analysis_result, call_graph_result, start_time);

        Ok(analysis_result)
    }

    /// Analyze the input contract to extract basic information
    async fn analyze_contract(&self) -> LydiaResult<ContractAnalysisResult> {
        let mut contract = Contract::new(
            self.config.platform.clone(),
            self.config.logic_address.clone(),
            self.config.storage_address.clone(),
            String::new(), // Test all functions
            self.config.block_number,
            defaults::CALLER.to_string(),
            String::new(),
            defaults::LEVEL,
        );

        contract.analyze().await
            .map_err(|e| LydiaError::ContractAnalysis(e.to_string()))?;

        let func_sign_list = contract.get_func_sign_list();
        let external_call_in_func_signature = contract.get_external_call_in_func_signature();
        let is_createbin = contract.is_createbin();

        info!("Function signatures found: {:?}", func_sign_list);
        info!("External calls in functions: {:?}", external_call_in_func_signature);

        Ok(ContractAnalysisResult {
            func_sign_list: func_sign_list.clone(),
            external_call_in_func_signature: external_call_in_func_signature.clone(),
            is_createbin: *is_createbin,
        })
    }

    /// Build call graphs for the contract
    async fn build_call_graphs(&self, contract_result: &ContractAnalysisResult) -> LydiaResult<CallGraphAnalysisResult> {
        let mut contracts = HashMap::new();
        let mut visited_contracts = HashSet::new();
        let mut visited_funcs = HashSet::new();
        let mut call_paths = Vec::new();
        let mut max_call_depth = 0;

        if contract_result.is_createbin {
            let result = self.build_createbin_call_graph(&mut contracts).await?;
            visited_contracts.extend(result.visited_contracts);
            visited_funcs.extend(result.visited_funcs);
            call_paths.push(result.call_path);
            max_call_depth = result.max_depth;
        } else {
            for func_sign in &contract_result.external_call_in_func_signature {
                let result = self.build_function_call_graph(func_sign, &mut contracts).await?;
                visited_contracts.extend(result.visited_contracts);
                visited_funcs.extend(result.visited_funcs);
                call_paths.push(result.call_path);
                max_call_depth = max_call_depth.max(result.max_depth);
            }
        }

        info!("Call graph analysis completed. Contracts analyzed: {}", contracts.len());

        Ok(CallGraphAnalysisResult {
            call_paths,
            visited_contracts,
            visited_funcs,
            max_call_depth,
            contracts,
        })
    }

    /// Build call graph for createbin contracts
    async fn build_createbin_call_graph(&self, contracts: &mut HashMap<String, Contract>) -> LydiaResult<SingleCallGraphResult> {
        let source = AnalysisSource::for_createbin(&self.config);
        self.construct_call_graph(source, contracts).await
    }

    /// Build call graph for a specific function
    async fn build_function_call_graph(&self, func_sign: &str, contracts: &mut HashMap<String, Contract>) -> LydiaResult<SingleCallGraphResult> {
        info!("Building call flow for function: {}", func_sign);
        let source = AnalysisSource::from_config(&self.config, func_sign.to_string());
        self.construct_call_graph(source, contracts).await
    }

    /// Construct a call graph from the given source
    async fn construct_call_graph(&self, source: AnalysisSource, contracts: &mut HashMap<String, Contract>) -> LydiaResult<SingleCallGraphResult> {
        let mut call_graph = CallGraph::new(self.config.platform.clone(), contracts);
        
        call_graph.construct_cross_contract_call_graph(source).await
            .map_err(|e| LydiaError::CallGraphConstruction(e.to_string()))?;

        let call_path = call_graph.get_output().to_string();
        println!("{}", call_path);

        Ok(SingleCallGraphResult {
            call_path,
            visited_contracts: call_graph.get_visited_contracts().clone(),
            visited_funcs: call_graph.get_visited_funcs().clone(),
            max_depth: call_graph.max_level,
        })
    }

    /// Perform flow analysis to detect malicious patterns
    async fn perform_flow_analysis(&self, contract_result: &ContractAnalysisResult, call_graph_result: &CallGraphAnalysisResult) -> LydiaResult<AnalysisResult> {
        let mut detector = FlowAnalysis::new(
            &call_graph_result.contracts,
            contract_result.func_sign_list.clone(),
            contract_result.external_call_in_func_signature.clone(),
            call_graph_result.visited_contracts.clone(),
            call_graph_result.visited_funcs.clone(),
        );

        let (is_attack, attack_matrix) = detector.detect();

        let mut result = AnalysisResult {
            is_attack,
            warning: String::from(defaults::WARNING_MEDIUM),
            attack_matrix,
            analysis_loc: if contract_result.is_createbin { 
                defaults::CREATEBIN_ANALYSIS_LOC 
            } else { 
                defaults::RUNTIMEBIN_ANALYSIS_LOC 
            }.to_string(),
            platform: self.config.platform.clone(),
            block_number: self.config.block_number,
            time: None,
            semantic_features: SemanticFeatures {
                op_creation: OpCreation {
                    op_multicreate: detector.op_multicreate_analysis(),
                    op_solecreate: detector.op_solecreate_analysis(),
                },
                op_selfdestruct: detector.op_selfdestruct_analysis(),
                op_env: detector.tainted_env_call_arg(),
            },
            external_call: ExternalCall {
                externalcall_inhook: detector.externalcall_inhook(),
                externalcall_infallback: detector.externalcall_infallback(),
            },
            call_paths: call_graph_result.call_paths.clone(),
            visited_contracts: call_graph_result.visited_contracts.iter().cloned().collect(),
            visited_contracts_num: call_graph_result.visited_contracts.len(),
            visited_funcs: call_graph_result.visited_funcs.iter().cloned().collect(),
            visited_funcs_num: call_graph_result.visited_funcs.len(),
            max_call_depth: call_graph_result.max_call_depth as u32,
            contract_funcsigs: contract_result.func_sign_list.clone(),
            contract_funcsigs_external_call: contract_result.external_call_in_func_signature.iter().cloned().collect(),
            sensitive_callsigs: detector.get_sig_info().to_vec(),
            overlap: Overlap {
                has_overlap: false,
                overlap_external_call: Vec::new(),
            },
            reentrancy_path_info: HashMap::new(),
        };

        // Analyze reentrancy paths
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

        // Check for overlaps between sensitive calls and external calls
        let sensitive_set: HashSet<_> = result.sensitive_callsigs.iter().cloned().collect();
        let external_set: HashSet<_> = result.contract_funcsigs_external_call.iter().cloned().collect();
        let overlap: Vec<_> = sensitive_set.intersection(&external_set).cloned().collect();

        if !overlap.is_empty() {
            result.overlap.has_overlap = true;
            result.overlap.overlap_external_call = overlap;
        }

        // Determine warning level
        self.calculate_warning_level(&mut result);

        Ok(result)
    }

    /// Calculate the appropriate warning level based on analysis results
    fn calculate_warning_level(&self, result: &mut AnalysisResult) {
        if result.semantic_features.op_creation.op_multicreate
            || result.semantic_features.op_creation.op_solecreate
            || result.semantic_features.op_selfdestruct
            || result.semantic_features.op_env
            || result.overlap.has_overlap
            || result.external_call.externalcall_inhook
            || result.external_call.externalcall_infallback
        {
            result.warning = defaults::WARNING_HIGH.to_string();
        }
    }

    /// Finalize the analysis results with timing and output
    fn finalize_results(&self, result: &mut AnalysisResult, _call_graph_result: CallGraphAnalysisResult, start_time: Instant) {
        let duration = start_time.elapsed();
        result.time = Some(format!("{}.{:09} seconds", duration.as_secs(), duration.subsec_nanos()));
        
        info!("Analysis completed for contract {} in {:?}", self.config.logic_address, duration);
    }
}

/// Result of a single call graph construction
struct SingleCallGraphResult {
    call_path: String,
    visited_contracts: HashSet<String>,
    visited_funcs: HashSet<String>,
    max_depth: i32,
}