use std::collections::HashSet;
use std::{collections::HashMap, error::Error, path::Path};

use crate::contract::contract::Contract;
use crate::contract::data_structure::{
    self, CallArgs, ExternalCall, FuncArgToSensitiveVar, TaintedCallArg,
};
use csv::{ReaderBuilder, StringRecord};
use log::error;
use serde::{Deserialize, Serialize};
const TEMP_PATH: &str = "./gigahorse-toolchain/.temp/";
const ANALYSIS: &str = "Leslie";

#[derive(Debug, Clone)]
pub struct ProgramPoint {
    pub caller_addr: String,
    pub call_site: String,
    pub caller_func_sign: String,
    pub target_contract_addr: String,
    pub target_func_sign: String,
    pub index: String,
    pub program_point_type: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ReachableSiteInfo {
    caller: String,
    caller_callback_func_sign: String,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ReenterInfo {
    reenter_target: String,
    reenter_func_sign: String,
}

#[allow(dead_code)]
pub struct FlowAnalysis<'a> {
    contracts: &'a HashMap<String, Contract>,
    main_contract_sign_list: Vec<String>,
    external_call_in_func_signature: HashSet<String>,
    pub visited_contracts: HashSet<String>,
    pub visited_funcs: HashSet<String>,
    intra_callsigns: Vec<String>,
    sensitive_callsigns: Vec<String>,
    attack_matrix: HashMap<String, bool>,
    victim_callback_info: HashMap<String, Vec<ReachableSiteInfo>>,
    attack_reenter_info: HashMap<String, Vec<ReenterInfo>>,
}

#[allow(dead_code)]
impl<'a> FlowAnalysis<'a> {
    pub fn new(
        contracts: &'a HashMap<String, Contract>,
        main_contract_sign_list: Vec<String>,
        external_call_in_func_signature: HashSet<String>,
        visited_contracts: HashSet<String>,
        visited_funcs: HashSet<String>,
    ) -> Self {
        FlowAnalysis {
            contracts: contracts,
            main_contract_sign_list: main_contract_sign_list,
            external_call_in_func_signature: external_call_in_func_signature,
            visited_contracts: visited_contracts,
            visited_funcs: visited_funcs,
            intra_callsigns: Vec::new(),
            sensitive_callsigns: Vec::new(),
            attack_matrix: HashMap::new(),
            victim_callback_info: HashMap::new(),
            attack_reenter_info: HashMap::new(),
        }
    }

    fn read_csv<T: From<StringRecord>>(
        &self,
        file_path: &str,
        data: &mut Vec<T>,
    ) -> Result<(), Box<dyn Error>> {
        if Path::new(&file_path).exists() {
            let mut rdr = ReaderBuilder::new()
                .delimiter(b'\t')
                .from_path(&file_path)?;
            for result in rdr.records() {
                let record = result?;
                data.push(T::from(record));
            }
        }
        Ok(())
    }

    fn intraprocedural_br_analysis(&mut self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut br_analysis_df = Vec::new();
                if let Err(err) = self
                    .read_csv::<data_structure::SensitiveOpOfBadRandomnessAfterExternalCall>(
                        &format!(
                            "{}{}/out/{}_SensitiveOpOfBadRandomnessAfterExternalCall.csv",
                            TEMP_PATH, temp_address, ANALYSIS
                        ),
                        &mut br_analysis_df,
                    )
                {
                    error!("Error reading CSV: {}", err);
                }
                for br_analysis in br_analysis_df {
                    if br_analysis.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    fn intraprocedural_dos_analysis(&mut self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut dos_analysis_df = Vec::new();
                if let Err(err) = self
                    .read_csv::<data_structure::SensitiveOpOfDoSAfterExternalCall>(
                        &format!(
                            "{}{}/out/{}_SensitiveOpOfDoSAfterExternalCall.csv",
                            TEMP_PATH, temp_address, ANALYSIS
                        ),
                        &mut dos_analysis_df,
                    )
                {
                    error!("Error reading CSV: {}", err);
                }
                for dos_analysis in dos_analysis_df {
                    if dos_analysis.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    // tainted op analysis
    pub fn tainted_env_call_arg(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::EnvVarFlowsToTaintedVar>(
                    &format!(
                        "{}{}/out/{}_EnvVarFlowsToTaintedVar.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for tainted_env_call_arg in df {
                    if tainted_env_call_arg.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    // other intra analysis
    pub fn op_multicreate_analysis(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let mut temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                if key.contains("__function_selector__") {
                    temp_func_sign = "__function_selector__";
                }
                let mut op_multicreate_analysis_df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::OpCreateInLoop>(
                    &format!(
                        "{}{}/out/{}_Op_CreateInLoop.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut op_multicreate_analysis_df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for op_multicreate_analysis in op_multicreate_analysis_df {
                    if op_multicreate_analysis.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    pub fn op_solecreate_analysis(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let mut temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                if key.contains("__function_selector__") {
                    temp_func_sign = "__function_selector__";
                }
                let mut op_solecreate_analysis_df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::OpSoleCreate>(
                    &format!("{}{}/out/{}_Op_SoleCreate.csv", TEMP_PATH, temp_address, ANALYSIS),
                    &mut op_solecreate_analysis_df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for op_solecreate_analysis in op_solecreate_analysis_df {
                    if op_solecreate_analysis.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    pub fn op_selfdestruct_analysis(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let mut temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                if key.contains("__function_selector__") {
                    temp_func_sign = "__function_selector__";
                }
                let mut op_selfdestruct_analysis_df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::OpSelfdestruct>(
                    &format!(
                        "{}{}/out/{}_Op_Selfdestruct.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut op_selfdestruct_analysis_df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for op_selfdestruct_analysis in op_selfdestruct_analysis_df {
                    if op_selfdestruct_analysis.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    // external call related
    pub fn externalcall_inhook(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::ExternalCallInHook>(
                    &format!(
                        "{}{}/out/{}_ExternalCallInHook.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for externalcall_inhook in df {
                    if externalcall_inhook.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    pub fn externalcall_infallback(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::ExternalCallInFallback>(
                    &format!(
                        "{}{}/out/{}_ExternalCallInFallback.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for externalcall_infallback in df {
                    if externalcall_infallback.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    // reentrancy related
    pub fn double_call_to_same_contract(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::DoubleCallToSameContract>(
                    &format!(
                        "{}{}/out/{}_DoubleCallToSameContract.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for double_call_to_same_contract in df {
                    if double_call_to_same_contract.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    pub fn double_call_to_same_contract_by_storage(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut df = Vec::new();
                if let Err(err) = self
                    .read_csv::<data_structure::DoubleCallToSameContractByStorage>(
                        &format!(
                            "{}{}/out/{}_DoubleCallToSameContractByStorage.csv",
                            TEMP_PATH, temp_address, ANALYSIS
                        ),
                        &mut df,
                    )
                {
                    error!("Error reading CSV: {}", err);
                }
                for double_call_to_same_contract_by_storage in df {
                    if double_call_to_same_contract_by_storage.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    pub fn preset_call_in_standard_erc20_transfer(&self) -> bool {
        for key in self.contracts.keys() {
            if self.contracts[key].level == 0 {
                let temp_address = key.split("_").collect::<Vec<&str>>()[2];
                let temp_func_sign = key.split("_").collect::<Vec<&str>>()[3];
                let mut df = Vec::new();
                if let Err(err) = self.read_csv::<data_structure::CallInStandardTransfer>(
                    &format!(
                        "{}{}/out/{}_CallInStandardTransfer.csv",
                        TEMP_PATH, temp_address, ANALYSIS
                    ),
                    &mut df,
                ) {
                    error!("Error reading CSV: {}", err);
                }
                for call_in_standard_erc20_transfer in df {
                    if call_in_standard_erc20_transfer.func_sign == temp_func_sign {
                        return true;
                    }
                }
                return false;
            }
        }
        return false;
    }

    fn spread_call_ret_func_ret(
        &self,
        contract_address: &str,
        call_stmt: &str,
        func_sign: &str,
        ret_index: &str,
    ) -> Vec<String> {
        let mut func_ret_index = Vec::new();
        let mut call_ret_func_ret_df = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::CallRetToFuncRet>(
            &format!(
                "{}{}/out/{}_Spread_CallRetToFuncRet.csv",
                TEMP_PATH, contract_address, ANALYSIS
            ),
            &mut call_ret_func_ret_df,
        ) {
            error!("Error reading CSV: {}", err);
        }
        for call_ret_func_ret in call_ret_func_ret_df {
            if call_ret_func_ret.func_sign == func_sign
                && call_ret_func_ret.call_stmt == call_stmt
                && call_ret_func_ret.call_ret_index == ret_index
            {
                func_ret_index.push(call_ret_func_ret.call_ret_index);
            }
        }
        func_ret_index
    }

    #[allow(unused_variables)]
    fn spread_call_ret_call_arg(
        &self,
        contract_address: &str,
        call_stmt: &str,
        ret_index: &str,
    ) -> Vec<CallArgs> {
        let mut call_args = Vec::new();
        let mut call_ret_call_arg_df = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::CallRetToCallArg>(
            &format!(
                "{}{}/out/{}_Spread_CallRetToCallArg.csv",
                TEMP_PATH, contract_address, ANALYSIS
            ),
            &mut call_ret_call_arg_df,
        ) {
            error!("Error reading CSV: {}", err);
        }
        for call_ret_call_arg in call_ret_call_arg_df {
            if call_ret_call_arg.call_stmt1 == call_stmt
                && call_ret_call_arg.call_ret_index == ret_index
            {
                call_args.push(CallArgs {
                    call_stmt: call_ret_call_arg.call_stmt2,
                    call_arg_index: call_ret_call_arg.call_arg_index,
                });
            }
        }
        call_args
    }

    #[allow(unused_variables)]
    fn spread_func_arg_call_arg(
        &self,
        contract_address: &str,
        func_sign: &str,
        func_arg_index: &str,
    ) -> Vec<CallArgs> {
        let mut call_args = Vec::new();
        let mut func_arg_call_arg_df = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::FuncArgToCallArg>(
            &format!(
                "{}{}/out/{}_Spread_FuncArgToCallArg.csv",
                TEMP_PATH, contract_address, ANALYSIS
            ),
            &mut func_arg_call_arg_df,
        ) {
            error!("Error reading CSV: {}", err);
        }
        for func_arg_call_arg in func_arg_call_arg_df {
            if func_arg_call_arg.func_sign == func_sign
                && func_arg_call_arg.func_arg_index == func_arg_index
            {
                call_args.push(CallArgs {
                    call_stmt: func_arg_call_arg.call_stmt,
                    call_arg_index: func_arg_call_arg.call_arg_index,
                });
            }
        }
        call_args
    }

    #[allow(unused_variables)]
    fn spread_func_arg_callee(
        &self,
        contract_address: &str,
        func_sign: &str,
        func_arg_index: &str,
    ) -> Vec<CallArgs> {
        let mut call_args = Vec::new();
        let mut func_arg_callee_df = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::FuncArgToCallee>(
            &format!(
                "{}{}/out/{}_Spread_FuncArgToCalleeVar.csv",
                TEMP_PATH, contract_address, ANALYSIS
            ),
            &mut func_arg_callee_df,
        ) {
            error!("Error reading CSV: {}", err);
        }
        for func_arg_callee in func_arg_callee_df {
            if func_arg_callee.func_sign == func_sign
                && func_arg_callee.func_arg_index == func_arg_index
            {
                call_args.push(CallArgs {
                    call_stmt: func_arg_callee.call_stmt,
                    call_arg_index: func_arg_callee.func_arg_index,
                });
            }
        }
        call_args
    }

    #[allow(unused_variables)]
    fn spread_func_arg_func_ret(
        &self,
        contract_address: &str,
        func_sign: &str,
        func_arg_index: &str,
    ) -> Vec<String> {
        let mut func_ret_index = Vec::new();
        let mut func_arg_func_ret_df = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::FuncArgToFuncRet>(
            &format!(
                "{}{}/out/{}_Spread_CallRetToFuncRet.csv",
                TEMP_PATH, contract_address, ANALYSIS
            ),
            &mut func_arg_func_ret_df,
        ) {
            error!("Error reading CSV: {}", err);
        }
        for func_arg_func_ret in func_arg_func_ret_df {
            if func_arg_func_ret.func_sign == func_sign
                && func_arg_func_ret.func_arg_index == func_arg_index
            {
                func_ret_index.push(func_arg_func_ret.func_ret_index);
            }
        }
        func_ret_index
    }

    #[allow(unused_variables)]
    fn find_executed_program_point(
        &self,
        caller: &str,
        call_site: &str,
        contract_addr: &str,
        func_sign: &str,
    ) -> String {
        let mut addr = String::new();
        let mut level: i32 = -1;
        for key in self.contracts.keys() {
            let temp: Vec<&str> = key.split('_').collect();
            if temp.len() >= 4 && temp[0] == caller && temp[1] == call_site && temp[3] == func_sign
            {
                match self.contracts.get(key) {
                    Some(contract) => {
                        if addr.is_empty() || contract.level > level {
                            addr = temp[2].to_string();
                            level = contract.level;
                        }
                    }
                    None => continue,
                }
            }
        }
        addr
    }

    fn get_new_program_point(
        &self,
        caller: &str,
        call_site: &str,
        target_contract_addr: &str,
        target_func_sign: &str,
        index: &str,
        caller_func_sign: &str,
        program_point_type: &str,
    ) -> ProgramPoint {
        let addr = self.find_executed_program_point(
            caller,
            call_site,
            target_contract_addr,
            target_func_sign,
        );
        ProgramPoint {
            caller_addr: caller.to_string(),
            call_site: call_site.to_string(),
            caller_func_sign: caller_func_sign.to_string(),
            target_contract_addr: addr,
            target_func_sign: target_func_sign.to_string(),
            index: index.to_string(),
            program_point_type: program_point_type.to_string(),
        }
    }

    fn get_external_call_info(
        &self,
        call_site: &str,
        external_calls: &[ExternalCall],
    ) -> Option<(String, String, String)> {
        for external_call in external_calls {
            if external_call.call_site == call_site {
                return Some((
                    external_call.caller_addr.clone(),
                    external_call.target_logic_addr.clone(),
                    external_call.target_func_sign.clone(),
                ));
            }
        }
        None
    }

    #[allow(unused_variables)]
    fn get_call_args_flow_from_sources(
        &self,
        contract_addr: &str,
        func_sign: &str,
    ) -> Vec<TaintedCallArg> {
        let mut call_args = Vec::new();
        let mut tainted_call_arg_df = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::TaintedCallArg>(
            &format!(
                "{}{}/out/{}_TaintedCallArg.csv",
                TEMP_PATH, contract_addr, ANALYSIS
            ),
            &mut tainted_call_arg_df,
        ) {
            error!("Error reading CSV: {}", err);
        }

        for result in tainted_call_arg_df {
            if func_sign == result.func_sign {
                let call_arg = TaintedCallArg {
                    call_stmt: result.call_stmt.clone(),
                    func_sign: result.func_sign.clone(),
                    call_arg_index: result.call_arg_index.clone(),
                };
                call_args.push(call_arg);
            }
        }
        // info!("call args of {}: {:?}", contract_addr, call_args);
        call_args
    }

    fn get_program_points_near_source(&self) -> Vec<ProgramPoint> {
        let mut pps_near_source = Vec::new();

        for (key, contract) in self.contracts.iter() {
            // info!("contract key: {}", key);
            let parts: Vec<&str> = key.split('_').collect();
            let (_temp_caller, _temp_callsite, temp_address, _temp_func_sign) =
                (parts[0], parts[1], parts[2], parts[3]);

            if contract.level == 0 {
                // info!("original contract");
                let temp_caller_func_sign = &contract.func_sign;
                let temp_call_args =
                    self.get_call_args_flow_from_sources(temp_address, temp_caller_func_sign);

                if !temp_call_args.is_empty() {
                    for temp_call_arg in temp_call_args {
                        if let Some((
                            temp_external_call_caller,
                            temp_external_call_logic_addr,
                            temp_external_call_func_sign,
                        )) = self.get_external_call_info(
                            &temp_call_arg.call_stmt,
                            &contract.external_calls,
                        ) {
                            pps_near_source.push(self.get_new_program_point(
                                &temp_external_call_caller,
                                &temp_call_arg.call_stmt,
                                &temp_external_call_logic_addr,
                                &temp_external_call_func_sign,
                                &temp_call_arg.call_arg_index,
                                temp_caller_func_sign,
                                "call_arg",
                            ));
                        }
                    }
                }
            }
        }
        // info!("pps near source: {:?}", pps_near_source);
        pps_near_source
    }

    #[allow(unused_variables)]
    fn get_func_args_flow_to_sink(
        &self,
        contract_addr: &str,
        func_sign: &str,
    ) -> (Vec<FuncArgToSensitiveVar>, Vec<String>) {
        let mut func_args = Vec::new();
        let mut sensitive_call_signs = Vec::new();

        let mut func_arg_to_sensitive_var_df: Vec<FuncArgToSensitiveVar> = Vec::new();
        if let Err(err) = self.read_csv::<data_structure::FuncArgToSensitiveVar>(
            &format!(
                "{}{}/out/{}_FuncArgToSensitiveVar.csv",
                TEMP_PATH, contract_addr, ANALYSIS
            ),
            &mut func_arg_to_sensitive_var_df,
        ) {
            error!("Error reading CSV: {}", err);
        }

        for result in func_arg_to_sensitive_var_df {
            if result.func_sign == func_sign {
                let func_arg = FuncArgToSensitiveVar {
                    func_sign: result.func_sign.clone(),
                    call_stmt: result.call_stmt.clone(),
                    func_arg: result.func_arg.clone(),
                    func_arg_index: result.func_arg_index.clone(),
                    sensitive_var: result.sensitive_var.clone(),
                    call_func_sign: result.call_func_sign.clone(),
                };
                func_args.push(func_arg);
                sensitive_call_signs.push(result.call_func_sign.clone().replace(
                    "00000000000000000000000000000000000000000000000000000000",
                    "",
                ));
            }
        }
        // info!("call args of {}: {:?}", contract_addr, call_args);
        (func_args, sensitive_call_signs)
    }

    fn get_program_points_near_sink(&self) -> (Vec<ProgramPoint>, Vec<String>) {
        let mut program_points_near_sink = Vec::new();
        let mut sensitive_callsigs = Vec::new();

        for (key, _value) in self.contracts.iter() {
            let parts: Vec<&str> = key.split('_').collect();
            let _temp_caller = parts[0];
            let _temp_callsite = parts[1];
            let temp_address = parts[2];
            let temp_func_sign = parts[3];
            let _temp_caller_func_sign = parts[4];
            // log information if needed

            let (temp_call_args, signs_func_arg) =
                self.get_func_args_flow_to_sink(temp_address, temp_func_sign);

            if !temp_call_args.is_empty() {
                for temp_call_arg in temp_call_args {
                    let (
                        temp_external_call_caller,
                        temp_external_call_logic_addr,
                        temp_external_call_func_sign,
                    ) = self
                        .get_external_call_info(
                            &temp_call_arg.call_stmt,
                            &self.contracts[key].external_calls,
                        )
                        .unwrap();

                    program_points_near_sink.push(self.get_new_program_point(
                        &temp_external_call_caller,
                        &temp_call_arg.call_stmt,
                        &temp_external_call_logic_addr,
                        &temp_external_call_func_sign,
                        &temp_call_arg.func_arg_index,
                        &self.contracts[key].func_sign,
                        "call_arg",
                    ));
                }
                // log information if needed
            }

            for signs in signs_func_arg {
                sensitive_callsigs.push(signs);
            }
        }

        (program_points_near_sink, sensitive_callsigs)
    }

    fn find_parent(
        &self,
        logic_addr: &str,
        func_sign: &str,
        caller: &str,
        call_site: &str,
    ) -> Option<&Contract> {
        for (_, contract) in self.contracts.iter() {
            for external_call in &contract.external_calls {
                if external_call.target_logic_addr == logic_addr
                    && external_call.target_func_sign == func_sign
                    && external_call.caller_addr == caller
                    && external_call.call_site == call_site
                {
                    return Some(contract);
                }
            }
        }
        None
    }

    fn find_contract(
        &self,
        caller: &str,
        callsite: &str,
        contract_addr: &str,
        func_sign: &str,
        caller_func_sign: &str,
    ) -> Option<&Contract> {
        let key = format!(
            "{}_{}_{}_{}_{}",
            caller, callsite, contract_addr, func_sign, caller_func_sign
        );
        self.contracts.get(&key)
    }

    fn is_same(&self, first: &ProgramPoint, second: &ProgramPoint) -> bool {
        first.caller_addr == second.caller_addr
            && first.call_site == second.call_site
            && first.target_func_sign == second.target_func_sign
            && first.index == second.index
            && first.program_point_type == second.program_point_type
            && first.caller_func_sign == second.caller_func_sign
    }

    fn is_reachable(&self, first: &ProgramPoint, second: &ProgramPoint) -> bool {
        if self.is_same(first, second) {
            return true;
        }
        let mut pending = vec![first.clone()];
        while let Some(temp) = pending.pop() {
            for program_point in self.transfer(&temp) {
                if self.is_same(&program_point, second) {
                    return true;
                }
                pending.push(program_point);
            }
        }
        false // Return false when the loop has zero elements to iterate on
    }

    fn transfer(&self, program_point: &ProgramPoint) -> Vec<ProgramPoint> {
        let mut next_program_points = Vec::new();

        // Assuming find_parent returns an Option<&Contract>
        let parent_contract = self.find_parent(
            &program_point.target_contract_addr,
            &program_point.target_func_sign,
            &program_point.caller_addr,
            &program_point.call_site,
        );
        let child_contract = match self.find_contract(
            &program_point.caller_addr,
            &program_point.call_site,
            &program_point.target_contract_addr,
            &program_point.target_func_sign,
            &program_point.caller_func_sign,
        ) {
            Some(contract) => contract,
            None => return next_program_points,
        };

        match program_point.program_point_type.as_str() {
            "func_ret" => {
                // Implement logic for "func_ret"
                if let Some(parent) = parent_contract {
                    let indexes = self.spread_call_ret_func_ret(
                        &program_point.caller_addr,
                        &program_point.call_site,
                        &parent.func_sign,
                        &program_point.index,
                    );
                    for index in indexes.iter() {
                        next_program_points.push(self.get_new_program_point(
                            &parent.caller,
                            &parent.call_site,
                            &parent.logic_addr,
                            &parent.func_sign,
                            index,
                            &program_point.caller_func_sign,
                            "func_ret",
                        ))
                    }
                }
                let call_args = self.spread_call_ret_call_arg(
                    &program_point.target_contract_addr,
                    &program_point.call_site,
                    &program_point.index,
                );
                for call_arg in call_args.iter() {
                    let (temp_caller, temp_logic_addr, temp_func_sign) = self
                        .get_external_call_info(&call_arg.call_stmt, &child_contract.external_calls)
                        .unwrap();
                    next_program_points.push(self.get_new_program_point(
                        &temp_caller,
                        &call_arg.call_stmt,
                        &temp_logic_addr,
                        &temp_func_sign, // temp func sign is the called function that lies in the attacker contract
                        &call_arg.call_arg_index,
                        &program_point.target_func_sign, // pp[func_sign] is the function that calls back to attacker contract
                        "call_arg",
                    ))
                }
            }
            "call_arg" => {
                let mut call_args: Vec<CallArgs> = Vec::new();
                call_args.extend(self.spread_func_arg_call_arg(
                    &program_point.target_contract_addr,
                    &program_point.target_func_sign,
                    &program_point.index,
                ));
                call_args.extend(self.spread_func_arg_callee(
                    &program_point.target_contract_addr,
                    &program_point.target_func_sign,
                    &program_point.index,
                ));

                for call_arg in call_args.iter() {
                    let temp_result = self.get_external_call_info(
                        &call_arg.call_stmt,
                        &child_contract.external_calls,
                    );

                    if temp_result != None {
                        let (_temp_caller, temp_logic_addr, temp_func_sign) = temp_result.unwrap();
                        next_program_points.push(self.get_new_program_point(
                            &program_point.target_contract_addr,
                            &call_arg.call_stmt,
                            &temp_logic_addr,
                            &temp_func_sign,
                            &call_arg.call_arg_index,
                            &program_point.target_func_sign,
                            "call_arg",
                        ))
                    }
                }
                // the return index of the function call
                let indexes = self.spread_func_arg_func_ret(
                    &program_point.target_contract_addr,
                    &program_point.target_func_sign,
                    &program_point.index,
                );
                for index in indexes.iter() {
                    next_program_points.push(self.get_new_program_point(
                        &program_point.caller_addr,
                        &program_point.call_site,
                        &program_point.target_contract_addr,
                        &program_point.target_func_sign,
                        index,
                        &program_point.caller_func_sign,
                        "func_ret",
                    ));
                }
            }
            _ => (),
        }

        next_program_points.clone()
    }

    pub fn detect(&mut self) -> (bool, HashMap<String, bool>) {
        let mut cross_contract = false;
        self.attack_matrix.insert("br".to_string(), false);
        self.attack_matrix.insert("dos".to_string(), false);
        self.attack_matrix.insert("reentrancy".to_string(), false);
        for (_key, contract) in self.contracts.iter() {
            if contract.level != 0 {
                cross_contract = true;
                break;
            }
        }

        if !cross_contract {
            return (false, self.attack_matrix.clone());
        }

        let mut result = false;

        // Assuming intraprocedural_br_analysis and intraprocedural_dos_analysis are methods returning bool
        if self.intraprocedural_br_analysis() {
            self.attack_matrix.insert("br".to_string(), true);
        }

        if self.intraprocedural_dos_analysis() {
            self.attack_matrix.insert("dos".to_string(), true);
        }
        let source = self.get_program_points_near_source();
        // info!("pp near source: {:?}", source);

        let (sink, sensitive_call_signs) = self.get_program_points_near_sink();

        self.sensitive_callsigns = sensitive_call_signs;

        let mut reachable: bool = false;
        let mut reachable_site: HashMap<String, ReachableSiteInfo> = HashMap::new();

        for program_point_source in &source {
            for program_point_sink in &sink {
                if self.is_same(program_point_source, program_point_sink)
                    || self.is_reachable(program_point_source, program_point_sink)
                {
                    reachable = true;
                    result = true;
                    let caller = program_point_sink.caller_addr.clone();
                    let caller_func_sign = program_point_sink.caller_func_sign.clone();
                    reachable_site.insert(
                        program_point_sink.target_func_sign.clone(),
                        ReachableSiteInfo {
                            caller: caller,
                            caller_callback_func_sign: caller_func_sign,
                        },
                    );
                }
            }
        }

        let mut victim_callback_info: HashMap<String, Vec<ReachableSiteInfo>> = HashMap::new();
        let mut attacker_reenter_info: HashMap<String, Vec<ReenterInfo>> = HashMap::new();
        if reachable {
            let sensitive_call_signs_set: HashSet<_> =
                self.sensitive_callsigns.iter().cloned().collect();
            let overlap: HashSet<_> = sensitive_call_signs_set
                .intersection(
                    &self
                        .external_call_in_func_signature
                        .iter()
                        .cloned()
                        .collect(),
                )
                .cloned()
                .collect();
            if !overlap.is_empty() {
                for i in overlap {
                    // initialize
                    victim_callback_info
                        .entry(i.clone())
                        .or_insert_with(Vec::new);
                    attacker_reenter_info
                        .entry(i.clone())
                        .or_insert_with(Vec::new);

                    if let Some(site) = reachable_site.get(&i) {
                        let entry = victim_callback_info.entry(i.clone()).or_default();
                        if !entry.contains(site) {
                            entry.push(site.clone());
                        }
                    }
                    for (_, contract) in self.contracts {
                        if contract.func_sign.eq(&i) && contract.level == 0 {
                            for ec in &contract.external_calls {
                                let res = ReenterInfo {
                                    reenter_target: ec.target_logic_addr.clone(),
                                    reenter_func_sign: ec.target_func_sign.clone(),
                                };

                                let entry = attacker_reenter_info.entry(i.clone()).or_default();
                                if !entry.contains(&res)
                                    && self.visited_contracts.contains(&res.reenter_target)
                                    && self.visited_funcs.contains(&res.reenter_func_sign)
                                {
                                    entry.push(res);
                                }
                            }
                            result = true;
                            self.attack_matrix.insert("reentrancy".to_string(), true);
                        }
                    }
                }
            }
        }

        if self.double_call_to_same_contract()
            || self.double_call_to_same_contract_by_storage()
            || self.preset_call_in_standard_erc20_transfer()
        {
            self.attack_matrix.insert("reentrancy".to_string(), true);
            result = true;
        }

        self.victim_callback_info = victim_callback_info;
        self.attack_reenter_info = attacker_reenter_info;
        (result, self.attack_matrix.clone())
    }

    pub fn get_reen_info(
        &self,
    ) -> (
        &HashMap<String, Vec<ReachableSiteInfo>>,
        &HashMap<String, Vec<ReenterInfo>>,
    ) {
        (&self.victim_callback_info, &self.attack_reenter_info)
    }

    pub fn get_sig_info(&self) -> &Vec<String> {
        &self.sensitive_callsigns
    }

    pub fn get_attack_matrix(&self) -> &HashMap<String, bool> {
        &self.attack_matrix
    }
}
