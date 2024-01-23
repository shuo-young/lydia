use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::{collections::HashMap, error::Error, path::Path};

use csv::{ReaderBuilder, StringRecord};

use crate::contract::contract::Contract;
use crate::contract::data_structure::{self, ExternalCall, TaintedCallArg};
use log::info;
const OUTPUT_PATH: &str = "./gigahorse-toolchain/";
const TEMP_PATH: &str = "./gigahorse-toolchain/.temp/";

#[derive(Debug)]
struct ProgramPoint {
    caller_addr: String,
    call_site: String,
    caller_func_sign: String,
    target_contract_addr: String,
    target_func_sign: String,
    index: i32,
    program_point_type: String,
}

pub struct FlowAnalysis<'a> {
    contracts: &'a HashMap<String, Contract>,
    main_contract_sign_list: Vec<String>,
    external_call_in_func_sigature: HashSet<String>,
    visited_contracts: Vec<String>,
    visited_funcs: Vec<String>,
    intra_callsigs: Vec<String>,
    sensitive_callsigs: Vec<String>,
    attack_matrix: HashMap<String, bool>,
    victim_callback_info: HashMap<String, Vec<(String, String)>>,
    attack_reenter_info: HashMap<String, Vec<(String, String)>>,
}

impl<'a> FlowAnalysis<'a> {
    pub fn new(
        contracts: &'a HashMap<String, Contract>,
        main_contract_sign_list: Vec<String>,
        external_call_in_func_sigature: HashSet<String>,
        visited_contracts: Vec<String>,
        visited_funcs: Vec<String>,
    ) -> Self {
        FlowAnalysis {
            contracts: contracts,
            main_contract_sign_list: main_contract_sign_list,
            external_call_in_func_sigature: external_call_in_func_sigature,
            visited_contracts: visited_contracts,
            visited_funcs: visited_funcs,
            intra_callsigs: Vec::new(),
            sensitive_callsigs: Vec::new(),
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
                self.read_csv::<data_structure::SensitiveOpOfBadRandomnessAfterExternalCall>(
                    &format!(
                        "{}{}/out/Leslie_SensitiveOpOfBadRandomnessAfterExternalCall.csv",
                        TEMP_PATH, temp_address
                    ),
                    &mut br_analysis_df,
                );
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
                self.read_csv::<data_structure::SensitiveOpOfDoSAfterExternalCall>(
                    &format!(
                        "{}{}/out/Leslie_SensitiveOpOfDoSAfterExternalCall.csv",
                        TEMP_PATH, temp_address
                    ),
                    &mut dos_analysis_df,
                );
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

    fn find_executed_pp(
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
        index: i32,
        caller_func_sign: &str,
        program_point_type: &str,
    ) -> ProgramPoint {
        let addr = self.find_executed_pp(caller, call_site, target_contract_addr, target_func_sign);
        ProgramPoint {
            caller_addr: caller.to_string(),
            call_site: call_site.to_string(),
            caller_func_sign: caller_func_sign.to_string(),
            target_contract_addr: addr,
            target_func_sign: target_func_sign.to_string(),
            index: index,
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

    fn get_call_args_flow_from_sources(
        &self,
        contract_addr: &str,
        func_sign: &str,
    ) -> Vec<TaintedCallArg> {
        let mut call_args = Vec::new();
        let mut tainted_call_arg_df = Vec::new();
        self.read_csv::<data_structure::TaintedCallArg>(
            &format!(
                "{}{}/out/Leslie_TaintedCallArg.csv",
                TEMP_PATH, contract_addr
            ),
            &mut tainted_call_arg_df,
        );

        for result in tainted_call_arg_df {
            let call_arg = TaintedCallArg {
                call_stmt: result.call_stmt.clone(),
                func_sign: result.func_sign.clone(),
                call_arg_index: result.call_arg_index.clone(),
            };
            call_args.push(call_arg);
        }
        // info!("call args of {}: {:?}", contract_addr, call_args);
        call_args
    }

    fn get_pps_near_source(&self) -> Vec<ProgramPoint> {
        let mut pps_near_source = Vec::new();

        for (key, contract) in self.contracts.iter() {
            // info!("contract key: {}", key);
            let parts: Vec<&str> = key.split('_').collect();
            let (temp_caller, temp_callsite, temp_address, temp_func_sign) =
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
                                temp_call_arg.call_arg_index.parse::<i32>().unwrap(),
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

    pub fn detect(&mut self) -> (bool, HashMap<String, bool>) {
        let mut cross_contract = false;
        for (key, contract) in self.contracts.iter() {
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
        } else {
            self.attack_matrix.insert("br".to_string(), false);
        }

        if self.intraprocedural_dos_analysis() {
            self.attack_matrix.insert("dos".to_string(), true);
        } else {
            self.attack_matrix.insert("dos".to_string(), false);
        }

        let source = self.get_pps_near_source();
        // info!("pp near source: {:?}", source);

        // Assuming get_pps_near_source and get_pps_near_sink return appropriate data structures
        let mut reachable_site: HashMap<String, String> = HashMap::new();

        // Assuming is_same and is_reachable are methods
        // for pp1 in &pps_near_source {
        //     for pp2 in &pps_near_sink {
        //         if self.is_same(pp1, pp2) || self.is_reachable(pp1, pp2) {
        //             reachable = true;
        //             let caller = pp2.caller.clone();
        //             let caller_func_sign = pp2.caller_func_sign.clone();
        //             reachable_site.insert(pp2.func_sign.clone(), (caller, caller_func_sign));
        //         }
        //     }
        // }

        // let mut victim_callback_info = HashMap::new();
        // let mut attack_reenter_info = HashMap::new();

        // if reachable {
        //     let overlap: HashSet<_> = sensitive_callsigs
        //         .intersection(&self.external_call_in_func_signature)
        //         .collect();
        //     if !overlap.is_empty() {
        //         for i in &overlap {
        //             victim_callback_info
        //                 .entry(i.clone())
        //                 .or_insert_with(Vec::new);
        //             attack_reenter_info
        //                 .entry(i.clone())
        //                 .or_insert_with(Vec::new);

        //             if let Some(site) = reachable_site.get(i) {
        //                 if !victim_callback_info.get_mut(i).unwrap().contains(site) {
        //                     victim_callback_info.get_mut(i).unwrap().push(site.clone());
        //                 }
        //             }
        //             for (key, contract) in &self.contracts {
        //                 if contract.func_sign == *i && contract.level == 0 {
        //                     for ec in &contract.external_calls {
        //                         let temp_target_address = ec.logic_addr.clone();
        //                         let temp_func_sign = ec.func_sign.clone();
        //                         let res = (temp_target_address.clone(), temp_func_sign.clone());
        //                         if !attack_reenter_info.get_mut(i).unwrap().contains(&res)
        //                             && self.visited_contracts.contains(&temp_target_address)
        //                             && self.visited_funcs.contains(&temp_func_sign)
        //                         {
        //                             attack_reenter_info.get_mut(i).unwrap().push(res);
        //                         }
        //                     }
        //                     result = true;
        //                     self.attack_matrix.insert("reentrancy".to_string(), true);
        //                 }
        //             }
        //         }
        //     }
        // }

        // self.victim_callback_info = victim_callback_info;
        // self.attack_reenter_info = attack_reenter_info;
        (result, self.attack_matrix.clone())
    }
}
