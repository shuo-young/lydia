use crate::{contract::contract::Contract, Source};
use std::collections::{HashMap, HashSet};

#[allow(dead_code)]
pub struct CallGraph {
    output: String,
    visited_contracts: HashSet<String>,
    visited_funcs: HashSet<String>,
    max_level: u32,
    platform: String,
    contracts: HashMap<String, Contract>,
}
impl CallGraph {
    pub fn new(platform: String) -> CallGraph {
        CallGraph {
            output: String::new(),
            visited_contracts: HashSet::new(),
            visited_funcs: HashSet::new(),
            max_level: 0,
            platform,
            contracts: HashMap::new(),
        }
    }

    pub fn get_output(&self) -> &str {
        &self.output
    }

    pub async fn construct_cross_contract_call_graph(
        &mut self,
        source: Source,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut pending = vec![source];
        println!("{:?}", pending);
        while let Some(temp) = pending.pop() {
            let index = pending.len();
            println!("pending length: {}", index);
            println!("current temp contract: {}", temp.logic_addr);
            if temp.level > self.max_level {
                self.max_level = temp.level;
            }

            let temp_key = format!(
                "{}_{}_{}_{}_{}",
                temp.caller, temp.call_site, temp.logic_addr, temp.func_sign, temp.caller_func_sign
            );
            println!(
                "{:indent$}{}_{}_{call_site} -> {}_{}",
                "",
                temp.caller,
                temp.caller_func_sign,
                temp.logic_addr,
                temp.func_sign,
                call_site = temp.call_site,
                indent = temp.level as usize
            );
            self.output.push_str(&format!(
                "{:indent$}{}_{}_{} -> {}_{}",
                "",
                temp.caller,
                temp.caller_func_sign,
                temp.call_site,
                temp.logic_addr,
                temp.func_sign,
                indent = temp.level as usize
            ));

            if self.contracts.contains_key(&temp_key) {
                continue;
            }

            self.visited_contracts.insert(temp.logic_addr.clone());
            self.visited_funcs.insert(temp.func_sign.clone());

            let mut new_contract = Contract::new(
                temp.platform.clone(),
                temp.logic_addr.clone(),
                temp.storage_addr.clone(),
                temp.func_sign.clone(),
                temp.block_number,
                temp.caller.clone(),
                temp.call_site.clone(),
                temp.level,
            );
            if let Err(e) = &new_contract.analyze().await {
                eprintln!("An error occurred during analysis: {}", e);
            };
            self.contracts.insert(temp_key.clone(), new_contract);

            for external_call in &self.contracts[&temp_key].external_calls {
                if !external_call.target_logic_addr.is_empty()
                    && !external_call.target_storage_addr.is_empty()
                    && !external_call.target_func_sign.is_empty()
                {
                    let source = Source {
                        platform: temp.platform.clone(),
                        logic_addr: external_call.target_logic_addr.clone(),
                        storage_addr: external_call.target_storage_addr.clone(),
                        func_sign: external_call.target_func_sign.clone(),
                        block_number: temp.block_number,
                        caller: external_call.caller_addr.clone(),
                        call_site: external_call.call_site.clone(),
                        level: temp.level + 1,
                        caller_func_sign: external_call.caller_func_sign.clone(),
                    };
                    pending.push(source);
                }
            }
        }
        Ok(())
    }
}