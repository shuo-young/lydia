use log::{error, info};
use std::collections::HashMap;
use std::io::{self};
use std::process::Command;
use std::{fs, path::Path};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use web3::types::Address;

use csv::{ReaderBuilder, StringRecord};
use std::error::Error;
use std::mem;

use crate::contract::data_structure;
use crate::contract::status_fetcher::Web3Transport;

use super::data_structure::ExternalCallData;

const CONTRACT_PATH: &str = "./gigahorse-toolchain/contracts/";
const CONTRACT_DIR: &str = "./contracts/";
const TEMP_PATH: &str = "./gigahorse-toolchain/.temp/";

#[derive(Debug)]
enum ValueType {
    Int(i32),
    Float(f64),
    Str(String),
}

#[derive(Debug)]
#[allow(dead_code)]
struct ExternalCall {
    target_logic_addr: String,
    target_storage_addr: String,
    target_func_sign: String,
    call_site: String,
    caller_func_sign: String,
    caller_addr: String,
}

#[allow(dead_code)]
pub struct Contract {
    platform: String,
    logic_addr: String,
    storage_addr: String,
    func_sign: String,
    block_number: u64,
    caller: String,
    call_site: String,
    level: u32,
    origin: bool,
    func: String,
    func_sign_dict: HashMap<String, String>,
    func_sign_list: Vec<String>,
    external_call_in_func_signature: Vec<String>,
    call_arg_vals: HashMap<i32, ValueType>,
    url: String,
    external_calls: Vec<ExternalCall>,
    createbin: bool,
    storage_space: HashMap<i32, ValueType>,
    // try to add double links
    caller_contract: Option<Box<Contract>>,
    target_contract: Option<Box<Contract>>,
    // data reader
    constant_callee_df: Vec<data_structure::ConstantCallee>,
    storage_callee_df: Vec<data_structure::StorageCallee>,
    storage_callee_proxy_df: Vec<data_structure::ProxyStorageCallee>,
    func_arg_callee_df: Vec<data_structure::FuncArgCallee>,
    constant_func_sign_df: Vec<data_structure::ConstantFuncSign>,
    proxy_func_sign_df: Vec<data_structure::ProxyFuncSign>,
}

#[allow(dead_code)]
impl Contract {
    pub fn new(
        platform: String,
        logic_addr: String,
        storage_addr: String,
        func_sign: String,
        block_number: u64,
        caller: String,
        call_site: String,
        level: u32,
    ) -> Contract {
        // Initialize a Contract instance
        let formatted_logic_addr = Self::format_addr(&logic_addr);
        let formatted_storage_addr = Self::format_addr(&storage_addr);
        Contract {
            platform,
            logic_addr: formatted_logic_addr,
            storage_addr: formatted_storage_addr,
            func_sign: func_sign.clone(),
            origin: func_sign.is_empty(),
            func: String::new(),
            func_sign_dict: HashMap::new(),
            func_sign_list: Vec::new(),
            external_call_in_func_signature: Vec::new(),
            call_arg_vals: HashMap::new(),
            url: String::new(),
            external_calls: Vec::new(),
            storage_space: HashMap::new(),
            block_number,
            caller,
            call_site,
            level,
            createbin: false,
            caller_contract: None,
            target_contract: None,
            constant_callee_df: Vec::new(),
            storage_callee_df: Vec::new(),
            storage_callee_proxy_df: Vec::new(),
            func_arg_callee_df: Vec::new(),
            constant_func_sign_df: Vec::new(),
            proxy_func_sign_df: Vec::new(),
        }
    }

    pub async fn analyze(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.download_bytecode().await?;
        // if code exists, go on analyzing
        let path = format!("{}{}.hex", CONTRACT_PATH, self.logic_addr);
        if Path::new(&path).exists() {
            // Perform analysis
            self.analyze_contract().await?;
        }
        Ok(())
    }

    fn format_addr(addr: &str) -> String {
        if addr.len() != 42 {
            let mut formatted_addr = String::from("0x");
            formatted_addr.push_str(&"0".repeat(42 - addr.len()));
            formatted_addr.push_str(&addr.replace("0x", ""));
            formatted_addr
        } else {
            addr.to_string()
        }
    }

    fn is_createbin(&self) -> &bool {
        &self.createbin
    }

    fn set_url(&mut self) {
        self.url =
            match self.platform.as_str() {
                "ETH" => "https://eth-mainnet.alchemyapi.io/v2/6t0LpEw9cr0OlGIVTFqs92aOIkfhktMk"
                    .to_string(),
                "BSC" => "wss://bsc.getblock.io/6bf31e7d-f5b2-4860-8e15-aa9a11f6533d/mainnet/"
                    .to_string(),
                _ => "".to_string(),
            };
    }

    async fn download_bytecode(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.set_url();
        if self.url.is_empty() {
            error!("URL is empty");
            return Ok(());
        }
        let loc: String = format!("{}{}.hex", CONTRACT_PATH, self.logic_addr);
        if Path::new(&loc).exists() {
            // Read the file
            // ... handle file reading and conditional logic
            let bin = fs::read_to_string(&loc)?;
            if bin == "0x" {
                // use contracts obtained from replay, but indeed, the creation code could be obtrained from the first deployment transaction
                let bin_content_path = format!(
                    "{}createbin/{}_createbin.hex",
                    CONTRACT_PATH, self.logic_addr
                );
                if let Ok(bin_content) = fs::read_to_string(bin_content_path) {
                    fs::write(&loc, &bin_content[2..])?;
                    self.createbin = true;
                    // Assume createbin only has constructor
                    self.func_sign = "__function_selector__".to_string();
                    self.func_sign_list = vec!["__function_selector__".to_string()];
                }
            }
        } else {
            // Perform network request to get bytecode
            // rpc methods are put into the status_fetcher module
            let contract_address: Address =
                self.logic_addr.parse().expect("Invalid contract address");
            let transport = Web3Transport::new(&self.url).await?;
            let code = transport.get_code(contract_address).await?;
            let hex_string = hex::encode(code.0.clone());
            // Check if the code is not the zero-byte code.
            if !code.0.is_empty() {
                // Use tokio's async file writing methods to write the code to a file.
                let mut file = File::create(&loc).await?;
                file.write_all(hex_string.as_bytes()).await?; // Skip the leading '0x' if present and finish code fetching
            }
        }

        Ok(())
    }

    async fn analyze_contract(&mut self) -> io::Result<()> {
        // Call external command to analyze the contract
        let command = format!(
            "cd ./gigahorse-toolchain && ./gigahorse.py -C ./clients/leslie.dl {}{}.hex >/dev/null 2>&1",
            CONTRACT_DIR, self.logic_addr
        );
        // Execute the command
        let status = Command::new("sh").arg("-c").arg(command).status()?;

        if !status.success() {
            error!("Command executed with failing error code");
        }
        // binding functions
        let _ = self.set_func();
        // extract known call arguments, constants etc.
        let _ = self.set_call_arg_vals();
        // prepare for the call info
        let _ = self.set_call_info();

        if self.origin {
            for func in self.func_sign_dict.clone().keys() {
                let _ = self
                    .set_external_calls(func, &self.func_sign_dict[func].clone())
                    .await;
            }
        } else {
            let func_clone = self.func.clone();
            let func_sign_clone = self.func_sign.clone();
            let _ = self.set_external_calls(&func_clone, &func_sign_clone).await;
        }
        info!("contract external calls{:?}", self.external_calls);
        Ok(())
    }

    fn set_call_info(&mut self) {
        // set callee
        let _ = self.set_callee_info();
        // set func sign
        let _ = self.set_func_sign_info();
    }

    fn set_callee_info(&mut self) -> Result<(), Box<dyn Error>> {
        // Temporarily take ownership of the vectors
        let mut constant_callee_df = mem::take(&mut self.constant_callee_df);
        let mut storage_callee_df = mem::take(&mut self.storage_callee_df);
        let mut storage_callee_proxy_df = mem::take(&mut self.storage_callee_proxy_df);
        let mut func_arg_callee_df = mem::take(&mut self.func_arg_callee_df);

        // type1: constant callee written in the contract
        self.read_csv::<data_structure::ConstantCallee>(
            &format!(
                "{}{}/out/Leslie_ExternalCall_Callee_ConstType.csv",
                TEMP_PATH, self.logic_addr
            ),
            &mut constant_callee_df,
        )?;
        // type2: callee stored in the storage-type state variable
        self.read_csv::<data_structure::StorageCallee>(
            &format!(
                "{}{}/out/Leslie_ExternalCall_Callee_StorageType.csv",
                TEMP_PATH, self.logic_addr
            ),
            &mut storage_callee_df,
        )?;
        // type3: proxy callee stored in the storage-type state variable
        self.read_csv::<data_structure::ProxyStorageCallee>(
            &format!(
                "{}{}/out/Leslie_ExternalCall_Callee_StorageType_ForProxy.csv",
                TEMP_PATH, self.logic_addr
            ),
            &mut storage_callee_proxy_df,
        )?;
        // type4: callee flowed from function arguments
        self.read_csv::<data_structure::FuncArgCallee>(
            &format!(
                "{}{}/out/Leslie_ExternalCall_Callee_FuncArgType.csv",
                TEMP_PATH, self.logic_addr
            ),
            &mut func_arg_callee_df,
        )?;
        // Put the vectors back
        self.constant_callee_df = constant_callee_df;
        self.storage_callee_df = storage_callee_df;
        self.storage_callee_proxy_df = storage_callee_proxy_df;
        self.func_arg_callee_df = func_arg_callee_df;
        info!("constant callee info: {:?}", self.constant_callee_df);
        info!("storage callee info: {:?}", self.storage_callee_df);
        info!(
            "storage callee for proxy info: {:?}",
            self.storage_callee_proxy_df
        );
        info!(
            "function argument callee info: {:?}",
            self.func_arg_callee_df
        );
        Ok(())
    }

    fn set_func_sign_info(&mut self) -> Result<(), Box<dyn Error>> {
        // Temporarily take ownership of the vectors
        let mut constant_func_sign_df = mem::take(&mut self.constant_func_sign_df);
        let mut proxy_func_sign_df = mem::take(&mut self.proxy_func_sign_df);
        // type1: constant func sign written in the contract
        self.read_csv::<data_structure::ConstantFuncSign>(
            &format!(
                "{}{}/out/Leslie_ExternalCall_FuncSign_ConstType.csv",
                TEMP_PATH, self.logic_addr
            ),
            &mut constant_func_sign_df,
        )?;
        // type2: proxy func sign
        self.read_csv::<data_structure::ProxyFuncSign>(
            &format!(
                "{}{}/out/Leslie_ExternalCall_FuncSign_ProxyType.csv",
                TEMP_PATH, self.logic_addr
            ),
            &mut proxy_func_sign_df,
        )?;
        // Put the vectors back
        self.constant_func_sign_df = constant_func_sign_df;
        self.proxy_func_sign_df = proxy_func_sign_df;
        info!(
            "constant function signature: {:?}",
            self.constant_func_sign_df
        );
        info!("proxy function signature: {:?}", self.proxy_func_sign_df);
        Ok(())
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

    #[allow(unused_variables)]
    async fn set_external_calls(
        &mut self,
        func: &str,
        func_sign: &str,
    ) -> Result<(), Box<dyn Error>> {
        // Process the first CSV file
        let loc_external_call = format!(
            "{}{}/out/Leslie_ExternalCallInfo.csv",
            TEMP_PATH, self.logic_addr
        );
        let mut external_calls_df = Vec::<ExternalCallData>::new();
        if fs::metadata(&loc_external_call)
            .map(|m| m.len() > 0)
            .unwrap_or(false)
        {
            let mut rdr = ReaderBuilder::new()
                .delimiter(b'\t')
                .from_path(&loc_external_call)?;

            for result in rdr.records() {
                let record = result?;
                if record.len() == 6 && &record[0] == func {
                    let external_call = data_structure::ExternalCallData {
                        func: record[0].to_string(),
                        call_stmt: record[1].to_string(),
                        call_op: record[2].to_string(),
                        callee_var: record[3].to_string(),
                        num_arg: record[4].to_string(),
                        num_ret: record[5].to_string(),
                    };
                    external_calls_df.push(external_call)
                }
            }
        }
        for external_call_data in &external_calls_df {
            let mut external_call = ExternalCall {
                target_logic_addr: String::new(),
                target_storage_addr: String::new(),
                target_func_sign: String::new(),
                caller_addr: self.caller.clone(),
                caller_func_sign: func_sign.to_string(),
                call_site: external_call_data.call_stmt.clone(),
            };
            // Logic to find and set the logic address
            if let Some(data) = self
                .constant_callee_df
                .iter()
                .find(|d| d.call_stmt == external_call_data.call_stmt)
            {
                external_call.target_logic_addr =
                    data.callee.clone().replace("000000000000000000000000", "");
            }

            // get storage from web3 api
            if let Some(data) = self
                .storage_callee_df
                .iter()
                .find(|d| d.call_stmt == external_call_data.call_stmt)
            {
                let contract_address: Address =
                    self.storage_addr.parse().expect("Invalid contract address");
                let transport = Web3Transport::new(&self.url).await?;
                external_call.target_logic_addr = transport
                    .get_storage(
                        contract_address,
                        &data.storage_slot,
                        &data.byte_low,
                        &data.byte_high,
                    )
                    .await?;
            }

            // get storage from web3 api
            if let Some(data) = self
                .storage_callee_proxy_df
                .iter()
                .find(|d| d.call_stmt == external_call_data.call_stmt)
            {
                let contract_storage_address: Address =
                    self.storage_addr.parse().expect("Invalid contract address");
                let transport = Web3Transport::new(&self.url).await?;
                external_call.target_logic_addr = transport
                    .get_storage(
                        contract_storage_address,
                        &data.storage_slot,
                        &String::from("0"),
                        &String::from("19"),
                    )
                    .await?;
            }

            // find callee got from the func arg, and try to recover the know args
            if let Some(data) = self
                .func_arg_callee_df
                .iter()
                .find(|d| d.call_stmt == external_call_data.call_stmt)
            {
                if data.func == data.pub_fun {
                    let temp_index: i32 = data.arg_index.parse::<i32>().unwrap();
                    if self.call_arg_vals.contains_key(&temp_index) {
                        external_call.target_logic_addr = match &self.call_arg_vals[&temp_index] {
                            ValueType::Int(i) => i.to_string(),
                            ValueType::Float(f) => f.to_string(),
                            ValueType::Str(s) => s.clone(),
                        }
                    }
                }
            }

            if external_call_data.call_op == "DELEGATECALL" {
                external_call.target_storage_addr = self.logic_addr.clone();
                external_call.caller_addr = self.caller.clone();
                external_call.call_site = self.call_site.clone();
            } else {
                external_call.target_storage_addr = external_call.target_logic_addr.clone();
                external_call.caller_addr = self.logic_addr.clone();
                external_call.call_site = external_call_data.call_stmt.clone();
            }

            // Logic to find and set the logic address
            if let Some(data) = self
                .constant_func_sign_df
                .iter()
                .find(|d| d.call_stmt == external_call_data.call_stmt)
            {
                external_call.target_func_sign = data.func_sign.clone()[..10].to_string();
            }

            if let Some(data) = self
                .proxy_func_sign_df
                .iter()
                .find(|d| d.call_stmt == external_call_data.call_stmt)
            {
                external_call.target_func_sign = func_sign.to_string();
            }
            self.external_calls.push(external_call);
        }

        Ok(())
    }

    fn set_func(&mut self) -> Result<(), Box<dyn Error>> {
        let loc = format!(
            "{}{}/out/Leslie_FunctionSelector.csv",
            TEMP_PATH, self.logic_addr
        );

        if fs::metadata(&loc).map(|m| m.len() > 0).unwrap_or(false) {
            let mut rdr = ReaderBuilder::new().delimiter(b'\t').from_path(loc)?;

            for result in rdr.records() {
                let record = result?;
                if record.len() == 2 {
                    let func = record[0].to_string();
                    let func_sign = record[1].to_string();
                    self.func_sign_list.push(func.clone());
                    self.func_sign_dict.insert(func, func_sign);
                }
            }
            info!("function signature dict{:?}", self.func_sign_dict);

            if !self.origin {
                self.func = self
                    .func_sign_dict
                    .iter()
                    .find_map(|(key, val)| {
                        if val == &self.func_sign {
                            Some(key.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or(String::new());
                info!("func_sign: {}", self.func_sign);
                info!("func: {}", self.func);
                if self.func.is_empty() {
                    self.func = self
                        .func_sign_dict
                        .iter()
                        .find_map(|(key, val)| {
                            if val == &String::from("0x00000000") {
                                Some(key.clone())
                            } else {
                                None
                            }
                        })
                        .unwrap_or(String::new());
                }
            }
        }

        Ok(())
    }

    fn set_call_arg_vals(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.caller.is_empty() {
            let loc = format!(
                "{}{}/out/Leslie_ExternalCall_Known_Arg.csv",
                TEMP_PATH, self.logic_addr
            );

            if fs::metadata(&loc).map(|m| m.len() > 0).unwrap_or(false) {
                let mut rdr = ReaderBuilder::new().delimiter(b'\t').from_path(loc)?;

                for result in rdr.deserialize::<(String, String, i32, String)>() {
                    let (_func, call_stmt, arg_index, arg_val_str) = result?;

                    if call_stmt == self.call_site {
                        let value = if let Ok(int_val) = arg_val_str.parse::<i32>() {
                            ValueType::Int(int_val)
                        } else if let Ok(float_val) = arg_val_str.parse::<f64>() {
                            ValueType::Float(float_val)
                        } else {
                            ValueType::Str(arg_val_str)
                        };

                        self.call_arg_vals.insert(arg_index, value);
                        info!("call arg values: {:?}", self.call_arg_vals);
                    }
                }
            }
        }
        Ok(())
    }
}
