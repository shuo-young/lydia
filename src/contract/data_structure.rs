use csv::StringRecord;
use serde::Deserialize;
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ConstantCallee {
    pub(crate) func: String,
    pub(crate) call_stmt: String,
    pub(crate) callee: String,
}
impl From<StringRecord> for ConstantCallee {
    fn from(record: StringRecord) -> Self {
        // Parse and create ConstantCallee
        ConstantCallee {
            func: record[0].to_string(),
            call_stmt: record[1].to_string(),
            callee: record[2].to_string(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct StorageCallee {
    func: String,
    pub(crate) call_stmt: String,
    pub(crate) storage_slot: String,
    pub(crate) byte_low: String,
    pub(crate) byte_high: String,
}
impl From<StringRecord> for StorageCallee {
    fn from(record: StringRecord) -> Self {
        // Parse and create StorageCallee
        StorageCallee {
            func: record[0].to_string(),
            call_stmt: record[1].to_string(),
            storage_slot: record[2].to_string(),
            byte_low: record[3].to_string(),
            byte_high: record[4].to_string(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ProxyStorageCallee {
    func: String,
    pub(crate) call_stmt: String,
    pub(crate) storage_slot: String,
}
impl From<StringRecord> for ProxyStorageCallee {
    fn from(record: StringRecord) -> Self {
        // Parse and create ProxyStorageCallee
        ProxyStorageCallee {
            func: record[0].to_string(),
            call_stmt: record[1].to_string(),
            storage_slot: record[2].to_string(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct FuncArgCallee {
    pub(crate) func: String,
    pub(crate) call_stmt: String,
    pub(crate) pub_fun: String,
    pub(crate) arg_index: String,
}
impl From<StringRecord> for FuncArgCallee {
    fn from(record: StringRecord) -> Self {
        // Parse and create FuncArgCallee
        FuncArgCallee {
            func: record[0].to_string(),
            call_stmt: record[1].to_string(),
            pub_fun: record[2].to_string(),
            arg_index: record[3].to_string(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ConstantFuncSign {
    func: String,
    pub(crate) call_stmt: String,
    pub(crate) func_sign: String,
}
impl From<StringRecord> for ConstantFuncSign {
    fn from(record: StringRecord) -> Self {
        // Parse and create ConstantFuncSign
        ConstantFuncSign {
            func: record[0].to_string(),
            call_stmt: record[1].to_string(),
            func_sign: record[2].to_string(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ProxyFuncSign {
    pub(crate) func: String,
    pub(crate) call_stmt: String,
}
impl From<StringRecord> for ProxyFuncSign {
    fn from(record: StringRecord) -> Self {
        // Parse and create ProxyFuncSign
        ProxyFuncSign {
            func: record[0].to_string(),
            call_stmt: record[1].to_string(),
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)]
#[derive(Eq, Hash, PartialEq, Deserialize)]
pub(crate) struct ExternalCallData {
    #[serde(rename = "0")]
    pub(crate) func: String,
    #[serde(rename = "1")]
    pub(crate) call_stmt: String,
    #[serde(rename = "2")]
    pub(crate) call_op: String,
    #[serde(rename = "3")]
    pub(crate) callee_var: String,
    #[serde(rename = "4")]
    pub(crate) num_arg: String,
    #[serde(rename = "5")]
    pub(crate) num_ret: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct ExternalCall {
    pub(crate) target_logic_addr: String,
    pub(crate) target_storage_addr: String,
    pub(crate) target_func_sign: String,
    pub(crate) call_site: String,
    pub(crate) caller_func_sign: String,
    pub(crate) caller_addr: String,
}
