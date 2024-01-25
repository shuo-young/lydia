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

#[derive(Debug)]
pub struct SensitiveOpOfBadRandomnessAfterExternalCall {
    pub func_sign: String,
    pub call_stmt: String,
    pub sensitive_var: String,
    pub source_op: String,
}

impl From<StringRecord> for SensitiveOpOfBadRandomnessAfterExternalCall {
    fn from(record: StringRecord) -> Self {
        // Parse and create SensitiveOpOfBadRandomnessAfterExternalCall
        SensitiveOpOfBadRandomnessAfterExternalCall {
            func_sign: record[0].to_string(),
            call_stmt: record[1].to_string(),
            sensitive_var: record[2].to_string(),
            source_op: record[3].to_string(),
        }
    }
}

pub struct SensitiveOpOfDoSAfterExternalCall {
    pub func_sign: String,
    pub call_stmt: String,
    pub call_ret_var: String,
    pub call_ret_index: String,
    pub sensitive_var: String,
}

impl From<StringRecord> for SensitiveOpOfDoSAfterExternalCall {
    fn from(record: StringRecord) -> Self {
        // Parse and create SensitiveOpOfDoSAfterExternalCall
        SensitiveOpOfDoSAfterExternalCall {
            func_sign: record[0].to_string(),
            call_stmt: record[1].to_string(),
            call_ret_var: record[2].to_string(),
            call_ret_index: record[3].to_string(),
            sensitive_var: record[4].to_string(),
        }
    }
}

#[derive(Debug)]
pub struct TaintedCallArg {
    pub func_sign: String,
    pub call_stmt: String,
    pub call_arg_index: String,
}

impl From<StringRecord> for TaintedCallArg {
    fn from(record: StringRecord) -> Self {
        // Parse and create TaintedCallArg
        TaintedCallArg {
            func_sign: record[0].to_string(),
            call_stmt: record[1].to_string(),
            call_arg_index: record[2].to_string(),
        }
    }
}

pub struct FuncArgToSensitiveVar {
    pub func_sign: String,
    pub call_stmt: String,
    pub func_arg: String,
    pub func_arg_index: String,
    pub sensitive_var: String,
    pub call_func_sign: String,
}

impl From<StringRecord> for FuncArgToSensitiveVar {
    fn from(record: StringRecord) -> Self {
        // Parse and create FuncArgToSensitiveVar
        FuncArgToSensitiveVar {
            func_sign: record[0].to_string(),
            call_stmt: record[1].to_string(),
            func_arg: record[2].to_string(),
            func_arg_index: record[3].to_string(),
            sensitive_var: record[4].to_string(),
            call_func_sign: record[5].to_string(),
        }
    }
}

pub struct CallRetToFuncRet {
    pub call_stmt: String,
    pub call_ret: String,
    pub call_ret_index: String,
    pub func_sign: String,
    pub func_ret_index: String,
    pub func_ret: String,
}

impl From<StringRecord> for CallRetToFuncRet {
    fn from(record: StringRecord) -> Self {
        // Parse and create SpreadCallRetToFuncRet
        CallRetToFuncRet {
            call_stmt: record[0].to_string(),
            call_ret: record[1].to_string(),
            call_ret_index: record[2].to_string(),
            func_sign: record[3].to_string(),
            func_ret_index: record[4].to_string(),
            func_ret: record[5].to_string(),
        }
    }
}

pub struct CallRetToCallArg {
    pub call_stmt1: String,
    pub call_ret: String,
    pub call_ret_index: String,
    pub call_stmt2: String,
    pub call_arg_index: String,
    pub call_arg: String,
}

impl From<StringRecord> for CallRetToCallArg {
    fn from(record: StringRecord) -> Self {
        // Parse and create SpreadCallRetToCallArg
        CallRetToCallArg {
            call_stmt1: record[0].to_string(),
            call_ret: record[1].to_string(),
            call_ret_index: record[2].to_string(),
            call_stmt2: record[3].to_string(),
            call_arg_index: record[4].to_string(),
            call_arg: record[5].to_string(),
        }
    }
}

pub struct CallArgs {
    pub call_stmt: String,
    pub call_arg_index: String,
}

pub struct FuncArgToCallArg {
    pub func_sign: String,
    pub func_arg_index: String,
    pub func_arg: String,
    pub call_stmt: String,
    pub call_arg_index: String,
    pub call_arg: String,
}

impl From<StringRecord> for FuncArgToCallArg {
    fn from(record: StringRecord) -> Self {
        // Parse and create SpreadFuncArgToCallArg
        FuncArgToCallArg {
            func_sign: record[0].to_string(),
            func_arg_index: record[1].to_string(),
            func_arg: record[2].to_string(),
            call_stmt: record[3].to_string(),
            call_arg_index: record[4].to_string(),
            call_arg: record[5].to_string(),
        }
    }
}

pub struct FuncArgToCallee {
    pub func_sign: String,
    pub func_arg_index: String,
    pub func_arg: String,
    pub call_stmt: String,
    pub call_arg_index: String,
}
impl From<StringRecord> for FuncArgToCallee {
    fn from(record: StringRecord) -> Self {
        // Parse and create SpreadFuncArgToCallee
        FuncArgToCallee {
            func_sign: record[0].to_string(),
            func_arg_index: record[1].to_string(),
            func_arg: record[2].to_string(),
            call_stmt: record[3].to_string(),
            call_arg_index: record[4].to_string(),
        }
    }
}

pub struct FuncArgToFuncRet {
    pub func_sign: String,
    pub func_arg_index: String,
    pub func_arg: String,
    pub func_ret_index: String,
    pub func_ret: String,
}

impl From<StringRecord> for FuncArgToFuncRet {
    fn from(record: StringRecord) -> Self {
        // Parse and create SpreadFuncArgToFuncRet
        FuncArgToFuncRet {
            func_sign: record[0].to_string(),
            func_arg_index: record[1].to_string(),
            func_arg: record[2].to_string(),
            func_ret_index: record[3].to_string(),
            func_ret: record[4].to_string(),
        }
    }
}

pub struct EnvVarFlowsToTaintedVar {
    pub func_sign: String,
    pub env_var: String,
    pub tainted_var: String,
}

impl From<StringRecord> for EnvVarFlowsToTaintedVar {
    fn from(record: StringRecord) -> Self {
        // Parse and create EnvVarFlowsToTaintedVar
        EnvVarFlowsToTaintedVar {
            func_sign: record[0].to_string(),
            env_var: record[1].to_string(),
            tainted_var: record[2].to_string(),
        }
    }
}

pub struct OpCreateInLoop {
    pub func_sign: String,
    pub stmt: String,
}

impl From<StringRecord> for OpCreateInLoop {
    fn from(record: StringRecord) -> Self {
        // Parse and create OpCreateInLoop
        OpCreateInLoop {
            func_sign: record[0].to_string(),
            stmt: record[1].to_string(),
        }
    }
}

pub struct OpSoleCreate {
    pub func_sign: String,
    pub stmt: String,
}

impl From<StringRecord> for OpSoleCreate {
    fn from(record: StringRecord) -> Self {
        // Parse and create OpSoleCreate
        OpSoleCreate {
            func_sign: record[0].to_string(),
            stmt: record[1].to_string(),
        }
    }
}

pub struct OpSelfdestruct {
    pub func_sign: String,
    pub target: String,
}

impl From<StringRecord> for OpSelfdestruct {
    fn from(record: StringRecord) -> Self {
        // Parse and create OpSelfdestruct
        OpSelfdestruct {
            func_sign: record[0].to_string(),
            target: record[1].to_string(),
        }
    }
}

pub struct ExternalCallInHook {
    pub call_stmt: String,
    pub func_sign: String,
}

impl From<StringRecord> for ExternalCallInHook {
    fn from(record: StringRecord) -> Self {
        // Parse and create ExternalCallInHook
        ExternalCallInHook {
            call_stmt: record[0].to_string(),
            func_sign: record[1].to_string(),
        }
    }
}

pub struct ExternalCallInFallback {
    pub call_stmt: String,
    pub func_sign: String,
}

impl From<StringRecord> for ExternalCallInFallback {
    fn from(record: StringRecord) -> Self {
        // Parse and create ExternalCallInFallback
        ExternalCallInFallback {
            call_stmt: record[0].to_string(),
            func_sign: record[1].to_string(),
        }
    }
}

pub struct DoubleCallToSameContract {
    pub func_sign: String,
    pub callee: String,
}

impl From<StringRecord> for DoubleCallToSameContract {
    fn from(record: StringRecord) -> Self {
        // Parse and create DoubleCallToSameContract
        DoubleCallToSameContract {
            func_sign: record[0].to_string(),
            callee: record[1].to_string(),
        }
    }
}

pub struct DoubleCallToSameContractByStorage {
    pub func_sign: String,
    pub call_stmt: String,
    pub call_ret_var: String,
    pub call_ret_index: String,
    pub sensitive_var: String,
}

impl From<StringRecord> for DoubleCallToSameContractByStorage {
    fn from(record: StringRecord) -> Self {
        // Parse and create DoubleCallToSameContractByStorage
        DoubleCallToSameContractByStorage {
            func_sign: record[0].to_string(),
            call_stmt: record[1].to_string(),
            call_ret_var: record[2].to_string(),
            call_ret_index: record[3].to_string(),
            sensitive_var: record[4].to_string(),
        }
    }
}
