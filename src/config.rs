//! Configuration module for Lydia
//! 
//! This module handles command-line argument parsing and application configuration.

use clap::{App, Arg};
use std::error::Error;
use std::fmt;

/// Default values used throughout the application
pub mod defaults {
    pub const BLOCKCHAIN_PLATFORM: &str = "ETH";
    pub const BLOCK_NUMBER: u64 = 16_000_000;
    pub const CALLER: &str = "msg.sender";
    pub const OUTPUT_DIR: &str = "./output/";
    pub const LEVEL: i32 = 0;
    pub const WARNING_MEDIUM: &str = "medium";
    pub const WARNING_HIGH: &str = "high";
    pub const CREATEBIN_FUNC_SELECTOR: &str = "__function_selector__";
    pub const CREATEBIN_ANALYSIS_LOC: &str = "createbin";
    pub const RUNTIMEBIN_ANALYSIS_LOC: &str = "runtimebin";
}

/// Configuration structure holding all application settings
#[derive(Debug, Clone)]
pub struct Config {
    pub platform: String,
    pub logic_address: String,
    pub storage_address: String,
    pub block_number: u64,
}

/// Custom error type for configuration-related errors
#[derive(Debug)]
pub enum ConfigError {
    InvalidBlockNumber(String),
    MissingRequiredField(String),
    ParseError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidBlockNumber(msg) => write!(f, "Invalid block number: {}", msg),
            ConfigError::MissingRequiredField(field) => write!(f, "Missing required field: {}", field),
            ConfigError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl Error for ConfigError {}

impl Config {
    /// Create a new configuration from command-line arguments
    pub fn from_args() -> Result<Self, ConfigError> {
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
                    .default_value(defaults::BLOCKCHAIN_PLATFORM),
            )
            .arg(
                Arg::with_name("logic_address")
                    .short('l')
                    .long("logic_address")
                    .value_name("LOGIC_ADDR")
                    .help("Contract address for storing business logic")
                    .takes_value(true)
                    .required(true),
            )
            .arg(
                Arg::with_name("storage_address")
                    .short('s')
                    .long("storage_address")
                    .value_name("STORAGE_ADDR")
                    .help("Contract address for storing business data")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("block_number")
                    .short('n')
                    .long("block_number")
                    .value_name("BLOCK_NUMBER")
                    .help("Blockchain snapshot block number")
                    .takes_value(true)
                    .default_value(&defaults::BLOCK_NUMBER.to_string()),
            )
            .get_matches();

        let platform = matches
            .value_of("blockchain_platform")
            .ok_or_else(|| ConfigError::MissingRequiredField("blockchain_platform".to_string()))?
            .to_string();

        let logic_address = matches
            .value_of("logic_address")
            .ok_or_else(|| ConfigError::MissingRequiredField("logic_address".to_string()))?
            .to_string();

        let storage_address = matches
            .value_of("storage_address")
            .unwrap_or(&logic_address)
            .to_string();

        let block_number = matches
            .value_of("block_number")
            .ok_or_else(|| ConfigError::MissingRequiredField("block_number".to_string()))?
            .parse::<u64>()
            .map_err(|e| ConfigError::InvalidBlockNumber(e.to_string()))?;

        Ok(Config {
            platform,
            logic_address,
            storage_address,
            block_number,
        })
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.logic_address.is_empty() {
            return Err(ConfigError::MissingRequiredField("logic_address".to_string()));
        }
        
        if !self.logic_address.starts_with("0x") || self.logic_address.len() != 42 {
            return Err(ConfigError::ParseError("Invalid Ethereum address format".to_string()));
        }

        Ok(())
    }
}

/// Source structure for analysis context
#[derive(Debug, Clone)]
pub struct AnalysisSource {
    pub platform: String,
    pub logic_addr: String,
    pub storage_addr: String,
    pub func_sign: String,
    pub block_number: u64,
    pub caller: String,
    pub caller_func_sign: String,
    pub call_site: String,
    pub level: i32,
}

impl AnalysisSource {
    /// Create a new analysis source from configuration
    pub fn from_config(config: &Config, func_sign: String) -> Self {
        Self {
            platform: config.platform.clone(),
            logic_addr: config.logic_address.clone(),
            storage_addr: config.storage_address.clone(),
            func_sign,
            block_number: config.block_number,
            caller: defaults::CALLER.to_string(),
            caller_func_sign: String::new(),
            call_site: String::new(),
            level: defaults::LEVEL,
        }
    }

    /// Create a source for createbin analysis
    pub fn for_createbin(config: &Config) -> Self {
        Self::from_config(config, defaults::CREATEBIN_FUNC_SELECTOR.to_string())
    }
}