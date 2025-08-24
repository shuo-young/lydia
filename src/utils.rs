//! Utility functions and helpers for Lydia
//! 
//! This module contains common utility functions used throughout the application.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use crate::config::defaults;
use crate::error::LydiaResult;
use crate::outputter::result_structure::Result as AnalysisResult;

/// Save analysis results to a JSON file
pub fn save_results_to_file(logic_address: &str, result: AnalysisResult) -> LydiaResult<()> {
    let mut results_map: HashMap<String, AnalysisResult> = HashMap::new();
    results_map.insert(logic_address.to_string(), result);

    let serialized = serde_json::to_string_pretty(&results_map)?;
    let file_path = format!("{}{}.json", defaults::OUTPUT_DIR, logic_address);
    
    // Ensure output directory exists
    if let Some(parent) = std::path::Path::new(&file_path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    let mut file = File::create(&file_path)?;
    file.write_all(serialized.as_bytes())?;
    
    println!("Results saved to: {}", file_path);
    Ok(())
}

/// Initialize the logging system
pub fn init_logging() {
    env_logger::init();
}

/// Format duration for human-readable output
pub fn format_duration(duration: std::time::Duration) -> String {
    format!("{}.{:09} seconds", duration.as_secs(), duration.subsec_nanos())
}

/// Validate Ethereum address format
pub fn is_valid_ethereum_address(address: &str) -> bool {
    address.starts_with("0x") && address.len() == 42 && address[2..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_ethereum_address() {
        assert!(is_valid_ethereum_address("0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE8"));
        assert!(!is_valid_ethereum_address("10C509AA9ab291C76c45414e7CdBd375e1D5AcE8"));
        assert!(!is_valid_ethereum_address("0x10C509AA9ab291C76c45414e7CdBd375e1D5AcE"));
        assert!(!is_valid_ethereum_address("0xGGC509AA9ab291C76c45414e7CdBd375e1D5AcE8"));
    }

    #[test]
    fn test_format_duration() {
        let duration = std::time::Duration::new(5, 123456789);
        let formatted = format_duration(duration);
        assert_eq!(formatted, "5.123456789 seconds");
    }
}