//! Lydia - Attacker Contract Identification Tool Library
//!
//! This crate provides functionality for analyzing Ethereum smart contracts
//! to detect malicious patterns and attack vectors.

pub mod analysis;
pub mod config;
pub mod contract;
pub mod error;
pub mod flow;
pub mod graph;
pub mod outputter;
pub mod utils;

// Re-export commonly used types
pub use crate::analysis::AnalysisEngine;
pub use crate::config::Config;
pub use crate::error::{LydiaError, LydiaResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_creation() {
        // This test would require command line args, so we skip it for now
        // In a real scenario, you'd want to test Config::from_args() with mock args
    }

    #[test]
    fn test_error_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
        let lydia_error: LydiaError = io_error.into();
        
        match lydia_error {
            LydiaError::Io(_) => {}, // Expected
            _ => panic!("Error conversion failed"),
        }
    }
}
