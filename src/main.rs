//! Lydia - Attacker Contract Identification Tool
//!
//! A Rust-based tool for analyzing Ethereum smart contracts to detect
//! malicious patterns and attack vectors using the Gigahorse toolchain.

// Module declarations
mod analysis;
mod config;
mod contract;
mod error;
mod flow;
mod graph;
mod outputter;
mod utils;

// Internal imports
use crate::analysis::AnalysisEngine;
use crate::config::Config;
use crate::error::LydiaResult;
use crate::utils::{init_logging, save_results_to_file};

// External imports
use log::{error, info};

#[tokio::main]
async fn main() {
    // Initialize logging first
    init_logging();
    
    // Run the main application logic and handle any errors
    if let Err(e) = run().await {
        error!("Application error: {}", e);
        std::process::exit(1);
    }
}

/// Main application logic
async fn run() -> LydiaResult<()> {
    // Parse configuration from command line arguments
    let config = Config::from_args()?;
    config.validate()?;
    
    info!("Starting Lydia analysis...");
    info!("Logic address: {}", config.logic_address);
    info!("Storage address: {}", config.storage_address);
    info!("Platform: {}", config.platform);
    info!("Block number: {}", config.block_number);

    // Create and run the analysis engine
    let engine = AnalysisEngine::new(config.clone());
    let result = engine.analyze().await?;
    
    // Display results
    println!("{:#?}", result);
    
    // Save results to file
    save_results_to_file(&config.logic_address, result)?;
    
    info!("Analysis completed successfully!");
    Ok(())
}
