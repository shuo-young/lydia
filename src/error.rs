//! Error handling module for Lydia
//! 
//! This module provides centralized error handling for the application.

use std::error::Error;
use std::fmt;

/// Main error type for the Lydia application
#[derive(Debug)]
pub enum LydiaError {
    /// Configuration-related errors
    Config(crate::config::ConfigError),
    /// Contract analysis errors
    ContractAnalysis(String),
    /// Call graph construction errors
    CallGraphConstruction(String),
    /// Flow analysis errors
    FlowAnalysis(String),
    /// I/O errors
    Io(std::io::Error),
    /// JSON serialization errors
    Json(serde_json::Error),
    /// Network/Web3 errors
    Network(String),
    /// General application errors
    General(String),
}

impl fmt::Display for LydiaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LydiaError::Config(err) => write!(f, "Configuration error: {}", err),
            LydiaError::ContractAnalysis(msg) => write!(f, "Contract analysis error: {}", msg),
            LydiaError::CallGraphConstruction(msg) => write!(f, "Call graph construction error: {}", msg),
            LydiaError::FlowAnalysis(msg) => write!(f, "Flow analysis error: {}", msg),
            LydiaError::Io(err) => write!(f, "I/O error: {}", err),
            LydiaError::Json(err) => write!(f, "JSON error: {}", err),
            LydiaError::Network(msg) => write!(f, "Network error: {}", msg),
            LydiaError::General(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl Error for LydiaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            LydiaError::Config(err) => Some(err),
            LydiaError::Io(err) => Some(err),
            LydiaError::Json(err) => Some(err),
            _ => None,
        }
    }
}

impl From<crate::config::ConfigError> for LydiaError {
    fn from(err: crate::config::ConfigError) -> Self {
        LydiaError::Config(err)
    }
}

impl From<std::io::Error> for LydiaError {
    fn from(err: std::io::Error) -> Self {
        LydiaError::Io(err)
    }
}

impl From<serde_json::Error> for LydiaError {
    fn from(err: serde_json::Error) -> Self {
        LydiaError::Json(err)
    }
}

/// Result type alias for the Lydia application
pub type LydiaResult<T> = Result<T, LydiaError>;

/// Helper macro for creating general errors
#[macro_export]
macro_rules! lydia_error {
    ($msg:expr) => {
        crate::error::LydiaError::General($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        crate::error::LydiaError::General(format!($fmt, $($arg)*))
    };
}