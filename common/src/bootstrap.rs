//! # Bootstrap system for ForgeOne
//!
//! This module provides a trust-aware boot process for the ForgeOne platform.
//! It handles initialization of logging, configuration, and other core systems.

use std::sync::Once;
use tracing::info;
use tracing_subscriber::fmt::format::FmtSpan;
use crate::config::ForgeConfig;
use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;
use crate::db::DbOptions;

/// Global initialization state
static mut INITIALIZED: bool = false;

/// Database initialization state
static DB_INIT: Once = Once::new();

/// Initialize the common crate with default configuration
pub fn init() -> Result<()> {
    let config = ForgeConfig::default();
    init_with_config(&config)
}

/// Initialize the common crate with custom configuration
pub fn init_with_config(config: &ForgeConfig) -> Result<()> {
    // Ensure we only initialize once
    unsafe {
        if INITIALIZED {
            return Ok(());
        }
        INITIALIZED = true;
    }

    // Initialize logging
    init_logging(config)?;

    // Log initialization
    info!("ForgeOne common crate initialized");
    info!("Name: {}, Version: {}, Environment: {}", config.name, config.version, config.environment);

    // Load environment variables
    if let Err(e) = dotenvy::dotenv() {
        // Not a fatal error, just log it
        tracing::warn!("Failed to load .env file: {}", e);
    }
    
    // Initialize telemetry
    if let Err(e) = crate::telemetry::init_telemetry(None) {
        tracing::warn!("Failed to initialize telemetry: {}", e);
    }
    
    // Initialize audit system
    // To:
    if let Err(e) = crate::audit::get_audit_manager() {
        tracing::warn!("Failed to initialize audit system: {}", e);
    }

    Ok(())
}

/// Initialize logging
fn init_logging(config: &ForgeConfig) -> Result<()> {
    let log_level = match config.log_level.as_str() {
        "trace" => tracing::Level::TRACE,
        "debug" => tracing::Level::DEBUG,
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        "error" => tracing::Level::ERROR,
        _ => tracing::Level::INFO,
    };

    // Initialize tracing subscriber
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_span_events(FmtSpan::CLOSE)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|e| ForgeError::ConfigError(format!("Failed to set global tracing subscriber: {}", e)))?;

    Ok(())
}

pub async fn run_diagnostics(identity: &IdentityContext) -> Result<crate::diagnostics::DiagnosticReport> {
    crate::diagnostics::run_system_diagnostics(identity)
        .await
        .map_err(|e| ForgeError::DiagnosticError {
            message: e.to_string(),
            component: "bootstrap".to_string(), 
            error_code: "BOOTSTRAP_ERROR".to_string(), 
            details: None, 
        })
}

/// Initialize the database system
pub fn init_db(options: Option<DbOptions>) -> Result<()> {
    let mut result = Ok(());
    
    DB_INIT.call_once(|| {
        let db_options = options.unwrap_or_default();
        
        if let Err(e) = crate::db::init(db_options) {
            tracing::error!("Failed to initialize database: {}", e);
            result = Err(e);
        } else {
            info!("Database system initialized successfully");
        }
    });
    
    result
}

/// Shutdown the system
pub fn shutdown() -> Result<()> {
    // Shutdown database if initialized
    if let Err(e) = crate::db::shutdown() {
        tracing::warn!("Error during database shutdown: {}", e);
    }
    
    info!("ForgeOne common crate shutdown complete");
    
    Ok(())
}