//! # Container Runtime Module
//!
//! This module provides the master control loop and runtime context for the container runtime.
//! It manages the overall lifecycle of the runtime and coordinates between different components.

use crate::lifecycle;
use crate::metrics;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Maximum number of containers
    pub max_containers: usize,
    /// Default resource limits
    pub default_resource_limits: crate::dna::ResourceLimits,
    /// Default trusted issuers
    pub default_trusted_issuers: Vec<String>,
    /// Default minimum entropy
    pub default_minimum_entropy: f64,
    /// Default execution mode
    pub default_exec_mode: crate::contract::zta::ExecMode,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable tracing
    pub enable_tracing: bool,
    /// Enable hot reload
    pub enable_hot_reload: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_containers: 100,
            default_resource_limits: crate::dna::ResourceLimits::default(),
            default_trusted_issuers: vec!["system".to_string()],
            default_minimum_entropy: 0.5,
            default_exec_mode: crate::contract::zta::ExecMode::Restricted,
            enable_metrics: true,
            enable_tracing: true,
            enable_hot_reload: false,
        }
    }
}

/// Runtime statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStats {
    /// Number of containers
    pub container_count: usize,
    /// Number of running containers
    pub running_container_count: usize,
    /// Number of paused containers
    pub paused_container_count: usize,
    /// Number of failed containers
    pub failed_container_count: usize,
    /// Runtime uptime in seconds
    pub uptime_seconds: u64,
    /// Start time in seconds since epoch
    pub start_time: u64,
    /// Last update time in seconds since epoch
    pub last_update_time: u64,
}

/// Runtime context
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    /// Runtime configuration
    config: Arc<RwLock<RuntimeConfig>>,
    /// Runtime statistics
    stats: Arc<RwLock<RuntimeStats>>,
    /// Runtime state
    running: Arc<RwLock<bool>>,
}

impl RuntimeContext {
    /// Create a new runtime context
    pub fn new(config: RuntimeConfig) -> Self {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stats = RuntimeStats {
            container_count: 0,
            running_container_count: 0,
            paused_container_count: 0,
            failed_container_count: 0,
            uptime_seconds: 0,
            start_time,
            last_update_time: start_time,
        };

        Self {
            config: Arc::new(RwLock::new(config)),
            stats: Arc::new(RwLock::new(stats)),
            running: Arc::new(RwLock::new(true)),
        }
    }

    /// Get the runtime configuration
    pub fn config(&self) -> Result<RuntimeConfig> {
        let config = self
            .config
            .read()
            .map_err(|_| ForgeError::InternalError("runtime_config lock poisoned".to_string()))?;

        Ok(config.clone())
    }

    /// Update the runtime configuration
    pub fn update_config(&self, config: RuntimeConfig) -> Result<()> {
        let mut current_config = self
            .config
            .write()
            .map_err(|_| ForgeError::InternalError("runtime_config lock poisoned".to_string()))?;

        *current_config = config;

        Ok(())
    }

    /// Get the runtime statistics
    pub fn stats(&self) -> Result<RuntimeStats> {
        let stats = self
            .stats
            .read()
            .map_err(|_| ForgeError::InternalError("runtime_stats lock poisoned".to_string()))?;

        Ok(stats.clone())
    }

    /// Update the runtime statistics
    pub fn update_stats(&self) -> Result<()> {
        let mut stats = self
            .stats
            .write()
            .map_err(|_| ForgeError::InternalError("runtime_stats lock poisoned".to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        stats.uptime_seconds = now - stats.start_time;
        stats.last_update_time = now;

        // TODO: Update container counts

        Ok(())
    }

    /// Check if the runtime is running
    pub fn is_running(&self) -> Result<bool> {
        let running = self
            .running
            .read()
            .map_err(|_| ForgeError::InternalError("runtime_running lock poisoned".to_string()))?;

        Ok(*running)
    }

    /// Stop the runtime
    pub fn stop(&self) -> Result<()> {
        let mut running = self
            .running
            .write()
            .map_err(|_| ForgeError::InternalError("runtime_running lock poisoned".to_string()))?;

        *running = false;

        Ok(())
    }

    /// Start the runtime
    pub fn start(&self) -> Result<()> {
        let mut running = self
            .running
            .write()
            .map_err(|_| ForgeError::InternalError("runtime_running lock poisoned".to_string()))?;

        *running = true;

        Ok(())
    }

    /// Run the runtime main loop
    pub fn run(&self) -> Result<()> {
        while self.is_running()? {
            // Update runtime statistics
            self.update_stats()?;

            // Sleep for a short duration
            std::thread::sleep(Duration::from_secs(1));
        }

        Ok(())
    }
}

/// Global runtime context instance
static mut RUNTIME_CONTEXT: Option<RuntimeContext> = None;

/// Initialize the runtime
pub fn init() -> Result<RuntimeContext> {
    init_with_config(&RuntimeConfig::default())
}

/// Initialize the runtime with custom configuration
pub fn init_with_config(config: &RuntimeConfig) -> Result<RuntimeContext> {
    let span = ExecutionSpan::new("init_runtime", common::identity::IdentityContext::system());

    // Initialize lifecycle manager
    lifecycle::init()?;

    // Create runtime context
    let context = RuntimeContext::new(config.clone());

    // Store the runtime context
    unsafe {
        if RUNTIME_CONTEXT.is_none() {
            RUNTIME_CONTEXT = Some(context.clone());
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "runtime_context".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(context)
}

/// Get the runtime context
pub fn get_runtime_context() -> Result<&'static RuntimeContext> {
    unsafe {
        match &RUNTIME_CONTEXT {
            Some(context) => Ok(context),
            None => Err(ForgeError::InternalError(
                "runtime_context not initialized".to_string(),
            )),
        }
    }
}

/// Shutdown the runtime
pub fn shutdown() -> Result<()> {
    let span = ExecutionSpan::new(
        "shutdown_runtime",
        common::identity::IdentityContext::system(),
    );

    // Get the runtime context
    let context = get_runtime_context()?;

    // Stop the runtime
    context.stop()?;

    // Clear the runtime context
    unsafe {
        RUNTIME_CONTEXT = None;
    }

    Ok(())
}

/// Load runtime configuration from a file
pub fn load_config(config_path: &str) -> Result<RuntimeConfig> {
    let span = ExecutionSpan::new(
        "load_runtime_config",
        common::identity::IdentityContext::system(),
    );

    // Load configuration from file
    let config_str = std::fs::read_to_string(config_path)
        .map_err(|e| ForgeError::IoError(format!("read {}: {}", config_path, e)))?;

    // Parse configuration
    let config: RuntimeConfig = serde_json::from_str(&config_str)
        .map_err(|e| ForgeError::InternalError(format!("json parse error: {}", e)))?;

    Ok(config)
}

/// Save runtime configuration to a file
pub fn save_config(config: &RuntimeConfig, config_path: &str) -> Result<()> {
    let span = ExecutionSpan::new(
        "save_runtime_config",
        common::identity::IdentityContext::system(),
    );

    // Serialize configuration
    let config_str = serde_json::to_string_pretty(config)
        .map_err(|e| ForgeError::InternalError(format!("json serialize error: {}", e)))?;

    // Save configuration to file
    std::fs::write(config_path, config_str)
        .map_err(|e| ForgeError::IoError(format!("write {}: {}", config_path, e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_context() {
        let config = RuntimeConfig::default();
        let context = RuntimeContext::new(config.clone());

        // Check initial state
        assert!(context.is_running().unwrap());

        // Get configuration
        let retrieved_config = context.config().unwrap();
        assert_eq!(retrieved_config.max_containers, config.max_containers);

        // Update configuration
        let mut new_config = config.clone();
        new_config.max_containers = 200;
        context.update_config(new_config.clone()).unwrap();

        // Check updated configuration
        let retrieved_config = context.config().unwrap();
        assert_eq!(retrieved_config.max_containers, 200);

        // Get statistics
        let stats = context.stats().unwrap();
        assert_eq!(stats.container_count, 0);

        // Update statistics
        context.update_stats().unwrap();

        // Stop the runtime
        context.stop().unwrap();
        assert!(!context.is_running().unwrap());

        // Start the runtime
        context.start().unwrap();
        assert!(context.is_running().unwrap());
    }
}
