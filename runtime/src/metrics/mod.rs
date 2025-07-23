//! # Container Metrics Module
//!
//! This module provides functionality for collecting, storing, and retrieving
//! metrics related to container performance and resource usage.

use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Container resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU usage in percentage
    pub cpu_percentage: f32,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// Disk read bytes
    pub disk_read_bytes: u64,
    /// Disk write bytes
    pub disk_write_bytes: u64,
    /// Network received bytes
    pub network_rx_bytes: u64,
    /// Network transmitted bytes
    pub network_tx_bytes: u64,
    /// Timestamp in seconds since epoch
    pub timestamp: u64,
}

impl ResourceUsage {
    /// Create a new resource usage with default values
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            cpu_percentage: 0.0,
            memory_bytes: 0,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            network_rx_bytes: 0,
            network_tx_bytes: 0,
            timestamp,
        }
    }
}

impl Default for ResourceUsage {
    fn default() -> Self {
        Self::new()
    }
}

/// Container metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerMetrics {
    /// Container ID
    pub container_id: String,
    /// Current resource usage
    pub current_usage: ResourceUsage,
    /// Peak resource usage
    pub peak_usage: ResourceUsage,
    /// Total CPU time in seconds
    pub total_cpu_time_seconds: f64,
    /// Total memory usage in byte-seconds
    pub total_memory_byte_seconds: u64,
    /// Total disk read bytes
    pub total_disk_read_bytes: u64,
    /// Total disk write bytes
    pub total_disk_write_bytes: u64,
    /// Total network received bytes
    pub total_network_rx_bytes: u64,
    /// Total network transmitted bytes
    pub total_network_tx_bytes: u64,
    /// Start time in seconds since epoch
    pub start_time: u64,
    /// Last update time in seconds since epoch
    pub last_update_time: u64,
    /// Historical usage samples
    pub history: Vec<ResourceUsage>,
    /// Maximum history size
    pub max_history_size: usize,
}

impl ContainerMetrics {
    /// Create new container metrics
    pub fn new(container_id: &str) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            container_id: container_id.to_string(),
            current_usage: ResourceUsage::new(),
            peak_usage: ResourceUsage::new(),
            total_cpu_time_seconds: 0.0,
            total_memory_byte_seconds: 0,
            total_disk_read_bytes: 0,
            total_disk_write_bytes: 0,
            total_network_rx_bytes: 0,
            total_network_tx_bytes: 0,
            start_time: timestamp,
            last_update_time: timestamp,
            history: Vec::new(),
            max_history_size: 100,
        }
    }

    /// Update metrics with new resource usage
    pub fn update(&mut self, usage: ResourceUsage) {
        // Calculate time delta since last update
        let now = usage.timestamp;
        let time_delta = now.saturating_sub(self.last_update_time) as f64;

        // Update current usage
        self.current_usage = usage.clone();

        // Update peak usage
        self.peak_usage.cpu_percentage = self.peak_usage.cpu_percentage.max(usage.cpu_percentage);
        self.peak_usage.memory_bytes = self.peak_usage.memory_bytes.max(usage.memory_bytes);
        self.peak_usage.disk_read_bytes = self.peak_usage.disk_read_bytes.max(usage.disk_read_bytes);
        self.peak_usage.disk_write_bytes = self.peak_usage.disk_write_bytes.max(usage.disk_write_bytes);
        self.peak_usage.network_rx_bytes = self.peak_usage.network_rx_bytes.max(usage.network_rx_bytes);
        self.peak_usage.network_tx_bytes = self.peak_usage.network_tx_bytes.max(usage.network_tx_bytes);

        // Update totals
        self.total_cpu_time_seconds += (usage.cpu_percentage / 100.0) as f64 * time_delta;
        self.total_memory_byte_seconds += usage.memory_bytes * time_delta as u64;
        self.total_disk_read_bytes = usage.disk_read_bytes;
        self.total_disk_write_bytes = usage.disk_write_bytes;
        self.total_network_rx_bytes = usage.network_rx_bytes;
        self.total_network_tx_bytes = usage.network_tx_bytes;

        // Update last update time
        self.last_update_time = now;

        // Add to history
        self.history.push(usage);

        // Trim history if needed
        if self.history.len() > self.max_history_size {
            self.history.remove(0);
        }
    }

    /// Get the average CPU usage over the container's lifetime
    pub fn average_cpu_percentage(&self) -> f32 {
        if self.last_update_time <= self.start_time {
            return 0.0;
        }

        let lifetime_seconds = self.last_update_time - self.start_time;
        if lifetime_seconds == 0 {
            return 0.0;
        }

        (self.total_cpu_time_seconds * 100.0 / lifetime_seconds as f64) as f32
    }

    /// Get the average memory usage over the container's lifetime
    pub fn average_memory_bytes(&self) -> u64 {
        if self.last_update_time <= self.start_time {
            return 0;
        }

        let lifetime_seconds = self.last_update_time - self.start_time;
        if lifetime_seconds == 0 {
            return 0;
        }

        self.total_memory_byte_seconds / lifetime_seconds
    }

    /// Reset the metrics
    pub fn reset(&mut self) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.current_usage = ResourceUsage::new();
        self.peak_usage = ResourceUsage::new();
        self.total_cpu_time_seconds = 0.0;
        self.total_memory_byte_seconds = 0;
        self.total_disk_read_bytes = 0;
        self.total_disk_write_bytes = 0;
        self.total_network_rx_bytes = 0;
        self.total_network_tx_bytes = 0;
        self.start_time = timestamp;
        self.last_update_time = timestamp;
        self.history.clear();
    }
}

/// Runtime metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeMetrics {
    /// Number of containers
    pub container_count: usize,
    /// Number of running containers
    pub running_container_count: usize,
    /// Number of paused containers
    pub paused_container_count: usize,
    /// Number of failed containers
    pub failed_container_count: usize,
    /// Total CPU usage in percentage
    pub total_cpu_percentage: f32,
    /// Total memory usage in bytes
    pub total_memory_bytes: u64,
    /// Total disk read bytes
    pub total_disk_read_bytes: u64,
    /// Total disk write bytes
    pub total_disk_write_bytes: u64,
    /// Total network received bytes
    pub total_network_rx_bytes: u64,
    /// Total network transmitted bytes
    pub total_network_tx_bytes: u64,
    /// Start time in seconds since epoch
    pub start_time: u64,
    /// Last update time in seconds since epoch
    pub last_update_time: u64,
}

impl RuntimeMetrics {
    /// Create new runtime metrics
    pub fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            container_count: 0,
            running_container_count: 0,
            paused_container_count: 0,
            failed_container_count: 0,
            total_cpu_percentage: 0.0,
            total_memory_bytes: 0,
            total_disk_read_bytes: 0,
            total_disk_write_bytes: 0,
            total_network_rx_bytes: 0,
            total_network_tx_bytes: 0,
            start_time: timestamp,
            last_update_time: timestamp,
        }
    }
}

impl Default for RuntimeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics manager
#[derive(Debug)]
pub struct MetricsManager {
    /// Container metrics
    container_metrics: Arc<RwLock<HashMap<String, ContainerMetrics>>>,
    /// Runtime metrics
    runtime_metrics: Arc<RwLock<RuntimeMetrics>>,
}

impl MetricsManager {
    /// Create a new metrics manager
    pub fn new() -> Self {
        Self {
            container_metrics: Arc::new(RwLock::new(HashMap::new())),
            runtime_metrics: Arc::new(RwLock::new(RuntimeMetrics::new())),
        }
    }

    /// Register a container for metrics collection
    pub fn register_container(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "register_container_metrics",
            common::identity::IdentityContext::system(),
        );

        let mut container_metrics = self.container_metrics.write().map_err(|_| ForgeError::LockError {
            resource: "container_metrics".to_string(),
        })?;

        // Check if container is already registered
        if container_metrics.contains_key(container_id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "container_metrics".to_string(),
                id: container_id.to_string(),
            });
        }

        // Create new container metrics
        let metrics = ContainerMetrics::new(container_id);
        container_metrics.insert(container_id.to_string(), metrics);

        // Update runtime metrics
        let mut runtime_metrics = self.runtime_metrics.write().map_err(|_| ForgeError::LockError {
            resource: "runtime_metrics".to_string(),
        })?;

        runtime_metrics.container_count += 1;

        Ok(())
    }

    /// Unregister a container
    pub fn unregister_container(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unregister_container_metrics",
            common::identity::IdentityContext::system(),
        );

        let mut container_metrics = self.container_metrics.write().map_err(|_| ForgeError::LockError {
            resource: "container_metrics".to_string(),
        })?;

        // Check if container is registered
        if !container_metrics.contains_key(container_id) {
            return Err(ForgeError::NotFoundError {
                resource: "container_metrics".to_string(),
                id: container_id.to_string(),
            });
        }

        // Remove container metrics
        container_metrics.remove(container_id);

        // Update runtime metrics
        let mut runtime_metrics = self.runtime_metrics.write().map_err(|_| ForgeError::LockError {
            resource: "runtime_metrics".to_string(),
        })?;

        runtime_metrics.container_count -= 1;

        Ok(())
    }

    /// Update container metrics
    pub fn update_container_metrics(
        &self,
        container_id: &str,
        usage: ResourceUsage,
    ) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_container_metrics",
            common::identity::IdentityContext::system(),
        );

        let mut container_metrics = self.container_metrics.write().map_err(|_| ForgeError::LockError {
            resource: "container_metrics".to_string(),
        })?;

        // Check if container is registered
        let metrics = container_metrics.get_mut(container_id).ok_or(ForgeError::NotFoundError {
            resource: "container_metrics".to_string(),
            id: container_id.to_string(),
        })?;

        // Update container metrics
        metrics.update(usage.clone());

        // Update runtime metrics
        self.update_runtime_metrics()?;

        Ok(())
    }

    /// Get container metrics
    pub fn get_container_metrics(&self, container_id: &str) -> Result<ContainerMetrics> {
        let span = ExecutionSpan::new(
            "get_container_metrics",
            common::identity::IdentityContext::system(),
        );

        let container_metrics = self.container_metrics.read().map_err(|_| ForgeError::LockError {
            resource: "container_metrics".to_string(),
        })?;

        // Check if container is registered
        let metrics = container_metrics.get(container_id).ok_or(ForgeError::NotFoundError {
            resource: "container_metrics".to_string(),
            id: container_id.to_string(),
        })?;

        Ok(metrics.clone())
    }

    /// Get runtime metrics
    pub fn get_runtime_metrics(&self) -> Result<RuntimeMetrics> {
        let span = ExecutionSpan::new(
            "get_runtime_metrics",
            common::identity::IdentityContext::system(),
        );

        let runtime_metrics = self.runtime_metrics.read().map_err(|_| ForgeError::LockError {
            resource: "runtime_metrics".to_string(),
        })?;

        Ok(runtime_metrics.clone())
    }

    /// Update runtime metrics
    fn update_runtime_metrics(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_runtime_metrics",
            common::identity::IdentityContext::system(),
        );

        let container_metrics = self.container_metrics.read().map_err(|_| ForgeError::LockError {
            resource: "container_metrics".to_string(),
        })?;

        let mut runtime_metrics = self.runtime_metrics.write().map_err(|_| ForgeError::LockError {
            resource: "runtime_metrics".to_string(),
        })?;

        // Update runtime metrics based on container metrics
        let mut total_cpu_percentage = 0.0;
        let mut total_memory_bytes = 0;
        let mut total_disk_read_bytes = 0;
        let mut total_disk_write_bytes = 0;
        let mut total_network_rx_bytes = 0;
        let mut total_network_tx_bytes = 0;

        for metrics in container_metrics.values() {
            total_cpu_percentage += metrics.current_usage.cpu_percentage;
            total_memory_bytes += metrics.current_usage.memory_bytes;
            total_disk_read_bytes += metrics.current_usage.disk_read_bytes;
            total_disk_write_bytes += metrics.current_usage.disk_write_bytes;
            total_network_rx_bytes += metrics.current_usage.network_rx_bytes;
            total_network_tx_bytes += metrics.current_usage.network_tx_bytes;
        }

        runtime_metrics.total_cpu_percentage = total_cpu_percentage;
        runtime_metrics.total_memory_bytes = total_memory_bytes;
        runtime_metrics.total_disk_read_bytes = total_disk_read_bytes;
        runtime_metrics.total_disk_write_bytes = total_disk_write_bytes;
        runtime_metrics.total_network_rx_bytes = total_network_rx_bytes;
        runtime_metrics.total_network_tx_bytes = total_network_tx_bytes;

        // Update last update time
        runtime_metrics.last_update_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }
}

/// Global metrics manager instance
static mut METRICS_MANAGER: Option<MetricsManager> = None;

/// Initialize the metrics manager
pub fn init() -> Result<()> {
    let span = ExecutionSpan::new(
        "init_metrics_manager",
        common::identity::IdentityContext::system(),
    );

    // Create metrics manager
    let manager = MetricsManager::new();

    // Store the metrics manager
    unsafe {
        if METRICS_MANAGER.is_none() {
            METRICS_MANAGER = Some(manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "metrics_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the metrics manager
pub fn get_metrics_manager() -> Result<&'static MetricsManager> {
    unsafe {
        match &METRICS_MANAGER {
            Some(manager) => Ok(manager),
            None => Err(ForgeError::UninitializedError {
                component: "metrics_manager".to_string(),
            }),
        }
    }
}

/// Register a container for metrics collection
pub fn register_container(container_id: &str) -> Result<()> {
    let manager = get_metrics_manager()?;
    manager.register_container(container_id)
}

/// Unregister a container
pub fn unregister_container(container_id: &str) -> Result<()> {
    let manager = get_metrics_manager()?;
    manager.unregister_container(container_id)
}

/// Update container metrics
pub fn update_container_metrics(container_id: &str, usage: ResourceUsage) -> Result<()> {
    let manager = get_metrics_manager()?;
    manager.update_container_metrics(container_id, usage)
}

/// Get container metrics
pub fn get_container_metrics(container_id: &str) -> Result<ContainerMetrics> {
    let manager = get_metrics_manager()?;
    manager.get_container_metrics(container_id)
}

/// Get runtime metrics
pub fn get_runtime_metrics() -> Result<RuntimeMetrics> {
    let manager = get_metrics_manager()?;
    manager.get_runtime_metrics()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_usage() {
        let usage = ResourceUsage::new();
        assert_eq!(usage.cpu_percentage, 0.0);
        assert_eq!(usage.memory_bytes, 0);
    }

    #[test]
    fn test_container_metrics() {
        let mut metrics = ContainerMetrics::new("test-container");

        // Check initial values
        assert_eq!(metrics.container_id, "test-container");
        assert_eq!(metrics.current_usage.cpu_percentage, 0.0);
        assert_eq!(metrics.peak_usage.memory_bytes, 0);
        assert_eq!(metrics.history.len(), 0);

        // Create resource usage
        let mut usage = ResourceUsage::new();
        usage.cpu_percentage = 10.0;
        usage.memory_bytes = 1024 * 1024; // 1 MB

        // Update metrics
        metrics.update(usage);

        // Check updated values
        assert_eq!(metrics.current_usage.cpu_percentage, 10.0);
        assert_eq!(metrics.current_usage.memory_bytes, 1024 * 1024);
        assert_eq!(metrics.peak_usage.cpu_percentage, 10.0);
        assert_eq!(metrics.peak_usage.memory_bytes, 1024 * 1024);
        assert_eq!(metrics.history.len(), 1);

        // Create another resource usage with higher values
        let mut usage2 = ResourceUsage::new();
        usage2.cpu_percentage = 20.0;
        usage2.memory_bytes = 2 * 1024 * 1024; // 2 MB

        // Update metrics again
        metrics.update(usage2);

        // Check updated values
        assert_eq!(metrics.current_usage.cpu_percentage, 20.0);
        assert_eq!(metrics.current_usage.memory_bytes, 2 * 1024 * 1024);
        assert_eq!(metrics.peak_usage.cpu_percentage, 20.0);
        assert_eq!(metrics.peak_usage.memory_bytes, 2 * 1024 * 1024);
        assert_eq!(metrics.history.len(), 2);

        // Reset metrics
        metrics.reset();

        // Check reset values
        assert_eq!(metrics.current_usage.cpu_percentage, 0.0);
        assert_eq!(metrics.current_usage.memory_bytes, 0);
        assert_eq!(metrics.peak_usage.cpu_percentage, 0.0);
        assert_eq!(metrics.peak_usage.memory_bytes, 0);
        assert_eq!(metrics.history.len(), 0);
    }

    #[test]
    fn test_metrics_manager() {
        // Initialize metrics manager
        init().unwrap();
        let manager = get_metrics_manager().unwrap();

        // Register container
        manager.register_container("test-container").unwrap();

        // Create resource usage
        let mut usage = ResourceUsage::new();
        usage.cpu_percentage = 10.0;
        usage.memory_bytes = 1024 * 1024; // 1 MB

        // Update container metrics
        manager
            .update_container_metrics("test-container", usage)
            .unwrap();

        // Get container metrics
        let metrics = manager.get_container_metrics("test-container").unwrap();
        assert_eq!(metrics.current_usage.cpu_percentage, 10.0);
        assert_eq!(metrics.current_usage.memory_bytes, 1024 * 1024);

        // Get runtime metrics
        let runtime_metrics = manager.get_runtime_metrics().unwrap();
        assert_eq!(runtime_metrics.container_count, 1);
        assert_eq!(runtime_metrics.total_cpu_percentage, 10.0);
        assert_eq!(runtime_metrics.total_memory_bytes, 1024 * 1024);

        // Unregister container
        manager.unregister_container("test-container").unwrap();

        // Check container is unregistered
        let result = manager.get_container_metrics("test-container");
        assert!(result.is_err());

        // Get runtime metrics again
        let runtime_metrics = manager.get_runtime_metrics().unwrap();
        assert_eq!(runtime_metrics.container_count, 0);
    }
}