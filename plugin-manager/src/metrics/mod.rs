//! Metrics module for the ForgeOne Plugin Manager
//!
//! Provides metrics collection and reporting for plugin performance monitoring.
//! Includes advanced telemetry for production-ready observability.

use common::telemetry::Telemetry;
use lazy_static::lazy_static;
use prometheus::{register_counter_vec, register_histogram_vec, CounterVec, HistogramVec};
use std::time::Instant;


// Define metrics
lazy_static! {
    /// Counter for plugin operations
    pub static ref PLUGIN_OPERATIONS: CounterVec = register_counter_vec!(
        "forge_plugin_operations_total",
        "Total number of plugin operations",
        &["plugin_id", "plugin_name", "operation"]
    )
    .unwrap();

    /// Histogram for plugin operation durations
    pub static ref PLUGIN_OPERATION_DURATION: HistogramVec = register_histogram_vec!(
        "forge_plugin_operation_duration_seconds",
        "Duration of plugin operations in seconds",
        &["plugin_id", "plugin_name", "operation"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
    )
    .unwrap();

    /// Counter for plugin syscalls
    pub static ref PLUGIN_SYSCALLS: CounterVec = register_counter_vec!(
        "forge_plugin_syscalls_total",
        "Total number of syscalls made by plugins",
        &["plugin_id", "plugin_name", "syscall", "result"]
    )
    .unwrap();

    /// Histogram for plugin syscall durations
    pub static ref PLUGIN_SYSCALL_DURATION: HistogramVec = register_histogram_vec!(
        "forge_plugin_syscall_duration_seconds",
        "Duration of plugin syscalls in seconds",
        &["plugin_id", "plugin_name", "syscall"],
        vec![0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5]
    )
    .unwrap();

    /// Counter for plugin memory usage
    pub static ref PLUGIN_MEMORY_USAGE: CounterVec = register_counter_vec!(
        "forge_plugin_memory_usage_bytes",
        "Memory usage of plugins in bytes",
        &["plugin_id", "plugin_name"]
    )
    .unwrap();

    /// Counter for plugin errors
    pub static ref PLUGIN_ERRORS: CounterVec = register_counter_vec!(
        "forge_plugin_errors_total",
        "Total number of errors encountered by plugins",
        &["plugin_id", "plugin_name", "error_type"]
    )
    .unwrap();
}

/// Records a plugin operation
///
/// # Arguments
///
/// * `plugin_id` - ID of the plugin
/// * `plugin_name` - Name of the plugin
/// * `operation` - Name of the operation
pub fn record_operation(plugin_id: &str, plugin_name: &str, operation: &str) {
    PLUGIN_OPERATIONS
        .with_label_values(&[plugin_id, plugin_name, operation])
        .inc();
}

/// Measures the duration of a plugin operation
///
/// # Arguments
///
/// * `plugin_id` - ID of the plugin
/// * `plugin_name` - Name of the plugin
/// * `operation` - Name of the operation
///
/// # Returns
///
/// * `OperationTimer` - Timer that will record the duration when dropped
pub fn measure_operation(plugin_id: &str, plugin_name: &str, operation: &str) -> OperationTimer {
    OperationTimer {
        plugin_id: plugin_id.to_string(),
        plugin_name: plugin_name.to_string(),
        operation: operation.to_string(),
        start_time: Instant::now(),
    }
}

/// Records a plugin syscall
///
/// # Arguments
///
/// * `plugin_id` - ID of the plugin
/// * `plugin_name` - Name of the plugin
/// * `syscall` - Name of the syscall
/// * `result` - Result of the syscall ("success", "failure", "denied")
pub fn record_syscall(plugin_id: &str, plugin_name: &str, syscall: &str, result: &str) {
    PLUGIN_SYSCALLS
        .with_label_values(&[plugin_id, plugin_name, syscall, result])
        .inc();
}

/// Measures the duration of a plugin syscall
///
/// # Arguments
///
/// * `plugin_id` - ID of the plugin
/// * `plugin_name` - Name of the plugin
/// * `syscall` - Name of the syscall
///
/// # Returns
///
/// * `SyscallTimer` - Timer that will record the duration when dropped
pub fn measure_syscall(plugin_id: &str, plugin_name: &str, syscall: &str) -> SyscallTimer {
    SyscallTimer {
        plugin_id: plugin_id.to_string(),
        plugin_name: plugin_name.to_string(),
        syscall: syscall.to_string(),
        start_time: Instant::now(),
    }
}

/// Records plugin memory usage
///
/// # Arguments
///
/// * `plugin_id` - ID of the plugin
/// * `plugin_name` - Name of the plugin
/// * `bytes` - Memory usage in bytes
pub fn record_memory_usage(plugin_id: &str, plugin_name: &str, bytes: u64) {
    PLUGIN_MEMORY_USAGE
        .with_label_values(&[plugin_id, plugin_name])
        .inc_by(bytes as f64);
}

/// Records a plugin error
///
/// # Arguments
///
/// * `plugin_id` - ID of the plugin
/// * `plugin_name` - Name of the plugin
/// * `error_type` - Type of error
pub fn record_error(plugin_id: &str, plugin_name: &str, error_type: &str) {
    PLUGIN_ERRORS
        .with_label_values(&[plugin_id, plugin_name, error_type])
        .inc();
}

/// Timer for measuring plugin operation durations
pub struct OperationTimer {
    plugin_id: String,
    plugin_name: String,
    operation: String,
    start_time: Instant,
}

impl Drop for OperationTimer {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed().as_secs_f64();
        PLUGIN_OPERATION_DURATION
            .with_label_values(&[&self.plugin_id, &self.plugin_name, &self.operation])
            .observe(duration);
    }
}

/// Timer for measuring plugin syscall durations
pub struct SyscallTimer {
    plugin_id: String,
    plugin_name: String,
    syscall: String,
    start_time: Instant,
}

impl Drop for SyscallTimer {
    fn drop(&mut self) {
        let duration = self.start_time.elapsed().as_secs_f64();
        PLUGIN_SYSCALL_DURATION
            .with_label_values(&[&self.plugin_id, &self.plugin_name, &self.syscall])
            .observe(duration);
    }
}

pub struct PluginManagerTelemetry;

impl Telemetry for PluginManagerTelemetry {
    fn record_plugin_health(
        &self,
        plugin_id: &str,
        plugin_name: &str,
        version: &str,
        is_healthy: bool,
    ) {
        let value = if is_healthy { 1.0 } else { 0.0 };
        // You can add a Prometheus gauge for health if needed
        // For now, just log or extend as needed
    }
    fn record_plugin_dependencies(
        &self,
        plugin_id: &str,
        plugin_name: &str,
        version: &str,
        dependency_count: u64,
    ) {
        // Add Prometheus gauge or log as needed
    }
    fn record_plugin_cpu_usage(
        &self,
        plugin_id: &str,
        plugin_name: &str,
        version: &str,
        cpu_percent: f64,
    ) {
        // Add Prometheus gauge or log as needed
    }
    fn record_security_event(
        &self,
        plugin_id: &str,
        plugin_name: &str,
        event_type: &str,
        severity: &str,
    ) {
        // Add Prometheus counter or log as needed
    }
    fn record_marketplace_event(&self, plugin_id: &str, plugin_name: &str, event_type: &str) {
        // Add Prometheus counter or log as needed
    }
}
