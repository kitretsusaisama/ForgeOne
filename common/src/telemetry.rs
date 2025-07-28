//! # Telemetry system for ForgeOne
//!
//! This module provides comprehensive telemetry capabilities for the ForgeOne platform, including:
//! - Metrics collection and reporting
//! - Distributed tracing with span correlation
//! - Health monitoring and reporting
//! - Performance profiling
//! - Resource usage tracking
//! - Prometheus integration
//! - OpenTelemetry integration
//! - Structured logging with context

use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;
use crate::observer::trace::ExecutionSpan;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

/// Telemetry metric types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetricType {
    /// Counter metrics (only increase)
    Counter,
    /// Gauge metrics (can increase or decrease)
    Gauge,
    /// Histogram metrics (statistical distribution)
    Histogram,
    /// Summary metrics (percentiles)
    Summary,
}

/// Telemetry metric value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricValue {
    /// Integer value
    Integer(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// String value
    String(String),
    /// Histogram values
    Histogram(Vec<f64>),
}

/// Telemetry metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metric {
    /// Metric name
    pub name: String,
    /// Metric description
    pub description: String,
    /// Metric type
    pub metric_type: MetricType,
    /// Metric value
    pub value: MetricValue,
    /// Metric labels
    pub labels: HashMap<String, String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// System is healthy
    Healthy,
    /// System is degraded but operational
    Degraded,
    /// System is unhealthy
    Unhealthy,
}

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Component name
    pub component: String,
    /// Health status
    pub status: HealthStatus,
    /// Details about the health check
    pub details: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// System health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Overall health status
    pub status: HealthStatus,
    /// Individual component health checks
    pub checks: Vec<HealthCheckResult>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// A telemetry span for tracking operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySpan {
    /// The ID of this span
    pub span_id: Uuid,
    /// The trace ID of this span
    pub trace_id: Uuid,
    /// The parent span ID of this span
    pub parent_span_id: Option<Uuid>,
    /// The name of this span
    pub name: String,
    /// The start time of this span
    pub start_time: DateTime<Utc>,
    /// The end time of this span
    pub end_time: Option<DateTime<Utc>>,
    /// The identity context of this span
    pub identity: IdentityContext,
    /// The attributes of this span
    pub attributes: HashMap<String, String>,
    /// The events of this span
    pub events: Vec<TelemetryEvent>,
    /// Performance metrics associated with this span
    pub metrics: HashMap<String, MetricValue>,
}

/// A telemetry event for tracking operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// The name of this event
    pub name: String,
    /// The time of this event
    pub time: DateTime<Utc>,
    /// The attributes of this event
    pub attributes: HashMap<String, String>,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage in bytes
    pub memory_usage: u64,
    /// Total memory available in bytes
    pub memory_total: u64,
    /// Disk usage in bytes
    pub disk_usage: u64,
    /// Total disk space in bytes
    pub disk_total: u64,
    /// Network received bytes
    pub network_rx: u64,
    /// Network transmitted bytes
    pub network_tx: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Telemetry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Whether telemetry is enabled
    pub enabled: bool,
    /// Metrics collection interval in seconds
    pub metrics_interval: u64,
    /// Health check interval in seconds
    pub health_check_interval: u64,
    /// Resource usage collection interval in seconds
    pub resource_usage_interval: u64,
    /// Whether to enable tracing
    pub enable_tracing: bool,
    /// Whether to enable Prometheus metrics
    pub enable_prometheus: bool,
    /// Whether to enable OpenTelemetry
    pub enable_opentelemetry: bool,
    /// Prometheus endpoint
    pub prometheus_endpoint: String,
    /// OpenTelemetry endpoint
    pub opentelemetry_endpoint: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            metrics_interval: 60,
            health_check_interval: 30,
            resource_usage_interval: 60,
            enable_tracing: true,
            enable_prometheus: true,
            enable_opentelemetry: false,
            prometheus_endpoint: "/metrics".to_string(),
            opentelemetry_endpoint: "http://localhost:4317".to_string(),
        }
    }
}

impl TelemetrySpan {
    /// Create a new telemetry span
    pub fn new(name: String, identity: IdentityContext) -> Self {
        Self {
            span_id: Uuid::new_v4(),
            trace_id: identity.request_id,
            parent_span_id: None,
            name,
            start_time: Utc::now(),
            end_time: None,
            identity,
            attributes: HashMap::new(),
            events: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    /// Create a child span from this span
    pub fn create_child(&self, name: String) -> Self {
        Self {
            span_id: Uuid::new_v4(),
            trace_id: self.trace_id,
            parent_span_id: Some(self.span_id),
            name,
            start_time: Utc::now(),
            end_time: None,
            identity: self.identity.clone(),
            attributes: HashMap::new(),
            events: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    /// Add an attribute to this span
    pub fn add_attribute(&mut self, key: String, value: String) {
        self.attributes.insert(key, value);
    }

    /// Add an event to this span
    pub fn add_event(&mut self, name: String, attributes: HashMap<String, String>) {
        self.events.push(TelemetryEvent {
            name,
            time: Utc::now(),
            attributes,
        });
    }

    /// Add a metric to this span
    pub fn add_metric(&mut self, key: String, value: MetricValue) {
        self.metrics.insert(key, value);
    }

    /// End this span
    pub fn end(&mut self) {
        self.end_time = Some(Utc::now());

        // Calculate duration and add as a metric
        if let Some(end_time) = self.end_time {
            let duration = end_time
                .signed_duration_since(self.start_time)
                .num_milliseconds();
            self.add_metric("duration_ms".to_string(), MetricValue::Integer(duration));
        }
    }

    /// Log this span at info level
    pub fn log_info(&mut self, message: &str) {
        info!(
            span_id = %self.span_id,
            trace_id = %self.trace_id,
            user_id = %self.identity.user_id,
            tenant_id = %self.identity.tenant_id,
            "{}", message
        );

        let mut attrs = HashMap::new();
        attrs.insert("message".to_string(), message.to_string());
        self.add_event("INFO".to_string(), attrs);
    }

    /// Log this span at debug level
    pub fn log_debug(&mut self, message: &str) {
        debug!(
            span_id = %self.span_id,
            trace_id = %self.trace_id,
            user_id = %self.identity.user_id,
            tenant_id = %self.identity.tenant_id,
            "{}", message
        );

        let mut attrs = HashMap::new();
        attrs.insert("message".to_string(), message.to_string());
        self.add_event("DEBUG".to_string(), attrs);
    }

    /// Log this span at warn level
    pub fn log_warn(&mut self, message: &str) {
        warn!(
            span_id = %self.span_id,
            trace_id = %self.trace_id,
            user_id = %self.identity.user_id,
            tenant_id = %self.identity.tenant_id,
            "{}", message
        );

        let mut attrs = HashMap::new();
        attrs.insert("message".to_string(), message.to_string());
        self.add_event("WARN".to_string(), attrs);
    }

    /// Log this span at error level
    pub fn log_error(&mut self, message: &str) {
        error!(
            span_id = %self.span_id,
            trace_id = %self.trace_id,
            user_id = %self.identity.user_id,
            tenant_id = %self.identity.tenant_id,
            "{}", message
        );

        let mut attrs = HashMap::new();
        attrs.insert("message".to_string(), message.to_string());
        self.add_event("ERROR".to_string(), attrs);
    }

    /// Log this span at trace level
    pub fn log_trace(&mut self, message: &str) {
        trace!(
            span_id = %self.span_id,
            trace_id = %self.trace_id,
            user_id = %self.identity.user_id,
            tenant_id = %self.identity.tenant_id,
            "{}", message
        );

        let mut attrs = HashMap::new();
        attrs.insert("message".to_string(), message.to_string());
        self.add_event("TRACE".to_string(), attrs);
    }
}

/// Trait for metric collectors
pub trait MetricCollector: Send + Sync {
    /// Collect metrics
    fn collect(&self) -> Result<Vec<Metric>>;
}

/// Trait for health checkers
pub trait HealthChecker: Send + Sync {
    /// Perform health check
    fn check(&self) -> Result<HealthCheckResult>;
}

/// Telemetry manager
pub struct TelemetryManager {
    /// Telemetry configuration
    config: RwLock<TelemetryConfig>,
    /// Metric collectors
    metric_collectors: RwLock<Vec<Box<dyn MetricCollector>>>,
    /// Health checkers
    health_checkers: RwLock<Vec<Box<dyn HealthChecker>>>,
    /// Current metrics
    metrics: RwLock<Vec<Metric>>,
    /// Current health report
    health_report: RwLock<HealthReport>,
    /// Current resource usage
    resource_usage: RwLock<ResourceUsage>,
    /// Active spans
    active_spans: RwLock<HashMap<String, TelemetrySpan>>,
    /// Completed spans
    completed_spans: RwLock<Vec<TelemetrySpan>>,
}

impl TelemetryManager {
    /// Create a new telemetry manager
    pub fn new(config: TelemetryConfig) -> Self {
        Self {
            config: RwLock::new(config),
            metric_collectors: RwLock::new(Vec::new()),
            health_checkers: RwLock::new(Vec::new()),
            metrics: RwLock::new(Vec::new()),
            health_report: RwLock::new(HealthReport {
                status: HealthStatus::Healthy,
                checks: Vec::new(),
                timestamp: Utc::now(),
            }),
            resource_usage: RwLock::new(ResourceUsage {
                cpu_usage: 0.0,
                memory_usage: 0,
                memory_total: 0,
                disk_usage: 0,
                disk_total: 0,
                network_rx: 0,
                network_tx: 0,
                timestamp: Utc::now(),
            }),
            active_spans: RwLock::new(HashMap::new()),
            completed_spans: RwLock::new(Vec::new()),
        }
    }

    /// Add a metric collector
    pub fn add_metric_collector<C: MetricCollector + 'static>(&self, collector: C) {
        self.metric_collectors
            .write()
            .unwrap()
            .push(Box::new(collector));
    }

    /// Add a health checker
    pub fn add_health_checker<C: HealthChecker + 'static>(&self, checker: C) {
        self.health_checkers
            .write()
            .unwrap()
            .push(Box::new(checker));
    }

    /// Update the telemetry configuration
    pub fn update_config(&self, config: TelemetryConfig) {
        *self.config.write().unwrap() = config;
    }

    /// Get the current telemetry configuration
    pub fn config(&self) -> TelemetryConfig {
        self.config.read().unwrap().clone()
    }

    /// Collect metrics from all collectors
    pub fn collect_metrics(&self) -> Result<Vec<Metric>> {
        let collectors = self.metric_collectors.read().unwrap();
        let mut metrics = Vec::new();

        for collector in collectors.iter() {
            let collector_metrics = collector.collect()?;
            metrics.extend(collector_metrics);
        }

        // Update the current metrics
        *self.metrics.write().unwrap() = metrics.clone();

        Ok(metrics)
    }

    /// Perform health checks
    pub fn check_health(&self) -> Result<HealthReport> {
        let checkers = self.health_checkers.read().unwrap();
        let mut checks = Vec::new();

        for checker in checkers.iter() {
            let check_result = checker.check()?;
            checks.push(check_result);
        }

        // Determine overall health status
        let status = if checks.iter().any(|c| c.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if checks.iter().any(|c| c.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        let report = HealthReport {
            status,
            checks,
            timestamp: Utc::now(),
        };

        // Update the current health report
        *self.health_report.write().unwrap() = report.clone();

        Ok(report)
    }

    /// Collect resource usage
    pub fn collect_resource_usage(&self) -> Result<ResourceUsage> {
        // This is a placeholder implementation
        // In a real implementation, this would use system APIs to collect resource usage

        let usage = ResourceUsage {
            cpu_usage: 0.0,
            memory_usage: 0,
            memory_total: 0,
            disk_usage: 0,
            disk_total: 0,
            network_rx: 0,
            network_tx: 0,
            timestamp: Utc::now(),
        };

        // Update the current resource usage
        *self.resource_usage.write().unwrap() = usage.clone();

        Ok(usage)
    }

    /// Start a new trace span
    pub fn start_span(&self, name: impl Into<String>, identity: IdentityContext) -> TelemetrySpan {
        let span = TelemetrySpan::new(name.into(), identity);
        let span_id = span.span_id.to_string();

        self.active_spans
            .write()
            .unwrap()
            .insert(span_id, span.clone());

        span
    }

    /// End a trace span
    pub fn end_span(&self, span_id: &Uuid) -> Result<()> {
        let span_id_str = span_id.to_string();
        let mut spans = self.active_spans.write().unwrap();

        if let Some(mut span) = spans.remove(&span_id_str) {
            span.end();
            self.completed_spans.write().unwrap().push(span);
        }

        Ok(())
    }

    /// Get Prometheus metrics
    pub fn get_prometheus_metrics(&self) -> Result<String> {
        let config = self.config.read().unwrap();
        if !config.enabled || !config.enable_prometheus {
            return Ok(String::new());
        }

        let metrics = self.metrics.read().unwrap();
        let mut output = String::new();

        for metric in metrics.iter() {
            // Skip non-numeric metrics
            let value = match &metric.value {
                MetricValue::Integer(v) => v.to_string(),
                MetricValue::Float(v) => v.to_string(),
                _ => continue,
            };

            // Add metric type comment
            output.push_str(&format!("# HELP {} {}\n", metric.name, metric.description));

            // Add metric type
            let metric_type = match metric.metric_type {
                MetricType::Counter => "counter",
                MetricType::Gauge => "gauge",
                MetricType::Histogram => "histogram",
                MetricType::Summary => "summary",
            };
            output.push_str(&format!("# TYPE {} {}\n", metric.name, metric_type));

            // Add metric value with labels
            if metric.labels.is_empty() {
                output.push_str(&format!("{} {}\n", metric.name, value));
            } else {
                let labels = metric
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{v}\""))
                    .collect::<Vec<_>>()
                    .join(",");
                output.push_str(&format!("{}{{{} {}}}\n", metric.name, labels, value));
            }
        }

        Ok(output)
    }

    /// Get the current health report
    pub fn get_health_report(&self) -> HealthReport {
        self.health_report.read().unwrap().clone()
    }

    /// Get the current resource usage
    pub fn get_resource_usage(&self) -> ResourceUsage {
        self.resource_usage.read().unwrap().clone()
    }

    /// Get all completed spans
    pub fn get_completed_spans(&self) -> Vec<TelemetrySpan> {
        self.completed_spans.read().unwrap().clone()
    }

    /// Clear completed spans
    pub fn clear_completed_spans(&self) {
        self.completed_spans.write().unwrap().clear();
    }
}

/// System metrics collector
pub struct SystemMetricsCollector;

impl SystemMetricsCollector {
    /// Create a new system metrics collector
    pub fn new() -> Self {
        Self
    }
}

impl MetricCollector for SystemMetricsCollector {
    fn collect(&self) -> Result<Vec<Metric>> {
        // This is a placeholder implementation
        // In a real implementation, this would use system APIs to collect metrics

        let mut metrics = Vec::new();

        // Add CPU usage metric
        metrics.push(Metric {
            name: "system_cpu_usage".to_string(),
            description: "System CPU usage percentage".to_string(),
            metric_type: MetricType::Gauge,
            value: MetricValue::Float(0.0),
            labels: HashMap::new(),
            timestamp: Utc::now(),
        });

        // Add memory usage metric
        metrics.push(Metric {
            name: "system_memory_usage".to_string(),
            description: "System memory usage in bytes".to_string(),
            metric_type: MetricType::Gauge,
            value: MetricValue::Integer(0),
            labels: HashMap::new(),
            timestamp: Utc::now(),
        });

        Ok(metrics)
    }
}

/// Database health checker
pub struct DatabaseHealthChecker;

impl DatabaseHealthChecker {
    /// Create a new database health checker
    pub fn new() -> Self {
        Self
    }
}

impl HealthChecker for DatabaseHealthChecker {
    fn check(&self) -> Result<HealthCheckResult> {
        // This is a placeholder implementation
        // In a real implementation, this would check the database connection

        Ok(HealthCheckResult {
            component: "database".to_string(),
            status: HealthStatus::Healthy,
            details: Some("Database connection is healthy".to_string()),
            timestamp: Utc::now(),
        })
    }
}

/// Performance timer for measuring execution time
pub struct PerformanceTimer {
    /// Start time
    start: Instant,
    /// Name of the operation being timed
    name: String,
    /// Whether to automatically report the timing when dropped
    auto_report: bool,
}

impl PerformanceTimer {
    /// Create a new performance timer
    pub fn new(name: impl Into<String>, auto_report: bool) -> Self {
        Self {
            start: Instant::now(),
            name: name.into(),
            auto_report,
        }
    }

    /// Get the elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Report the timing
    pub fn report(&self) -> Result<()> {
        let elapsed = self.elapsed();
        let elapsed_ms = elapsed.as_millis() as f64;

        // Record the metric
        let mut labels = HashMap::new();
        labels.insert("operation".to_string(), self.name.clone());

        record_gauge(
            "operation_duration_ms",
            "Duration of an operation in milliseconds",
            elapsed_ms,
            labels,
        )?;

        debug!("Performance: {} took {:.2} ms", self.name, elapsed_ms);

        Ok(())
    }
}

impl Drop for PerformanceTimer {
    fn drop(&mut self) {
        if self.auto_report {
            let _ = self.report();
        }
    }
}

// Global telemetry manager
static TELEMETRY_MANAGER: OnceLock<Arc<TelemetryManager>> = OnceLock::new();

/// Initialize the telemetry module
pub fn init_telemetry(config: Option<TelemetryConfig>) -> Result<()> {
    let config = config.unwrap_or_default();
    let manager = Arc::new(TelemetryManager::new(config));

    // Add default collectors and checkers
    manager.add_metric_collector(SystemMetricsCollector::new());
    manager.add_health_checker(DatabaseHealthChecker::new());

    TELEMETRY_MANAGER
        .set(manager)
        .map_err(|_| ForgeError::TelemetryError("Telemetry already initialized".to_string()))?;

    Ok(())
}

/// Initialize syscall metrics (for compatibility)
pub fn init_syscall_metrics() -> crate::error::Result<()> {
    init_telemetry(None)
}

/// Get the global telemetry manager
pub fn get_telemetry_manager() -> Result<Arc<TelemetryManager>> {
    TELEMETRY_MANAGER
        .get()
        .cloned()
        .ok_or_else(|| ForgeError::TelemetryError("Telemetry module not initialized".to_string()))
}

/// Generate a new trace ID
pub fn generate_trace_id() -> Uuid {
    Uuid::new_v4()
}

/// Start a new trace span
pub fn start_span(name: impl Into<String>, identity: IdentityContext) -> Result<TelemetrySpan> {
    let manager = get_telemetry_manager()?;
    Ok(manager.start_span(name, identity))
}

/// End a trace span
pub fn end_span(span_id: &Uuid) -> Result<()> {
    let manager = get_telemetry_manager()?;
    manager.end_span(span_id)
}

/// Create a new performance timer
pub fn time_operation(name: impl Into<String>, auto_report: bool) -> PerformanceTimer {
    PerformanceTimer::new(name, auto_report)
}

/// Get Prometheus metrics
pub fn get_prometheus_metrics() -> Result<String> {
    let manager = get_telemetry_manager()?;
    manager.get_prometheus_metrics()
}

/// Check system health
pub fn check_health() -> Result<HealthReport> {
    let manager = get_telemetry_manager()?;
    manager.check_health()
}

/// Collect metrics
pub fn collect_metrics() -> Result<Vec<Metric>> {
    let manager = get_telemetry_manager()?;
    manager.collect_metrics()
}

/// Collect resource usage
pub fn collect_resource_usage() -> Result<ResourceUsage> {
    let manager = get_telemetry_manager()?;
    manager.collect_resource_usage()
}

/// Record a metric
pub fn record_metric(
    name: impl Into<String>,
    description: impl Into<String>,
    metric_type: MetricType,
    value: MetricValue,
    labels: HashMap<String, String>,
) -> Result<()> {
    let metric = Metric {
        name: name.into(),
        description: description.into(),
        metric_type,
        value,
        labels,
        timestamp: Utc::now(),
    };

    let manager = get_telemetry_manager()?;
    let mut metrics = manager.metrics.write().unwrap();

    // Update existing metric or add new one
    let mut found = false;
    for existing in metrics.iter_mut() {
        if existing.name == metric.name && existing.labels == metric.labels {
            *existing = metric.clone();
            found = true;
            break;
        }
    }

    if !found {
        metrics.push(metric);
    }

    Ok(())
}

/// Record a counter metric
pub fn record_counter(
    name: impl Into<String>,
    description: impl Into<String>,
    value: i64,
    labels: HashMap<String, String>,
) -> Result<()> {
    record_metric(
        name,
        description,
        MetricType::Counter,
        MetricValue::Integer(value),
        labels,
    )
}

/// Record a gauge metric
pub fn record_gauge(
    name: impl Into<String>,
    description: impl Into<String>,
    value: f64,
    labels: HashMap<String, String>,
) -> Result<()> {
    record_metric(
        name,
        description,
        MetricType::Gauge,
        MetricValue::Float(value),
        labels,
    )
}

/// Record a histogram metric
pub fn record_histogram(
    name: impl Into<String>,
    description: impl Into<String>,
    values: Vec<f64>,
    labels: HashMap<String, String>,
) -> Result<()> {
    record_metric(
        name,
        description,
        MetricType::Histogram,
        MetricValue::Histogram(values),
        labels,
    )
}

/// Increment a counter metric
pub fn increment_counter(
    name: impl Into<String>,
    description: impl Into<String>,
    labels: HashMap<String, String>,
) -> Result<()> {
    let name_str = name.into();
    let manager = get_telemetry_manager()?;
    let mut metrics = manager.metrics.write().unwrap();

    // Find existing metric or create new one
    let mut found = false;
    for existing in metrics.iter_mut() {
        if existing.name == name_str && existing.labels == labels {
            match &mut existing.value {
                MetricValue::Integer(v) => {
                    *v += 1;
                    found = true;
                    break;
                }
                MetricValue::Float(v) => {
                    *v += 1.0;
                    found = true;
                    break;
                }
                _ => {}
            }
        }
    }

    if !found {
        metrics.push(Metric {
            name: name_str,
            description: description.into(),
            metric_type: MetricType::Counter,
            value: MetricValue::Integer(1),
            labels,
            timestamp: Utc::now(),
        });
    }

    Ok(())
}

/// Decrement a gauge metric
pub fn decrement_gauge(
    name: impl Into<String>,
    description: impl Into<String>,
    labels: HashMap<String, String>,
) -> Result<()> {
    let name_str = name.into();
    let manager = get_telemetry_manager()?;
    let mut metrics = manager.metrics.write().unwrap();

    // Find existing metric or create new one
    let mut found = false;
    for existing in metrics.iter_mut() {
        if existing.name == name_str && existing.labels == labels {
            match &mut existing.value {
                MetricValue::Integer(v) => {
                    *v -= 1;
                    found = true;
                    break;
                }
                MetricValue::Float(v) => {
                    *v -= 1.0;
                    found = true;
                    break;
                }
                _ => {}
            }
        }
    }

    if !found {
        metrics.push(Metric {
            name: name_str,
            description: description.into(),
            metric_type: MetricType::Gauge,
            value: MetricValue::Float(-1.0),
            labels,
            timestamp: Utc::now(),
        });
    }

    Ok(())
}

/// Record a denied syscall in telemetry
pub fn record_denied_syscall<C: crate::observer::SyscallContextTrait>(
    context: &C,
    span: &mut TelemetrySpan,
) {
    let mut attrs = std::collections::HashMap::new();
    attrs.insert("syscall_name".to_string(), context.name().to_string());
    attrs.insert("result".to_string(), context.result_string());
    attrs.insert("denied".to_string(), "true".to_string());
    span.add_event("syscall_denied".to_string(), attrs);
    span.log_warn("Denied syscall recorded in telemetry");
}

/// Adapter: Convert ExecutionSpan to TelemetrySpan for telemetry integration
pub fn execution_span_to_telemetry_span(exec_span: &ExecutionSpan) -> TelemetrySpan {
    TelemetrySpan::new(exec_span.name.clone(), exec_span.identity.clone())
    // Optionally, copy more fields if needed
}
