//! # Tracing Adapter Module
//!
//! This module provides a stable tracing API for the runtime, re-exporting and adapting the main telemetry system.

pub use common::telemetry::{
    check_health, collect_metrics, collect_resource_usage, decrement_gauge, end_span,
    execution_span_to_telemetry_span, generate_trace_id, get_prometheus_metrics,
    get_telemetry_manager, increment_counter, init_telemetry, record_counter,
    record_denied_syscall, record_gauge, record_histogram, record_metric, start_span,
    time_operation, HealthCheckResult, HealthChecker, HealthReport, HealthStatus, Metric,
    MetricCollector, MetricType, MetricValue, NoopTelemetry, ResourceUsage, Telemetry,
    TelemetryConfig, TelemetryEvent, TelemetryManager, TelemetrySpan,
};
