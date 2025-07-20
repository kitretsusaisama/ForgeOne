# Telemetry System

## Overview
The Telemetry module provides comprehensive telemetry capabilities for the ForgeOne platform, enabling monitoring, tracing, and performance analysis across the system.

## Key Features
- Metrics collection and reporting
- Distributed tracing with span correlation
- Health monitoring and reporting
- Performance profiling
- Resource usage tracking
- Prometheus integration
- OpenTelemetry integration
- Structured logging with context

## Core Components

### MetricType
Telemetry metric types:
- `Counter` - Counter metrics (only increase)
- `Gauge` - Gauge metrics (can increase or decrease)
- `Histogram` - Histogram metrics (statistical distribution)
- `Summary` - Summary metrics (percentiles)

### MetricValue
Telemetry metric value:
- `Integer` - Integer value
- `Float` - Float value
- `Boolean` - Boolean value
- `String` - String value
- `Histogram` - Histogram values

### Metric
Telemetry metric:
- `name` - Metric name
- `description` - Metric description
- `metric_type` - Metric type
- `value` - Metric value
- `labels` - Metric labels
- `timestamp` - Timestamp

### HealthStatus
Health status:
- `Healthy` - System is healthy
- `Degraded` - System is degraded but operational
- `Unhealthy` - System is unhealthy

### HealthCheckResult
Health check result:
- `component` - Component name
- `status` - Health status
- `details` - Details about the health check
- `timestamp` - Timestamp

### HealthReport
System health report:
- `status` - Overall health status
- `checks` - Individual component health checks
- `timestamp` - Timestamp

## Usage Example
```rust
// Initialize telemetry
telemetry::init_telemetry(None)?;

// Record a metric
let metric = Metric {
    name: "request_count".to_string(),
    description: "Number of requests".to_string(),
    metric_type: MetricType::Counter,
    value: MetricValue::Integer(1),
    labels: HashMap::new(),
    timestamp: Utc::now(),
};
telemetry::record_metric(&metric)?;

// Get health report
let health_report = telemetry::get_health_report()?;
println!("System health: {:?}", health_report.status);
```

## Related Modules
- [Diagnostics](./diagnostics.md)
- [Observer](./observer.md)
- [Audit](./audit.md)