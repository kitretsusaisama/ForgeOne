# Metrics Module Documentation

## Overview

The Metrics Module is a critical component of the Quantum-Network Fabric Layer that provides comprehensive monitoring, performance tracking, and observability capabilities. It collects, aggregates, and exposes metrics from all network manager components, enabling operators to monitor system health, diagnose issues, and optimize performance.

## Architecture

The Metrics Module consists of the following components:

- **Metrics Manager**: Central controller for metrics collection and exposure
- **Metrics Registry**: Repository for all metrics definitions and instances
- **Metrics Collectors**: Component-specific collectors for gathering metrics
- **Exporters**: Interfaces for exposing metrics in various formats
- **Integration Points**: Hooks into other modules for metrics collection

## Metrics Manager

The Metrics Manager (`MetricsManager`) is the central component that:

- Initializes and configures the metrics subsystem
- Provides a registry for metrics creation and registration
- Manages metrics collection from all components
- Exposes metrics through HTTP and other protocols
- Handles metrics aggregation and processing

### Configuration

The Metrics Manager can be configured through the `MetricsConfig` structure:

```rust
pub struct MetricsConfig {
    pub enabled: bool,
    pub http_endpoint: String,
    pub http_port: u16,
    pub collection_interval_seconds: u64,
    pub retention_period_seconds: u64,
    pub exporters: Vec<MetricsExporter>,
    pub labels: HashMap<String, String>,
}
```

Default configuration:
- Enabled: true
- HTTP Endpoint: "/metrics"
- HTTP Port: 9100
- Collection Interval: 15 seconds
- Retention Period: 3600 seconds (1 hour)
- Exporters: Prometheus
- Labels: {"service": "quantum-network-manager"}

## Metrics Types

The Metrics Module supports different types of metrics:

### Counters

Counters are cumulative metrics that can only increase or be reset to zero:

- Used for counting events, operations, or errors
- Monotonically increasing values
- Typically used with rates in visualization
- Examples: request_count, error_count, bytes_transferred

```rust
pub fn create_counter(&self, name: &str, help: &str, label_names: &[&str]) -> Result<Counter> {
    let counter = Counter::with_opts(
        Opts::new(name, help)
            .const_labels(self.config.labels.clone()),
    )?;
    
    self.registry.register(Box::new(counter.clone()))?;
    Ok(counter)
}
```

### Gauges

Gauges are metrics that can increase and decrease:

- Used for measuring current values
- Can go up and down based on system state
- Represent point-in-time measurements
- Examples: connection_count, memory_usage, queue_size

```rust
pub fn create_gauge(&self, name: &str, help: &str, label_names: &[&str]) -> Result<Gauge> {
    let gauge = Gauge::with_opts(
        Opts::new(name, help)
            .const_labels(self.config.labels.clone()),
    )?;
    
    self.registry.register(Box::new(gauge.clone()))?;
    Ok(gauge)
}
```

### Histograms

Histograms measure the distribution of values:

- Used for measuring durations or sizes
- Provides count, sum, and quantiles
- Allows for percentile calculations
- Examples: request_duration, packet_size, operation_latency

```rust
pub fn create_histogram(
    &self,
    name: &str,
    help: &str,
    label_names: &[&str],
    buckets: Option<Vec<f64>>,
) -> Result<Histogram> {
    let histogram = match buckets {
        Some(buckets) => {
            Histogram::with_opts(
                HistogramOpts::new(name, help)
                    .const_labels(self.config.labels.clone())
                    .buckets(buckets),
            )?
        },
        None => {
            Histogram::with_opts(
                HistogramOpts::new(name, help)
                    .const_labels(self.config.labels.clone()),
            )?
        },
    };
    
    self.registry.register(Box::new(histogram.clone()))?;
    Ok(histogram)
}
```

### Summaries

Summaries are similar to histograms but calculate quantiles on the client side:

- Used for measuring durations with specific quantiles
- Provides count, sum, and configured quantiles
- More accurate for specific percentiles than histograms
- Examples: request_duration_quantiles, gc_pause_quantiles

```rust
pub fn create_summary(
    &self,
    name: &str,
    help: &str,
    label_names: &[&str],
    objectives: Option<HashMap<f64, f64>>,
) -> Result<Summary> {
    let summary = match objectives {
        Some(objectives) => {
            Summary::with_opts(
                SummaryOpts::new(name, help)
                    .const_labels(self.config.labels.clone())
                    .objectives(objectives),
            )?
        },
        None => {
            Summary::with_opts(
                SummaryOpts::new(name, help)
                    .const_labels(self.config.labels.clone()),
            )?
        },
    };
    
    self.registry.register(Box::new(summary.clone()))?;
    Ok(summary)
}
```

## Component Metrics

The Metrics Module collects metrics from all network manager components:

### API Module Metrics

- `api_requests_total`: Counter of API requests by endpoint and method
- `api_request_duration_seconds`: Histogram of API request durations
- `api_errors_total`: Counter of API errors by endpoint and error type
- `api_active_connections`: Gauge of active API connections

### CNI Module Metrics

- `cni_operations_total`: Counter of CNI operations by command type
- `cni_operation_duration_seconds`: Histogram of CNI operation durations
- `cni_operation_errors_total`: Counter of CNI operation errors by type
- `cni_active_requests`: Gauge of active CNI requests

### Virtual Network Module Metrics

- `vnet_networks_total`: Gauge of total virtual networks
- `vnet_endpoints_total`: Gauge of total network endpoints
- `vnet_operations_total`: Counter of virtual network operations by type
- `vnet_operation_duration_seconds`: Histogram of operation durations
- `vnet_operation_errors_total`: Counter of operation errors by type

### Firewall Module Metrics

- `firewall_rules_total`: Gauge of total firewall rules
- `firewall_operations_total`: Counter of firewall operations by type
- `firewall_operation_duration_seconds`: Histogram of operation durations
- `firewall_operation_errors_total`: Counter of operation errors by type
- `firewall_connections_rejected_total`: Counter of rejected connections

### Bridge Module Metrics

- `bridge_interfaces_total`: Gauge of total bridge interfaces
- `bridge_operations_total`: Counter of bridge operations by type
- `bridge_operation_duration_seconds`: Histogram of operation durations
- `bridge_operation_errors_total`: Counter of operation errors by type
- `bridge_veth_pairs_total`: Gauge of total veth pairs

### DNS Module Metrics

- `dns_records_total`: Gauge of total DNS records by type
- `dns_queries_total`: Counter of DNS queries by type
- `dns_query_duration_seconds`: Histogram of DNS query durations
- `dns_query_errors_total`: Counter of DNS query errors by type
- `dns_cache_hit_ratio`: Gauge of DNS cache hit ratio

### NAT Module Metrics

- `nat_rules_total`: Gauge of total NAT rules by type
- `nat_port_mappings_total`: Gauge of total port mappings
- `nat_operations_total`: Counter of NAT operations by type
- `nat_operation_duration_seconds`: Histogram of operation durations
- `nat_operation_errors_total`: Counter of operation errors by type

## Metrics Collection

The Metrics Module collects metrics through various mechanisms:

### Direct Instrumentation

Components directly instrument their code with metrics:

```rust
// Example from the API module
pub async fn handle_request(&self, req: Request<Body>) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    
    // Increment request counter
    self.metrics.api_requests_total
        .with_label_values(&[&path, &method])
        .inc();
    
    // Record request duration
    let timer = self.metrics.api_request_duration_seconds
        .with_label_values(&[&path, &method])
        .start_timer();
    
    // Process request
    let result = self.process_request(req).await;
    
    // Stop timer
    timer.observe_duration();
    
    // Record errors if any
    if let Err(ref e) = result {
        self.metrics.api_errors_total
            .with_label_values(&[&path, &method, &e.to_string()])
            .inc();
    }
    
    result
}
```

### Periodic Collection

Some metrics are collected periodically:

```rust
pub async fn collect_metrics(&self) {
    let networks = self.vnet_manager.list_networks().await.unwrap_or_default();
    self.metrics.vnet_networks_total.set(networks.len() as f64);
    
    let endpoints = self.vnet_manager.list_endpoints().await.unwrap_or_default();
    self.metrics.vnet_endpoints_total.set(endpoints.len() as f64);
    
    // Collect other metrics...
}
```

### Event-Based Collection

Metrics can be updated based on events:

```rust
pub async fn on_network_created(&self, network: &VirtualNetwork) {
    self.metrics.vnet_operations_total
        .with_label_values(&["create"])
        .inc();
    
    self.metrics.vnet_networks_total.inc();
}

pub async fn on_network_deleted(&self, network_id: &str) {
    self.metrics.vnet_operations_total
        .with_label_values(&["delete"])
        .inc();
    
    self.metrics.vnet_networks_total.dec();
}
```

## Metrics Exporters

The Metrics Module supports different exporters for metrics:

### Prometheus Exporter

The default exporter that exposes metrics in Prometheus format:

```rust
pub struct PrometheusExporter {
    registry: Registry,
    http_endpoint: String,
    http_port: u16,
}

impl PrometheusExporter {
    pub fn new(registry: Registry, config: &MetricsConfig) -> Self {
        Self {
            registry,
            http_endpoint: config.http_endpoint.clone(),
            http_port: config.http_port,
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        let registry = self.registry.clone();
        let endpoint = self.http_endpoint.clone();
        
        let metrics_handler = move |_req: Request<Body>| {
            let encoder = TextEncoder::new();
            let metric_families = registry.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Body::from(buffer))
                .unwrap();
            
            future::ok::<_, hyper::Error>(response)
        };
        
        let addr = SocketAddr::from(([0, 0, 0, 0], self.http_port));
        let service = make_service_fn(|_| {
            let endpoint = endpoint.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    if req.uri().path() == endpoint {
                        metrics_handler(req)
                    } else {
                        let response = Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Body::from("Not Found"))
                            .unwrap();
                        future::ok(response)
                    }
                }))
            }
        });
        
        let server = Server::bind(&addr).serve(service);
        
        info!("Prometheus metrics server listening on http://0.0.0.0:{}{}", 
              self.http_port, self.http_endpoint);
        
        server.await.map_err(|e| Error::MetricsExporterError(e.to_string()))
    }
}
```

### StatsD Exporter

An optional exporter for StatsD-compatible systems:

```rust
pub struct StatsDExporter {
    registry: Registry,
    statsd_host: String,
    statsd_port: u16,
    prefix: String,
    interval_seconds: u64,
}

impl StatsDExporter {
    pub fn new(
        registry: Registry,
        statsd_host: String,
        statsd_port: u16,
        prefix: String,
        interval_seconds: u64,
    ) -> Self {
        Self {
            registry,
            statsd_host,
            statsd_port,
            prefix,
            interval_seconds,
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        let registry = self.registry.clone();
        let host = self.statsd_host.clone();
        let port = self.statsd_port;
        let prefix = self.prefix.clone();
        let interval = Duration::from_secs(self.interval_seconds);
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
                    if let Ok(addr) = format!("{host}:{port}").parse() {
                        if let Ok(_) = socket.connect(addr).await {
                            let metric_families = registry.gather();
                            
                            for mf in metric_families {
                                for m in mf.get_metric() {
                                    let name = format!("{}.{}", prefix, mf.get_name());
                                    let labels = m.get_label()
                                        .iter()
                                        .map(|l| format!("{}.{}", l.get_name(), l.get_value()))
                                        .collect::<Vec<_>>()
                                        .join(".");
                                    
                                    let full_name = if labels.is_empty() {
                                        name
                                    } else {
                                        format!("{}.{}", name, labels)
                                    };
                                    
                                    match mf.get_type() {
                                        MetricType::COUNTER => {
                                            let value = m.get_counter().get_value();
                                            let msg = format!("{full_name}:{value}|c\n");
                                            let _ = socket.send(msg.as_bytes()).await;
                                        },
                                        MetricType::GAUGE => {
                                            let value = m.get_gauge().get_value();
                                            let msg = format!("{full_name}:{value}|g\n");
                                            let _ = socket.send(msg.as_bytes()).await;
                                        },
                                        MetricType::HISTOGRAM => {
                                            let h = m.get_histogram();
                                            let count = h.get_sample_count();
                                            let sum = h.get_sample_sum();
                                            let msg = format!("{full_name}.count:{count}|c\n");
                                            let _ = socket.send(msg.as_bytes()).await;
                                            let msg = format!("{full_name}.sum:{sum}|c\n");
                                            let _ = socket.send(msg.as_bytes()).await;
                                        },
                                        MetricType::SUMMARY => {
                                            let s = m.get_summary();
                                            let count = s.get_sample_count();
                                            let sum = s.get_sample_sum();
                                            let msg = format!("{full_name}.count:{count}|c\n");
                                            let _ = socket.send(msg.as_bytes()).await;
                                            let msg = format!("{full_name}.sum:{sum}|c\n");
                                            let _ = socket.send(msg.as_bytes()).await;
                                        },
                                        _ => {},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
}
```

## Integration with Other Modules

The Metrics Module integrates with all other modules through a consistent pattern:

1. **Metrics Creation**: Each module defines its metrics during initialization
2. **Metrics Registration**: Metrics are registered with the central registry
3. **Metrics Collection**: Modules update metrics during operations
4. **Metrics Exposure**: The Metrics Manager exposes all metrics

```rust
// Example integration with the Virtual Network module
pub struct VNetMetrics {
    pub networks_total: Gauge,
    pub endpoints_total: Gauge,
    pub operations_total: CounterVec,
    pub operation_duration_seconds: HistogramVec,
    pub operation_errors_total: CounterVec,
}

impl VNetMetrics {
    pub fn new(metrics_manager: &MetricsManager) -> Result<Self> {
        let networks_total = metrics_manager.create_gauge(
            "vnet_networks_total",
            "Total number of virtual networks",
            &[],
        )?;
        
        let endpoints_total = metrics_manager.create_gauge(
            "vnet_endpoints_total",
            "Total number of network endpoints",
            &[],
        )?;
        
        let operations_total = metrics_manager.create_counter_vec(
            "vnet_operations_total",
            "Total number of virtual network operations",
            &["operation"],
        )?;
        
        let operation_duration_seconds = metrics_manager.create_histogram_vec(
            "vnet_operation_duration_seconds",
            "Duration of virtual network operations in seconds",
            &["operation"],
            Some(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
        )?;
        
        let operation_errors_total = metrics_manager.create_counter_vec(
            "vnet_operation_errors_total",
            "Total number of virtual network operation errors",
            &["operation", "error"],
        )?;
        
        Ok(Self {
            networks_total,
            endpoints_total,
            operations_total,
            operation_duration_seconds,
            operation_errors_total,
        })
    }
}
```

## Performance Considerations

The Metrics Module is designed with performance in mind:

1. **Low Overhead**: Metrics collection has minimal impact on system performance
2. **Efficient Storage**: Metrics are stored in memory with optimized data structures
3. **Configurable Collection**: Collection intervals can be adjusted based on needs
4. **Selective Metrics**: Metrics can be enabled or disabled based on requirements
5. **Efficient Serialization**: Metrics are serialized efficiently for export

## Example Usage

### Initializing the Metrics Module

```rust
let config = MetricsConfig {
    enabled: true,
    http_endpoint: "/metrics".to_string(),
    http_port: 9100,
    collection_interval_seconds: 15,
    retention_period_seconds: 3600,
    exporters: vec![MetricsExporter::Prometheus],
    labels: {
        let mut labels = HashMap::new();
        labels.insert("service".to_string(), "quantum-network-manager".to_string());
        labels
    },
};

let metrics_manager = MetricsManager::new(config);
metrics_manager.start().await?;

println!("Metrics server started on http://0.0.0.0:9100/metrics");
```

### Creating and Using Metrics

```rust
// Create metrics
let request_counter = metrics_manager.create_counter_vec(
    "api_requests_total",
    "Total number of API requests",
    &["endpoint", "method"],
)?;

let request_duration = metrics_manager.create_histogram_vec(
    "api_request_duration_seconds",
    "Duration of API requests in seconds",
    &["endpoint", "method"],
    Some(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]),
)?;

// Use metrics in code
request_counter.with_label_values(&["/networks", "GET"]).inc();

let timer = request_duration
    .with_label_values(&["/networks", "GET"])
    .start_timer();

// Perform operation
// ...

// Stop timer to record duration
timer.observe_duration();
```

### Querying Metrics

Metrics can be queried using Prometheus query language (PromQL):

```
# Total API requests by endpoint
sum(api_requests_total) by (endpoint)

# 95th percentile of request durations
histogram_quantile(0.95, sum(rate(api_request_duration_seconds_bucket[5m])) by (endpoint, le))

# Error rate
sum(rate(api_errors_total[5m])) / sum(rate(api_requests_total[5m]))
```

## Troubleshooting

Common issues and their solutions:

1. **Metrics Not Appearing**: Check if metrics are enabled and the exporter is running
2. **High Memory Usage**: Reduce the number of metrics or label cardinality
3. **Performance Impact**: Adjust collection intervals or disable high-cardinality metrics
4. **Metric Name Collisions**: Ensure metric names are unique across all components
5. **Exporter Failures**: Check network connectivity and port availability