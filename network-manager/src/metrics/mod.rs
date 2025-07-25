//! # Metrics Module
//!
//! This module provides metrics collection and export functionality for the network manager.
//! It collects metrics about network traffic, container connectivity, and security events.
//! The metrics are exported in Prometheus format for monitoring and observability.

mod collector;
mod exporter;

pub use collector::{start_collector, MetricsCollector};
pub use exporter::{start_exporter, MetricsExporter};

use common::error::Result;
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};

/// Metrics configuration
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Metrics endpoint address
    pub address: String,
    /// Metrics endpoint port
    pub port: u16,
    /// Collection interval in seconds
    pub interval: u64,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            address: "127.0.0.1".to_string(),
            port: 9100,
            interval: 15,
        }
    }
}

/// Metrics manager
pub struct MetricsManager {
    /// Metrics configuration
    config: MetricsConfig,
    /// Prometheus registry
    registry: Registry,
    /// Network metrics
    network_metrics: NetworkMetrics,
    /// Container metrics
    container_metrics: ContainerMetrics,
    /// Security metrics
    security_metrics: SecurityMetrics,
}

impl MetricsManager {
    /// Create a new metrics manager
    pub fn new(config: MetricsConfig) -> Self {
        let registry = Registry::new();
        let network_metrics = NetworkMetrics::new(&registry);
        let container_metrics = ContainerMetrics::new(&registry);
        let security_metrics = SecurityMetrics::new(&registry);

        Self {
            config,
            registry,
            network_metrics,
            container_metrics,
            security_metrics,
        }
    }

    /// Initialize the metrics manager
    pub async fn init(&self) -> Result<()> {
        if !self.config.enabled {
            tracing::info!("Metrics collection is disabled");
            return Ok(());
        }

        // Start the metrics server
        let addr = format!("{}}:{}", self.config.address, self.config.port);
        tracing::info!("Starting metrics server on {}", addr);

        // In a real implementation, we would start an HTTP server here
        // that exposes the metrics in Prometheus format

        Ok(())
    }

    /// Record network traffic
    pub fn record_network_traffic(&self, network_id: &str, bytes_in: u64, bytes_out: u64) {
        self.network_metrics.record_traffic(network_id, bytes_in, bytes_out);
    }

    /// Record container connection
    pub fn record_container_connection(&self, network_id: &str) {
        self.container_metrics.record_connection(network_id);
    }

    /// Record container disconnection
    pub fn record_container_disconnection(&self, network_id: &str) {
        self.container_metrics.record_disconnection(network_id);
    }

    /// Record security event
    pub fn record_security_event(&self, event_type: &str, network_id: &str) {
        self.security_metrics.record_event(event_type, network_id);
    }
}

/// Network metrics
struct NetworkMetrics {
    /// Bytes received
    bytes_in: IntCounterVec,
    /// Bytes sent
    bytes_out: IntCounterVec,
    /// Active networks
    active_networks: IntGauge,
    /// Network latency
    network_latency: Histogram,
}

impl NetworkMetrics {
    /// Create new network metrics
    fn new(registry: &Registry) -> Self {
        let bytes_in = IntCounterVec::new(
            Opts::new("network_bytes_in", "Total bytes received by network"),
            &["network_id"],
        )
        .unwrap();

        let bytes_out = IntCounterVec::new(
            Opts::new("network_bytes_out", "Total bytes sent by network"),
            &["network_id"],
        )
        .unwrap();

        let active_networks = IntGauge::new(
            "active_networks",
            "Number of active virtual networks",
        )
        .unwrap();

        let network_latency = Histogram::with_opts(
            HistogramOpts::new(
                "network_latency",
                "Network latency in milliseconds",
            )
            .buckets(vec![5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0]),
        )
        .unwrap();

        registry.register(Box::new(bytes_in.clone())).unwrap();
        registry.register(Box::new(bytes_out.clone())).unwrap();
        registry.register(Box::new(active_networks.clone())).unwrap();
        registry.register(Box::new(network_latency.clone())).unwrap();

        Self {
            bytes_in,
            bytes_out,
            active_networks,
            network_latency,
        }
    }

    /// Record network traffic
    fn record_traffic(&self, network_id: &str, bytes_in: u64, bytes_out: u64) {
        self.bytes_in.with_label_values(&[network_id]).inc_by(bytes_in);
        self.bytes_out.with_label_values(&[network_id]).inc_by(bytes_out);
    }

    /// Set active networks count
    fn set_active_networks(&self, count: i64) {
        self.active_networks.set(count);
    }

    /// Record network latency
    fn record_latency(&self, latency_ms: f64) {
        self.network_latency.observe(latency_ms);
    }
}

/// Container metrics
struct ContainerMetrics {
    /// Connected containers
    connected_containers: IntGaugeVec,
    /// Container connections
    container_connections: IntCounterVec,
    /// Container disconnections
    container_disconnections: IntCounterVec,
}

impl ContainerMetrics {
    /// Create new container metrics
    fn new(registry: &Registry) -> Self {
        let connected_containers = IntGaugeVec::new(
            Opts::new("connected_containers", "Number of connected containers"),
            &["network_id"],
        )
        .unwrap();

        let container_connections = IntCounterVec::new(
            Opts::new("container_connections", "Total container connections"),
            &["network_id"],
        )
        .unwrap();

        let container_disconnections = IntCounterVec::new(
            Opts::new("container_disconnections", "Total container disconnections"),
            &["network_id"],
        )
        .unwrap();

        registry.register(Box::new(connected_containers.clone())).unwrap();
        registry.register(Box::new(container_connections.clone())).unwrap();
        registry.register(Box::new(container_disconnections.clone())).unwrap();

        Self {
            connected_containers,
            container_connections,
            container_disconnections,
        }
    }

    /// Record container connection
    fn record_connection(&self, network_id: &str) {
        self.container_connections.with_label_values(&[network_id]).inc();
        self.connected_containers.with_label_values(&[network_id]).inc();
    }

    /// Record container disconnection
    fn record_disconnection(&self, network_id: &str) {
        self.container_disconnections.with_label_values(&[network_id]).inc();
        self.connected_containers.with_label_values(&[network_id]).dec();
    }
}

/// Security metrics
struct SecurityMetrics {
    /// Security events
    security_events: IntCounterVec,
    /// Firewall blocks
    firewall_blocks: IntCounterVec,
    /// Authentication failures
    auth_failures: IntCounterVec,
}

impl SecurityMetrics {
    /// Create new security metrics
    fn new(registry: &Registry) -> Self {
        let security_events = IntCounterVec::new(
            Opts::new("security_events", "Total security events"),
            &["event_type", "network_id"],
        )
        .unwrap();

        let firewall_blocks = IntCounterVec::new(
            Opts::new("firewall_blocks", "Total firewall blocks"),
            &["network_id"],
        )
        .unwrap();

        let auth_failures = IntCounterVec::new(
            Opts::new("auth_failures", "Total authentication failures"),
            &["network_id"],
        )
        .unwrap();

        registry.register(Box::new(security_events.clone())).unwrap();
        registry.register(Box::new(firewall_blocks.clone())).unwrap();
        registry.register(Box::new(auth_failures.clone())).unwrap();

        Self {
            security_events,
            firewall_blocks,
            auth_failures,
        }
    }

    /// Record security event
    fn record_event(&self, event_type: &str, network_id: &str) {
        self.security_events.with_label_values(&[event_type, network_id]).inc();

        if event_type == "firewall_block" {
            self.firewall_blocks.with_label_values(&[network_id]).inc();
        } else if event_type == "auth_failure" {
            self.auth_failures.with_label_values(&[network_id]).inc();
        }
    }
}

/// Initialize the metrics module
pub async fn init() -> Result<()> {
    let config = MetricsConfig::default();
    
    if !config.enabled {
        tracing::info!("Metrics collection is disabled");
        return Ok(());
    }
    
    // Create the registry
    let registry = Arc::new(Registry::new());
    
    // Create the metrics manager
    let metrics_manager = MetricsManager::new(config.clone());
    metrics_manager.init().await?;
    
    // Start the metrics exporter
    let addr = SocketAddr::new(
        config.address.parse().unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
        config.port,
    );
    start_exporter(registry.clone(), addr).await?;
    
    // Start the metrics collector if we have a network manager state
    // In a real implementation, we would get the state from a global context
    // let state = get_network_manager_state();
    // start_collector(registry.clone(), state, config.interval).await?;
    
    tracing::info!("Metrics module initialized successfully");
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_config_default() {
        let config = MetricsConfig::default();
        assert!(config.enabled);
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.port, 9100);
        assert_eq!(config.interval, 15);
    }
}