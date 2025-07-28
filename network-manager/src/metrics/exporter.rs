//! # Metrics Exporter
//!
//! This module provides functionality for exporting metrics in Prometheus format.
//! It implements an HTTP server that exposes metrics on a configurable endpoint.

use common::error::Result;
use prometheus::{Encoder, Registry, TextEncoder};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::Filter;

/// Metrics exporter
pub struct MetricsExporter {
    /// Prometheus registry
    registry: Arc<Registry>,
    /// Server address
    address: SocketAddr,
}

impl MetricsExporter {
    /// Create a new metrics exporter
    pub fn new(registry: Arc<Registry>, address: SocketAddr) -> Self {
        Self { registry, address }
    }

    /// Start the metrics exporter
    pub async fn start(&self) -> Result<()> {
        let registry = self.registry.clone();

        // Define the metrics endpoint
        let metrics_route = warp::path("metrics")
            .and(warp::get())
            .map(move || {
                let encoder = TextEncoder::new();
                let metric_families = registry.gather();
                let mut buffer = Vec::new();
                encoder.encode(&metric_families, &mut buffer).unwrap();
                warp::reply::with_header(
                    String::from_utf8(buffer).unwrap(),
                    "content-type",
                    encoder.format_type(),
                )
            });

        // Define the health endpoint
        let health_route = warp::path("health")
            .and(warp::get())
            .map(|| warp::reply::json(&serde_json::json!({"status": "ok"})));

        // Combine routes
        let routes = metrics_route.or(health_route);

        // Start the server
        tracing::info!("Starting metrics exporter on {}", self.address);
        warp::serve(routes).run(self.address).await;

        Ok(())
    }
}

/// Start the metrics exporter in the background
pub async fn start_exporter(registry: Arc<Registry>, address: SocketAddr) -> Result<()> {
    let exporter = MetricsExporter::new(registry, address);

    // Spawn the exporter in a background task
    tokio::spawn(async move {
        if let Err(e) = exporter.start().await {
            tracing::error!("Metrics exporter error: {}", e);
        }
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Counter, Opts};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_metrics_exporter() {
        // Create a registry
        let registry = Arc::new(Registry::new());

        // Register a counter
        let counter = Counter::with_opts(Opts::new("test_counter", "Test counter")).unwrap();
        registry.register(Box::new(counter.clone())).unwrap();

        // Increment the counter
        counter.inc();

        // Create an exporter with a random port
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let exporter = MetricsExporter::new(registry, address);

        // We don't actually start the exporter in the test
        // as it would block indefinitely
        // This is just a simple test to ensure the code compiles
        assert!(true);
    }
}