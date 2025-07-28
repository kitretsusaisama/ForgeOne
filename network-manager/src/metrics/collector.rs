//! # Metrics Collector
//!
//! This module provides functionality for collecting metrics from various components
//! of the network manager. It periodically collects metrics and updates the registry.

use common::error::Result;
use prometheus::Registry;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time;

use crate::model::SharedNetworkManagerState;

/// Metrics collector
pub struct MetricsCollector {
    /// Prometheus registry
    registry: Arc<Registry>,
    /// Network manager state
    state: SharedNetworkManagerState,
    /// Collection interval
    interval: Duration,
    /// Running flag
    running: Arc<RwLock<bool>>,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(
        registry: Arc<Registry>,
        state: SharedNetworkManagerState,
        interval_secs: u64,
    ) -> Self {
        Self {
            registry,
            state,
            interval: Duration::from_secs(interval_secs),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the metrics collector
    pub async fn start(&self) -> Result<()> {
        let running = self.running.clone();
        *running.write().await = true;

        let state = self.state.clone();
        let interval = self.interval;

        // Spawn the collector in a background task
        tokio::spawn(async move {
            let mut interval_timer = time::interval(interval);

            loop {
                interval_timer.tick().await;

                // Check if we should stop
                if !*running.read().await {
                    break;
                }

                // Collect metrics
                Self::collect_metrics(state.clone()).await;
            }
        });

        Ok(())
    }

    /// Stop the metrics collector
    pub async fn stop(&self) -> Result<()> {
        *self.running.write().await = false;
        Ok(())
    }

    /// Collect metrics from the network manager state
    async fn collect_metrics(state: SharedNetworkManagerState) {
        let state_guard = state.read().unwrap();

        // Collect network metrics
        let network_count = state_guard.networks.len() as i64;
        let endpoint_count = state_guard.endpoints.len() as i64;

        // In a real implementation, we would update the metrics in the registry
        // based on the collected data

        tracing::debug!(
            "Collected metrics: networks={}, endpoints={}",
            network_count,
            endpoint_count
        );

        // We don't actually update any metrics here as this is just a skeleton implementation
    }
}

/// Start the metrics collector in the background
pub async fn start_collector(
    registry: Arc<Registry>,
    state: SharedNetworkManagerState,
    interval_secs: u64,
) -> Result<Arc<MetricsCollector>> {
    let collector = Arc::new(MetricsCollector::new(registry, state, interval_secs));
    collector.start().await?;
    Ok(collector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model;
    use std::time::Duration;

    #[tokio::test]
    async fn test_metrics_collector() {
        // Create a registry
        let registry = Arc::new(Registry::new());

        // Create a network manager state
        let state = model::new_shared_state();

        // Create a collector with a short interval
        let collector = MetricsCollector::new(registry, state, 1);

        // Start the collector
        collector.start().await.unwrap();

        // Wait a bit for the collector to run
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Stop the collector
        collector.stop().await.unwrap();

        // This is just a simple test to ensure the code runs without errors
        assert!(true);
    }
}