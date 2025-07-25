//! # Quantum API Server Binary
//!
//! This binary implements the API server for the Quantum-Network Fabric Layer.
//! It provides REST and gRPC interfaces for managing networks and containers.

use common::error::Result;
use network_manager::api::{server::ApiServer, ApiConfig};
use network_manager::vnet::VNetManager;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    info!("Starting Quantum API Server");

    // Initialize virtual network manager
    let vnet_manager = Arc::new(RwLock::new(VNetManager::new()));

    // Initialize API server
    let api_config = ApiConfig::default();
    let mut api_server = ApiServer::new(api_config, vnet_manager.clone());

    // Initialize and start the API server
    if let Err(e) = api_server.init().await {
        error!("Failed to initialize API server: {}", e);
        return Err(e);
    }

    if let Err(e) = api_server.start().await {
        error!("Failed to start API server: {}", e);
        return Err(e);
    }

    // Wait for Ctrl+C
    tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");

    info!("Shutting down Quantum API Server");

    // Stop the API server
    if let Err(e) = api_server.stop().await {
        error!("Failed to stop API server: {}", e);
        return Err(e);
    }

    Ok(())
}