//! # ForgeOne Quantum-Network Fabric Layer
//!
//! This crate provides a Zero Trust Network Manager for the ForgeOne platform.
//! It implements a secure, scalable, and extensible network fabric for containers
//! with features like Zero Trust Network Access (ZTNA), WASM-native CNI plugins,
//! programmable mesh networking, and real-time policy enforcement.

use common::error::Result;

// Re-export public modules
pub mod api;
pub mod bridge;
pub mod cni;
pub mod dns;
pub mod firewall;
pub mod mesh;
pub mod metrics;
pub mod model;
pub mod nat;
pub mod vnet;

/// Network manager version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the network manager
pub async fn init() -> Result<()> {
    tracing::info!("Initializing ForgeOne Quantum-Network Fabric Layer v{}", VERSION);
    
    // Initialize modules
    metrics::init().await?;
    
    // Initialize virtual network manager
    let vnet_manager = std::sync::Arc::new(tokio::sync::RwLock::new(vnet::VNetManager::new()));
    
    // Initialize CNI module
    let cni_config = cni::CniConfig::default();
    let cni_manager = cni::CniManager::new(cni_config);
    cni_manager.init().await?;
    
    // Initialize API server
    let api_config = api::ApiConfig::default();
    let mut api_server = api::server::ApiServer::new(api_config, vnet_manager.clone());
    api_server.init().await?;
    api_server.start().await?;
    
    Ok(())
}

/// Shutdown the network manager
pub async fn shutdown() -> Result<()> {
    tracing::info!("Shutting down ForgeOne Quantum-Network Fabric Layer");
    
    // Shutdown modules
    // In a real implementation, we would shut down the API server and CNI server here
    
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_version() {
        assert!(!super::VERSION.is_empty());
    }
}