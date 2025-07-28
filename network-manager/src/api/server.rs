//! # API Server Implementation
//!
//! This module implements the API server for the network manager, providing REST and gRPC interfaces.

use super::ApiConfig;
use crate::cni::{CniConfig, CniManager, CniServer};
use crate::model::{IsolationLevel, NetworkDriverType, VirtualNetwork};
use crate::vnet::VNetManager;
use common::error::{ForgeError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// API server
pub struct ApiServer {
    /// Configuration
    config: ApiConfig,
    /// Virtual network manager
    vnet_manager: Arc<RwLock<VNetManager>>,
    /// CNI manager
    cni_manager: Option<CniManager>,
    /// CNI server
    cni_server: Option<CniServer>,
    /// Running flag
    running: bool,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(config: ApiConfig, vnet_manager: Arc<RwLock<VNetManager>>) -> Self {
        Self {
            config,
            vnet_manager,
            cni_manager: None,
            cni_server: None,
            running: false,
        }
    }

    /// Initialize the API server
    pub async fn init(&mut self) -> Result<()> {
        info!("Initializing API server");

        // Initialize CNI manager
        let cni_config = CniConfig::default();
        let cni_manager = CniManager::new(cni_config.clone());
        cni_manager.init().await?;
        self.cni_manager = Some(cni_manager);

        // Initialize CNI server
        let cni_server = CniServer::new(cni_config, self.vnet_manager.clone());
        self.cni_server = Some(cni_server);

        Ok(())
    }

    /// Start the API server
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        info!(
            "Starting API server on {}:{}",
            self.config.address, self.config.port
        );

        // Start CNI server
        if let Some(cni_server) = &mut self.cni_server {
            cni_server.start().await?;
        }

        // Start REST API server
        self.start_rest_server().await?;

        // Start gRPC server
        self.start_grpc_server().await?;

        self.running = true;

        Ok(())
    }

    /// Start the REST API server
    async fn start_rest_server(&self) -> Result<()> {
        info!("Starting REST API server");

        // In a real implementation, this would start a REST API server
        // For now, we'll just return success

        Ok(())
    }

    /// Start the gRPC server
    async fn start_grpc_server(&self) -> Result<()> {
        info!("Starting gRPC server");

        // Create and start the gRPC API server
        let mut grpc_server = super::grpc::GrpcApiServer::new(
            self.config.clone(),
            self.vnet_manager.clone(),
        );
        grpc_server.start().await?;

        Ok(())
    }

    /// Stop the API server
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("Stopping API server");

        // Stop CNI server
        if let Some(cni_server) = &mut self.cni_server {
            cni_server.stop().await?;
        }

        self.running = false;

        Ok(())
    }

    /// Create a network
    pub async fn create_network(
        &self,
        name: String,
        cidr: String,
        gateway: Option<std::net::IpAddr>,
        driver: NetworkDriverType,
        isolation_mode: IsolationLevel,
    ) -> Result<VirtualNetwork> {
        info!("Creating network {}", name);

        let mut vnet_manager = self.vnet_manager.write().await;
        let network = vnet_manager.create_network(name, cidr, gateway, driver, isolation_mode).await?;

        // Generate and install CNI configuration
        if let Some(cni_manager) = &self.cni_manager {
            let cni_config = cni_manager.generate_network_config(&network)?;
            cni_manager.install_network_config(&cni_config)?;
        }

        Ok(network)
    }

    /// Delete a network
    pub async fn delete_network(&self, network_id: &str) -> Result<()> {
        info!("Deleting network {}", network_id);

        // Uninstall CNI configuration
        if let Some(cni_manager) = &self.cni_manager {
            cni_manager.uninstall_network_config(network_id)?;
        }

        let mut vnet_manager = self.vnet_manager.write().await;
        vnet_manager.delete_network(network_id).await
    }

    /// Connect a container to a network
    pub async fn connect_container(
        &self,
        container_id: &str,
        network_id: &str,
        namespace_path: &str,
        interface_name: &str,
        static_ip: Option<std::net::IpAddr>,
    ) -> Result<std::net::IpAddr> {
        info!(
            "Connecting container {} to network {}",
            container_id, network_id
        );

        let mut vnet_manager = self.vnet_manager.write().await;
        let ip = vnet_manager
            .connect_container(container_id, network_id, namespace_path, interface_name, static_ip)
            .await?;

        Ok(ip)
    }

    /// Disconnect a container from a network
    pub async fn disconnect_container(
        &self,
        container_id: &str,
        network_id: &str,
    ) -> Result<()> {
        info!(
            "Disconnecting container {} from network {}",
            container_id, network_id
        );

        let mut vnet_manager = self.vnet_manager.write().await;
        vnet_manager.disconnect_container(container_id, network_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_config_default() {
        let config = ApiConfig::default();
        assert_eq!(config.address, "127.0.0.1");
        assert_eq!(config.port, 9443);
        assert_eq!(config.tls_enabled, false);
        assert_eq!(config.auth_enabled, false);
    }
}