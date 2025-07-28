//! # Bridge Module
//!
//! This module provides functionality for creating and managing network bridges
//! and virtual Ethernet (veth) pairs for container networking.

mod netlink;

pub use netlink::*;

use crate::model::{Endpoint, NetworkDriverType, VirtualNetwork};
use common::error::{ForgeError, Result};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Bridge configuration
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge name
    pub name: String,
    /// Bridge IP address
    pub ip: IpAddr,
    /// Bridge MTU
    pub mtu: u32,
    /// Enable IP forwarding
    pub enable_ip_forward: bool,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            name: "forge0".to_string(),
            ip: "172.17.0.1".parse().unwrap(),
            mtu: 1500,
            enable_ip_forward: true,
        }
    }
}

/// Bridge manager
pub struct BridgeManager {
    config: BridgeConfig,
}

impl BridgeManager {
    /// Create a new bridge manager
    pub fn new(config: BridgeConfig) -> Self {
        Self { config }
    }

    /// Initialize the bridge
    pub async fn init(&self) -> Result<()> {
        info!("Initializing bridge {}", self.config.name);

        // Create the bridge
        self.create_bridge().await?;

        // Set bridge IP
        self.set_bridge_ip().await?;

        // Enable IP forwarding if needed
        if self.config.enable_ip_forward {
            self.enable_ip_forwarding().await?;
        }

        Ok(())
    }

    /// Create the bridge
    async fn create_bridge(&self) -> Result<()> {
        debug!("Creating bridge {}", self.config.name);
        
        // Use netlink to create bridge
        create_bridge(&self.config.name, self.config.mtu).await
    }

    /// Set bridge IP
    async fn set_bridge_ip(&self) -> Result<()> {
        debug!("Setting bridge {} IP to {}", self.config.name, self.config.ip);
        
        // Use netlink to set bridge IP
        set_interface_ip(&self.config.name, self.config.ip).await
    }

    /// Enable IP forwarding
    async fn enable_ip_forwarding(&self) -> Result<()> {
        debug!("Enabling IP forwarding");
        
        // This is platform-specific and may require elevated privileges
        #[cfg(target_os = "linux")]
        {
            // On Linux, write to /proc/sys/net/ipv4/ip_forward
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
                .map_err(|e| ForgeError::NetworkError(format!("Failed to enable IP forwarding: {}", e)))?;
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            warn!("IP forwarding is only supported on Linux");
        }
        
        Ok(())
    }

    /// Connect a container to the bridge
    pub async fn connect_container(
        &self,
        container_id: &str,
        endpoint: &Endpoint,
    ) -> Result<()> {
        info!("Connecting container {} to bridge {}", container_id, self.config.name);
        
        // Create veth pair
        let host_veth = format!("veth{}", &container_id[..12]);
        let container_veth = endpoint.interface.clone();
        
        // Use netlink to create veth pair
        create_veth_pair(&host_veth, &container_veth).await?;
        
        // Connect host veth to bridge
        connect_veth_to_bridge(&host_veth, &self.config.name).await?;
        
        // Set container veth IP and up
        set_interface_ip(&container_veth, endpoint.ip).await?;
        set_interface_up(&container_veth).await?;
        
        Ok(())
    }

    /// Disconnect a container from the bridge
    pub async fn disconnect_container(&self, container_id: &str) -> Result<()> {
        info!("Disconnecting container {} from bridge {}", container_id, self.config.name);
        
        // Delete veth pair (deleting one end automatically deletes the other)
        let host_veth = format!("veth{}", &container_id[..12]);
        delete_interface(&host_veth).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_bridge_config_default() {
        let config = BridgeConfig::default();
        assert_eq!(config.name, "forge0");
        assert_eq!(config.mtu, 1500);
        assert!(config.enable_ip_forward);
    }
}