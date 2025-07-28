//! # Virtual Network Module
//!
//! This module provides functionality for creating and managing virtual networks
//! for the Quantum-Network Fabric Layer.

mod overlay;
mod underlay;

pub use overlay::*;
pub use underlay::*;

use crate::model::{IsolationLevel, NetworkDriverType, VirtualNetwork};
use common::error::{ForgeError, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

/// Virtual Network Manager configuration
#[derive(Debug, Clone)]
pub struct VNetConfig {
    /// Default network driver type
    pub default_driver: NetworkDriverType,
    /// Default isolation level
    pub default_isolation: IsolationLevel,
    /// Enable IPv6
    pub enable_ipv6: bool,
    /// Default subnet for virtual networks
    pub default_subnet: String,
    /// Maximum number of virtual networks
    pub max_networks: usize,
}

impl Default for VNetConfig {
    fn default() -> Self {
        Self {
            default_driver: NetworkDriverType::Bridge,
            default_isolation: IsolationLevel::Container,
            enable_ipv6: true,
            default_subnet: "172.18.0.0/16".to_string(),
            max_networks: 1024,
        }
    }
}

/// Virtual Network Manager
pub struct VNetManager {
    /// Configuration
    config: VNetConfig,
    /// Virtual networks
    networks: Arc<RwLock<HashMap<String, VirtualNetwork>>>,
    /// Network endpoints
    endpoints: Arc<RwLock<HashMap<String, crate::model::Endpoint>>>,
    /// Network statistics
    stats: Arc<RwLock<HashMap<String, crate::model::NetworkStats>>>,
    /// Network drivers
    drivers: HashMap<NetworkDriverType, Box<dyn NetworkDriver>>,
}

impl VNetManager {
    /// Create a new virtual network manager
    pub fn new() -> Self {
        Self::new_with_config(VNetConfig::default())
    }

    /// Create a new virtual network manager with the specified configuration
    pub fn new_with_config(config: VNetConfig) -> Self {
        let mut drivers = HashMap::new();

        // Register bridge driver
        drivers.insert(
            NetworkDriverType::Bridge,
            Box::new(BridgeNetworkDriver::new()) as Box<dyn NetworkDriver>,
        );

        // Register overlay driver
        drivers.insert(
            NetworkDriverType::Overlay,
            Box::new(OverlayNetworkDriver::new()) as Box<dyn NetworkDriver>,
        );

        // Register macvlan driver
        drivers.insert(
            NetworkDriverType::MacVlan,
            Box::new(MacVlanNetworkDriver::new()) as Box<dyn NetworkDriver>,
        );

        Self {
            config,
            networks: Arc::new(RwLock::new(HashMap::new())),
            endpoints: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            drivers,
        }
    }

    /// Initialize the virtual network manager
    pub async fn init(&self) -> Result<()> {
        info!("Initializing virtual network manager");

        // Initialize all drivers
        for (driver_type, driver) in &self.drivers {
            info!("Initializing {:?} driver", driver_type);
            driver.init().await?;
        }

        Ok(())
    }

    /// Get an endpoint by container ID and network ID
    pub fn get_endpoint(&self, container_id: &str, network_id: &str) -> Option<crate::model::Endpoint> {
        let endpoints = self.endpoints.read().unwrap();
        let endpoint_id = format!("{}-{}", container_id, network_id);
        endpoints.get(&endpoint_id).cloned()
    }

    /// Get network statistics by network ID
    pub fn get_network_stats(&self, network_id: &str) -> Option<crate::model::NetworkStats> {
        let stats = self.stats.read().unwrap();
        stats.get(network_id).cloned()
    }

    /// Create a new virtual network
    pub async fn create_network(
        &self,
        name: &str,
        driver_type: Option<NetworkDriverType>,
        subnet: Option<String>,
        isolation: Option<IsolationLevel>,
    ) -> Result<VirtualNetwork> {
        let driver = driver_type.unwrap_or(self.config.default_driver);
        let isolation_level = isolation.unwrap_or(self.config.default_isolation);
        let subnet_str = subnet.unwrap_or_else(|| self.config.default_subnet.clone());

        info!(
            "Creating virtual network {} with driver {:?}",
            name, driver
        );

        // Check if network already exists
        {
            let networks = self.networks.read().unwrap();
            if networks.contains_key(name) {
                return Err(ForgeError::NetworkError(format!(
                    "Network {} already exists",
                    name
                )));
            }
        }

        // Check if we've reached the maximum number of networks
        {
            let networks = self.networks.read().unwrap();
            if networks.len() >= self.config.max_networks {
                return Err(ForgeError::NetworkError(
                    "Maximum number of networks reached".to_string(),
                ));
            }
        }

        // Create the network using the appropriate driver
        let driver_impl = match self.drivers.get(&driver) {
            Some(d) => d,
            None => {
                return Err(ForgeError::NetworkError(format!(
                    "Driver {:?} not found",
                    driver
                )))
            }
        };

        let network = driver_impl
            .create_network(name, &subnet_str, isolation_level)
            .await?;

        // Store the network
        {
            let mut networks = self.networks.write().unwrap();
            networks.insert(name.to_string(), network.clone());
        }

        Ok(network)
    }

    /// Delete a virtual network
    pub async fn delete_network(&self, name: &str) -> Result<()> {
        info!("Deleting virtual network {}", name);

        // Get the network
        let network = {
            let networks = self.networks.read().unwrap();
            match networks.get(name) {
                Some(n) => n.clone(),
                None => {
                    return Err(ForgeError::NetworkError(format!(
                        "Network {} not found",
                        name
                    )))
                }
            }
        };

        // Delete the network using the appropriate driver
        let driver_impl = match self.drivers.get(&network.driver) {
            Some(d) => d,
            None => {
                return Err(ForgeError::NetworkError(format!(
                    "Driver {:?} not found",
                    network.driver
                )))
            }
        };

        driver_impl.delete_network(&network).await?;

        // Remove the network from storage
        {
            let mut networks = self.networks.write().unwrap();
            networks.remove(name);
        }

        Ok(())
    }

    /// Connect a container to a virtual network
    pub async fn connect_container(
        &self,
        network_name: &str,
        container_id: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<IpAddr> {
        info!(
            "Connecting container {} to network {}",
            container_id, network_name
        );

        // Get the network
        let network = {
            let networks = self.networks.read().unwrap();
            match networks.get(network_name) {
                Some(n) => n.clone(),
                None => {
                    return Err(ForgeError::NetworkError(format!(
                        "Network {} not found",
                        network_name
                    )))
                }
            }
        };

        // Connect the container using the appropriate driver
        let driver_impl = match self.drivers.get(&network.driver) {
            Some(d) => d,
            None => {
                return Err(ForgeError::NetworkError(format!(
                    "Driver {:?} not found",
                    network.driver
                )))
            }
        };

        let ip = driver_impl
            .connect_container(&network, container_id, ip_address)
            .await?;

        Ok(ip)
    }

    /// Disconnect a container from a virtual network
    pub async fn disconnect_container(
        &self,
        network_name: &str,
        container_id: &str,
    ) -> Result<()> {
        info!(
            "Disconnecting container {} from network {}",
            container_id, network_name
        );

        // Get the network
        let network = {
            let networks = self.networks.read().unwrap();
            match networks.get(network_name) {
                Some(n) => n.clone(),
                None => {
                    return Err(ForgeError::NetworkError(format!(
                        "Network {} not found",
                        network_name
                    )))
                }
            }
        };

        // Disconnect the container using the appropriate driver
        let driver_impl = match self.drivers.get(&network.driver) {
            Some(d) => d,
            None => {
                return Err(ForgeError::NetworkError(format!(
                    "Driver {:?} not found",
                    network.driver
                )))
            }
        };

        driver_impl
            .disconnect_container(&network, container_id)
            .await?;

        Ok(())
    }

    /// Get a virtual network by name
    pub fn get_network(&self, name: &str) -> Option<VirtualNetwork> {
        let networks = self.networks.read().unwrap();
        networks.get(name).cloned()
    }

    /// List all virtual networks
    pub fn list_networks(&self) -> Vec<VirtualNetwork> {
        let networks = self.networks.read().unwrap();
        networks.values().cloned().collect()
    }
}

/// Network driver trait
#[async_trait::async_trait]
pub trait NetworkDriver: Send + Sync {
    /// Initialize the driver
    async fn init(&self) -> Result<()>;

    /// Create a new virtual network
    async fn create_network(
        &self,
        name: &str,
        subnet: &str,
        isolation: IsolationLevel,
    ) -> Result<VirtualNetwork>;

    /// Delete a virtual network
    async fn delete_network(&self, network: &VirtualNetwork) -> Result<()>;

    /// Connect a container to a virtual network
    async fn connect_container(
        &self,
        network: &VirtualNetwork,
        container_id: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<IpAddr>;

    /// Disconnect a container from a virtual network
    async fn disconnect_container(
        &self,
        network: &VirtualNetwork,
        container_id: &str,
    ) -> Result<()>;
}

/// Bridge network driver
pub struct BridgeNetworkDriver {
    // Bridge-specific configuration
}

impl BridgeNetworkDriver {
    /// Create a new bridge network driver
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl NetworkDriver for BridgeNetworkDriver {
    async fn init(&self) -> Result<()> {
        // Initialize bridge driver
        Ok(())
    }

    async fn create_network(
        &self,
        name: &str,
        subnet: &str,
        isolation: IsolationLevel,
    ) -> Result<VirtualNetwork> {
        // Create a bridge network
        let network = VirtualNetwork {
            id: format!("br-{}", name),
            name: name.to_string(),
            driver: NetworkDriverType::Bridge,
            subnet: subnet.to_string(),
            gateway: get_gateway_from_subnet(subnet)?,
            isolation,
            created_at: chrono::Utc::now(),
        };

        // Create the bridge
        // This would call into the bridge module

        Ok(network)
    }

    async fn delete_network(&self, network: &VirtualNetwork) -> Result<()> {
        // Delete the bridge
        // This would call into the bridge module

        Ok(())
    }

    async fn connect_container(
        &self,
        network: &VirtualNetwork,
        container_id: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<IpAddr> {
        // Connect container to bridge
        // This would call into the bridge module

        // Allocate IP if not provided
        let ip = match ip_address {
            Some(ip) => ip,
            None => {
                // In a real implementation, this would allocate an IP from the subnet
                // For now, just return a dummy IP
                IpAddr::V4(Ipv4Addr::new(172, 18, 0, 2))
            }
        };

        Ok(ip)
    }

    async fn disconnect_container(
        &self,
        network: &VirtualNetwork,
        container_id: &str,
    ) -> Result<()> {
        // Disconnect container from bridge
        // This would call into the bridge module

        Ok(())
    }
}

/// MacVLAN network driver
pub struct MacVlanNetworkDriver {
    // MacVLAN-specific configuration
}

impl MacVlanNetworkDriver {
    /// Create a new MacVLAN network driver
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl NetworkDriver for MacVlanNetworkDriver {
    async fn init(&self) -> Result<()> {
        // Initialize MacVLAN driver
        Ok(())
    }

    async fn create_network(
        &self,
        name: &str,
        subnet: &str,
        isolation: IsolationLevel,
    ) -> Result<VirtualNetwork> {
        // Create a MacVLAN network
        let network = VirtualNetwork {
            id: format!("macvlan-{}", name),
            name: name.to_string(),
            driver: NetworkDriverType::MacVlan,
            subnet: subnet.to_string(),
            gateway: get_gateway_from_subnet(subnet)?,
            isolation,
            created_at: chrono::Utc::now(),
        };

        // Create the MacVLAN network
        // This would call into the MacVLAN implementation

        Ok(network)
    }

    async fn delete_network(&self, network: &VirtualNetwork) -> Result<()> {
        // Delete the MacVLAN network
        // This would call into the MacVLAN implementation

        Ok(())
    }

    async fn connect_container(
        &self,
        network: &VirtualNetwork,
        container_id: &str,
        ip_address: Option<IpAddr>,
    ) -> Result<IpAddr> {
        // Connect container to MacVLAN network
        // This would call into the MacVLAN implementation

        // Allocate IP if not provided
        let ip = match ip_address {
            Some(ip) => ip,
            None => {
                // In a real implementation, this would allocate an IP from the subnet
                // For now, just return a dummy IP
                IpAddr::V4(Ipv4Addr::new(172, 18, 0, 2))
            }
        };

        Ok(ip)
    }

    async fn disconnect_container(
        &self,
        network: &VirtualNetwork,
        container_id: &str,
    ) -> Result<()> {
        // Disconnect container from MacVLAN network
        // This would call into the MacVLAN implementation

        Ok(())
    }
}

/// Helper function to get gateway IP from subnet
fn get_gateway_from_subnet(subnet: &str) -> Result<IpAddr> {
    // Parse the subnet
    let subnet = match ipnetwork::IpNetwork::from_str(subnet) {
        Ok(subnet) => subnet,
        Err(e) => {
            return Err(ForgeError::NetworkError(format!(
                "Invalid subnet {}: {}",
                subnet, e
            )))
        }
    };

    // Get the first usable IP as the gateway
    match subnet {
        ipnetwork::IpNetwork::V4(subnet) => {
            let ip = subnet.nth(1).ok_or_else(|| {
                ForgeError::NetworkError(format!(
                    "Subnet {} too small for gateway",
                    subnet
                ))
            })?;
            Ok(IpAddr::V4(ip))
        }
        ipnetwork::IpNetwork::V6(subnet) => {
            let ip = subnet.nth(1).ok_or_else(|| {
                ForgeError::NetworkError(format!(
                    "Subnet {} too small for gateway",
                    subnet
                ))
            })?;
            Ok(IpAddr::V6(ip))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_vnet_config_default() {
        let config = VNetConfig::default();
        assert_eq!(config.default_driver, NetworkDriverType::Bridge);
        assert_eq!(config.default_isolation, IsolationLevel::Container);
        assert!(config.enable_ipv6);
        assert_eq!(config.default_subnet, "172.18.0.0/16");
        assert_eq!(config.max_networks, 1024);
    }

    #[test]
    fn test_get_gateway_from_subnet() {
        let gateway = get_gateway_from_subnet("192.168.1.0/24").unwrap();
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        let gateway = get_gateway_from_subnet("10.0.0.0/16").unwrap();
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        // Test IPv6
        let gateway = get_gateway_from_subnet("fd00::/64").unwrap();
        assert_eq!(
            gateway,
            IpAddr::V6(std::net::Ipv6Addr::from_str("fd00::1").unwrap())
        );
    }
}