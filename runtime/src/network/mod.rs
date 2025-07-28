//! # Container Network Module
//!
//! This module provides networking functionality for containers, including
//! network creation, configuration, and inter-container communication.

use crate::registry::ContainerRegistration;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

/// Network driver type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDriverType {
    /// Bridge network driver
    Bridge,
    /// Host network driver
    Host,
    /// Overlay network driver
    Overlay,
    /// Macvlan network driver
    Macvlan,
    /// IPvlan network driver
    IPvlan,
    /// None network driver
    None,
}

impl std::fmt::Display for NetworkDriverType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkDriverType::Bridge => write!(f, "bridge"),
            NetworkDriverType::Host => write!(f, "host"),
            NetworkDriverType::Overlay => write!(f, "overlay"),
            NetworkDriverType::Macvlan => write!(f, "macvlan"),
            NetworkDriverType::IPvlan => write!(f, "ipvlan"),
            NetworkDriverType::None => write!(f, "none"),
        }
    }
}

/// Network scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkScope {
    /// Local scope
    Local,
    /// Global scope
    Global,
    /// Swarm scope
    Swarm,
}

impl std::fmt::Display for NetworkScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkScope::Local => write!(f, "local"),
            NetworkScope::Global => write!(f, "global"),
            NetworkScope::Swarm => write!(f, "swarm"),
        }
    }
}

/// IP address management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPAMConfig {
    /// Subnet
    pub subnet: String,
    /// IP range
    pub ip_range: Option<String>,
    /// Gateway
    pub gateway: Option<String>,
    /// Auxiliary addresses
    pub aux_addresses: HashMap<String, String>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network name
    pub name: String,
    /// Network driver type
    pub driver: NetworkDriverType,
    /// Network scope
    pub scope: NetworkScope,
    /// Whether the network is internal
    pub internal: bool,
    /// Whether IPv6 is enabled
    pub enable_ipv6: bool,
    /// IPAM configuration
    pub ipam: Option<IPAMConfig>,
    /// Network options
    pub options: HashMap<String, String>,
    /// Network labels
    pub labels: HashMap<String, String>,
}

impl NetworkConfig {
    /// Create a new network configuration
    pub fn new(name: &str, driver: NetworkDriverType) -> Self {
        Self {
            name: name.to_string(),
            driver,
            scope: NetworkScope::Local,
            internal: false,
            enable_ipv6: false,
            ipam: None,
            options: HashMap::new(),
            labels: HashMap::new(),
        }
    }

    /// Set network scope
    pub fn with_scope(mut self, scope: NetworkScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set whether the network is internal
    pub fn with_internal(mut self, internal: bool) -> Self {
        self.internal = internal;
        self
    }

    /// Set whether IPv6 is enabled
    pub fn with_ipv6(mut self, enable_ipv6: bool) -> Self {
        self.enable_ipv6 = enable_ipv6;
        self
    }

    /// Set IPAM configuration
    pub fn with_ipam(mut self, ipam: IPAMConfig) -> Self {
        self.ipam = Some(ipam);
        self
    }

    /// Add a network option
    pub fn with_option(mut self, key: &str, value: &str) -> Self {
        self.options.insert(key.to_string(), value.to_string());
        self
    }

    /// Add a network label
    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }
}

/// Container endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Container ID
    pub container_id: String,
    /// Network ID
    pub network_id: String,
    /// IPv4 address
    pub ipv4_address: Option<Ipv4Addr>,
    /// IPv6 address
    pub ipv6_address: Option<Ipv6Addr>,
    /// MAC address
    pub mac_address: Option<String>,
    /// DNS servers
    pub dns_servers: Vec<IpAddr>,
    /// DNS search domains
    pub dns_search_domains: Vec<String>,
    /// Extra hosts
    pub extra_hosts: HashMap<String, IpAddr>,
}

impl Endpoint {
    /// Create a new endpoint
    pub fn new(container_id: &str, network_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            network_id: network_id.to_string(),
            ipv4_address: None,
            ipv6_address: None,
            mac_address: None,
            dns_servers: Vec::new(),
            dns_search_domains: Vec::new(),
            extra_hosts: HashMap::new(),
        }
    }

    /// Set IPv4 address
    pub fn with_ipv4(mut self, ipv4: Ipv4Addr) -> Self {
        self.ipv4_address = Some(ipv4);
        self
    }

    /// Set IPv6 address
    pub fn with_ipv6(mut self, ipv6: Ipv6Addr) -> Self {
        self.ipv6_address = Some(ipv6);
        self
    }

    /// Set MAC address
    pub fn with_mac(mut self, mac: &str) -> Self {
        self.mac_address = Some(mac.to_string());
        self
    }

    /// Add a DNS server
    pub fn with_dns_server(mut self, server: IpAddr) -> Self {
        self.dns_servers.push(server);
        self
    }

    /// Add a DNS search domain
    pub fn with_dns_search_domain(mut self, domain: &str) -> Self {
        self.dns_search_domains.push(domain.to_string());
        self
    }

    /// Add an extra host
    pub fn with_extra_host(mut self, hostname: &str, ip: IpAddr) -> Self {
        self.extra_hosts.insert(hostname.to_string(), ip);
        self
    }
}

/// Network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Network {
    /// Network ID
    pub id: String,
    /// Network configuration
    pub config: NetworkConfig,
    /// Network endpoints
    pub endpoints: HashMap<String, Endpoint>,
    /// Creation time in seconds since epoch
    pub created_at: u64,
}

impl Network {
    /// Create a new network
    pub fn new(id: &str, config: NetworkConfig) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: id.to_string(),
            config,
            endpoints: HashMap::new(),
            created_at: now,
        }
    }

    /// Add an endpoint
    pub fn add_endpoint(&mut self, endpoint: Endpoint) -> Result<()> {
        // Check if endpoint already exists
        if self.endpoints.contains_key(&endpoint.container_id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "endpoint".to_string(),
                id: endpoint.container_id.clone(),
            });
        }

        // Add endpoint
        self.endpoints
            .insert(endpoint.container_id.clone(), endpoint);

        Ok(())
    }

    /// Remove an endpoint
    pub fn remove_endpoint(&mut self, container_id: &str) -> Result<Endpoint> {
        // Check if endpoint exists
        if !self.endpoints.contains_key(container_id) {
            return Err(ForgeError::NotFound(format!("endpoint: {}", container_id)));
        }

        // Remove endpoint
        Ok(self.endpoints.remove(container_id).unwrap())
    }

    /// Get an endpoint
    pub fn get_endpoint(&self, container_id: &str) -> Result<&Endpoint> {
        // Check if endpoint exists
        self.endpoints
            .get(container_id)
            .ok_or(ForgeError::NotFound(format!("endpoint: {}", container_id)))
    }

    /// Get all endpoints
    pub fn get_endpoints(&self) -> Vec<&Endpoint> {
        self.endpoints.values().collect()
    }

    /// Get number of endpoints
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }
}

/// Network manager
#[derive(Debug)]
pub struct NetworkManager {
    /// Map of network ID to network
    networks: Arc<RwLock<HashMap<String, Network>>>,
    /// Map of network name to network ID
    name_to_id: Arc<RwLock<HashMap<String, String>>>,
    /// Map of container ID to set of network IDs
    container_networks: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl NetworkManager {
    /// Create a new network manager
    pub fn new() -> Self {
        Self {
            networks: Arc::new(RwLock::new(HashMap::new())),
            name_to_id: Arc::new(RwLock::new(HashMap::new())),
            container_networks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a network
    pub fn create_network(&self, config: NetworkConfig) -> Result<String> {
        let span = ExecutionSpan::new(
            "create_network",
            common::identity::IdentityContext::system(),
        );

        // Generate network ID
        let id = format!("net_{}", &config.name);

        // Create network
        let network = Network::new(&id, config.clone());

        // Add to networks
        let mut networks = self
            .networks
            .write()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        // Check if network with the same ID already exists
        if networks.contains_key(&id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "network".to_string(),
                id: id.clone(),
            });
        }

        // Add to name to ID map
        let mut name_to_id = self.name_to_id.write().map_err(|_| {
            ForgeError::InternalError("network_name_to_id lock poisoned".to_string())
        })?;

        // Check if network with the same name already exists
        if name_to_id.contains_key(&config.name) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "network".to_string(),
                id: config.name.clone(),
            });
        }

        // Add to maps
        networks.insert(id.clone(), network);
        name_to_id.insert(config.name.clone(), id.clone());

        Ok(id)
    }

    /// Remove a network
    pub fn remove_network(&self, id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_network",
            common::identity::IdentityContext::system(),
        );

        // Get network
        let mut networks = self
            .networks
            .write()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        let network = networks
            .get(id)
            .ok_or(ForgeError::NotFound(format!("network: {}", id)))?;

        // Check if network has endpoints
        if !network.endpoints.is_empty() {
            return Err(ForgeError::InternalError(format!(
                "Cannot remove network {}: has {} endpoints",
                id,
                network.endpoints.len()
            )));
        }

        // Remove from name to ID map
        let mut name_to_id = self.name_to_id.write().map_err(|_| {
            ForgeError::InternalError("network_name_to_id lock poisoned".to_string())
        })?;

        name_to_id.remove(&network.config.name);

        // Remove from networks
        networks.remove(id);

        Ok(())
    }

    /// Get a network
    pub fn get_network(&self, id: &str) -> Result<Network> {
        let span = ExecutionSpan::new("get_network", common::identity::IdentityContext::system());

        // Get network
        let networks = self
            .networks
            .read()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        let network = networks
            .get(id)
            .ok_or(ForgeError::NotFound(format!("network: {}", id)))?;

        Ok(network.clone())
    }

    /// Get a network by name
    pub fn get_network_by_name(&self, name: &str) -> Result<Network> {
        let span = ExecutionSpan::new(
            "get_network_by_name",
            common::identity::IdentityContext::system(),
        );

        // Get network ID from name
        let name_to_id = self.name_to_id.read().map_err(|_| {
            ForgeError::InternalError("network_name_to_id lock poisoned".to_string())
        })?;

        let id = name_to_id
            .get(name)
            .ok_or(ForgeError::NotFound(format!("network: {}", name)))?;

        // Get network
        self.get_network(id)
    }

    /// List all networks
    pub fn list_networks(&self) -> Result<Vec<Network>> {
        let span = ExecutionSpan::new("list_networks", common::identity::IdentityContext::system());

        // Get all networks
        let networks = self
            .networks
            .read()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        Ok(networks.values().cloned().collect())
    }

    /// Connect a container to a network
    pub fn connect_container(
        &self,
        container_id: &str,
        network_id: &str,
        endpoint_config: Option<Endpoint>,
    ) -> Result<()> {
        let span = ExecutionSpan::new(
            "connect_container",
            common::identity::IdentityContext::system(),
        );

        // Get network
        let mut networks = self
            .networks
            .write()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        let network = networks
            .get_mut(network_id)
            .ok_or(ForgeError::NotFound(format!("network: {}", network_id)))?;

        // Create endpoint
        let endpoint = match endpoint_config {
            Some(config) => config,
            None => Endpoint::new(container_id, network_id),
        };

        // Add endpoint to network
        network.add_endpoint(endpoint)?;

        // Add network to container networks
        let mut container_networks = self.container_networks.write().map_err(|_| {
            ForgeError::InternalError("container_networks lock poisoned".to_string())
        })?;

        let networks_set = container_networks
            .entry(container_id.to_string())
            .or_insert_with(HashSet::new);

        networks_set.insert(network_id.to_string());

        Ok(())
    }

    /// Disconnect a container from a network
    pub fn disconnect_container(&self, container_id: &str, network_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "disconnect_container",
            common::identity::IdentityContext::system(),
        );

        // Get network
        let mut networks = self
            .networks
            .write()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        let network = networks
            .get_mut(network_id)
            .ok_or(ForgeError::NotFound(format!("network: {}", network_id)))?;

        // Remove endpoint from network
        network.remove_endpoint(container_id)?;

        // Remove network from container networks
        let mut container_networks = self.container_networks.write().map_err(|_| {
            ForgeError::InternalError("container_networks lock poisoned".to_string())
        })?;

        if let Some(networks_set) = container_networks.get_mut(container_id) {
            networks_set.remove(network_id);

            // Remove container from container_networks if it has no networks
            if networks_set.is_empty() {
                container_networks.remove(container_id);
            }
        }

        Ok(())
    }

    /// Get container networks
    pub fn get_container_networks(&self, container_id: &str) -> Result<Vec<Network>> {
        let span = ExecutionSpan::new(
            "get_container_networks",
            common::identity::IdentityContext::system(),
        );

        // Get container networks
        let container_networks = self.container_networks.read().map_err(|_| {
            ForgeError::InternalError("container_networks lock poisoned".to_string())
        })?;

        let networks_set = container_networks
            .get(container_id)
            .ok_or(ForgeError::NotFound(format!("container: {}", container_id)))?;

        // Get networks
        let networks = self
            .networks
            .read()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        let mut result = Vec::new();
        for network_id in networks_set {
            if let Some(network) = networks.get(network_id) {
                result.push(network.clone());
            }
        }

        Ok(result)
    }

    /// Get container endpoints
    pub fn get_container_endpoints(&self, container_id: &str) -> Result<Vec<Endpoint>> {
        let span = ExecutionSpan::new(
            "get_container_endpoints",
            common::identity::IdentityContext::system(),
        );

        // Get container networks
        let container_networks = self.container_networks.read().map_err(|_| {
            ForgeError::InternalError("container_networks lock poisoned".to_string())
        })?;

        let networks_set = container_networks
            .get(container_id)
            .ok_or(ForgeError::NotFound(format!("container: {}", container_id)))?;

        // Get networks
        let networks = self
            .networks
            .read()
            .map_err(|_| ForgeError::InternalError("networks lock poisoned".to_string()))?;

        let mut result = Vec::new();
        for network_id in networks_set {
            if let Some(network) = networks.get(network_id) {
                if let Some(endpoint) = network.endpoints.get(container_id) {
                    result.push(endpoint.clone());
                }
            }
        }

        Ok(result)
    }

    /// Clean up container networks
    pub fn cleanup_container(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "cleanup_container",
            common::identity::IdentityContext::system(),
        );

        // Get container networks
        let container_networks = self.container_networks.read().map_err(|_| {
            ForgeError::InternalError("container_networks lock poisoned".to_string())
        })?;

        let networks_set = match container_networks.get(container_id) {
            Some(set) => set.clone(),
            None => return Ok(()), // No networks to clean up
        };

        // Disconnect container from all networks
        for network_id in networks_set {
            let _ = self.disconnect_container(container_id, &network_id);
        }

        Ok(())
    }
}

/// Global network manager instance
static mut NETWORK_MANAGER: Option<NetworkManager> = None;

/// Initialize the network manager
pub fn init() -> Result<()> {
    let span = ExecutionSpan::new(
        "init_network_manager",
        common::identity::IdentityContext::system(),
    );

    // Create network manager
    let manager = NetworkManager::new();

    // Store the network manager
    unsafe {
        if NETWORK_MANAGER.is_none() {
            NETWORK_MANAGER = Some(manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "network_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the network manager
pub fn get_network_manager() -> Result<&'static NetworkManager> {
    unsafe {
        match &NETWORK_MANAGER {
            Some(manager) => Ok(manager),
            None => Err(ForgeError::InternalError(
                "network_manager not initialized".to_string(),
            )),
        }
    }
}

/// Create a network
pub fn create_network(config: NetworkConfig) -> Result<String> {
    let manager = get_network_manager()?;
    manager.create_network(config)
}

/// Remove a network
pub fn remove_network(id: &str) -> Result<()> {
    let manager = get_network_manager()?;
    manager.remove_network(id)
}

/// Get a network
pub fn get_network(id: &str) -> Result<Network> {
    let manager = get_network_manager()?;
    manager.get_network(id)
}

/// Get a network by name
pub fn get_network_by_name(name: &str) -> Result<Network> {
    let manager = get_network_manager()?;
    manager.get_network_by_name(name)
}

/// List all networks
pub fn list_networks() -> Result<Vec<Network>> {
    let manager = get_network_manager()?;
    manager.list_networks()
}

/// Connect a container to a network
pub fn connect_container(
    container_id: &str,
    network_id: &str,
    endpoint_config: Option<Endpoint>,
) -> Result<()> {
    let manager = get_network_manager()?;
    manager.connect_container(container_id, network_id, endpoint_config)
}

/// Disconnect a container from a network
pub fn disconnect_container(container_id: &str, network_id: &str) -> Result<()> {
    let manager = get_network_manager()?;
    manager.disconnect_container(container_id, network_id)
}

/// Get container networks
pub fn get_container_networks(container_id: &str) -> Result<Vec<Network>> {
    let manager = get_network_manager()?;
    manager.get_container_networks(container_id)
}

/// Get container endpoints
pub fn get_container_endpoints(container_id: &str) -> Result<Vec<Endpoint>> {
    let manager = get_network_manager()?;
    manager.get_container_endpoints(container_id)
}

/// Clean up container networks
pub fn cleanup_container(container_id: &str) -> Result<()> {
    let manager = get_network_manager()?;
    manager.cleanup_container(container_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_network_manager() {
        // Initialize network manager
        init().unwrap();
        let manager = get_network_manager().unwrap();

        // Create network configuration
        let config = NetworkConfig::new("test-network", NetworkDriverType::Bridge)
            .with_internal(true)
            .with_ipv6(false);

        // Create network
        let network_id = manager.create_network(config).unwrap();

        // Get network
        let network = manager.get_network(&network_id).unwrap();
        assert_eq!(network.config.name, "test-network");
        assert_eq!(network.config.driver, NetworkDriverType::Bridge);
        assert_eq!(network.config.internal, true);

        // Get network by name
        let network = manager.get_network_by_name("test-network").unwrap();
        assert_eq!(network.id, network_id);

        // Connect container to network
        let endpoint = Endpoint::new("test-container", &network_id)
            .with_ipv4(Ipv4Addr::new(172, 17, 0, 2))
            .with_mac("02:42:ac:11:00:02");

        manager
            .connect_container("test-container", &network_id, Some(endpoint))
            .unwrap();

        // Get container networks
        let networks = manager.get_container_networks("test-container").unwrap();
        assert_eq!(networks.len(), 1);
        assert_eq!(networks[0].id, network_id);

        // Get container endpoints
        let endpoints = manager.get_container_endpoints("test-container").unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].container_id, "test-container");
        assert_eq!(endpoints[0].network_id, network_id);
        assert_eq!(
            endpoints[0].ipv4_address,
            Some(Ipv4Addr::new(172, 17, 0, 2))
        );

        // Disconnect container from network
        manager
            .disconnect_container("test-container", &network_id)
            .unwrap();

        // Check container is disconnected
        let result = manager.get_container_networks("test-container");
        assert!(result.is_err());

        // Remove network
        manager.remove_network(&network_id).unwrap();

        // Check network is removed
        let result = manager.get_network(&network_id);
        assert!(result.is_err());
    }
}
