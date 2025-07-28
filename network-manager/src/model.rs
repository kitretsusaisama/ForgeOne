//! # Network Manager Model
//!
//! This module defines the core data structures and types used throughout the network manager.

use common::trust::{Action, ZtaPolicyGraph};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// Network isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// Full isolation - no communication allowed outside the network
    Full,
    /// Peer-only isolation - only communication with peers in the same network
    PeerOnly,
    /// Mesh-only isolation - only communication with mesh-enabled containers
    MeshOnly,
    /// No isolation - all communication allowed
    None,
}

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

/// Virtual network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualNetwork {
    /// Network ID
    pub id: String,
    /// Network name
    pub name: String,
    /// Network CIDR
    pub cidr: String,
    /// Network gateway
    pub gateway: IpAddr,
    /// Network driver
    pub driver: NetworkDriverType,
    /// Network isolation level
    pub isolation_mode: IsolationLevel,
    /// Network options
    pub options: HashMap<String, String>,
    /// Network labels
    pub labels: HashMap<String, String>,
    /// Network creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl VirtualNetwork {
    /// Create a new virtual network
    pub fn new(
        name: String,
        cidr: String,
        gateway: IpAddr,
        driver: NetworkDriverType,
        isolation_mode: IsolationLevel,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            cidr,
            gateway,
            driver,
            isolation_mode,
            options: HashMap::new(),
            labels: HashMap::new(),
            created_at: chrono::Utc::now(),
        }
    }
}

/// Network endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    /// Endpoint ID
    pub id: String,
    /// Container ID
    pub container_id: String,
    /// Network ID
    pub network_id: String,
    /// Endpoint IP address
    pub ip: IpAddr,
    /// Endpoint MAC address
    pub mac: String,
    /// Endpoint interface name
    pub interface: String,
    /// Endpoint creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Endpoint {
    /// Create a new endpoint
    pub fn new(container_id: String, network_id: String, ip: IpAddr, interface: String) -> Self {
        // Generate a MAC address based on the IP
        let mac = match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("02:42:{:02x}:{:02x}:{:02x}:{:02x}", octets[0], octets[1], octets[2], octets[3])
            }
            IpAddr::V6(ipv6) => {
                let segments = ipv6.segments();
                format!(
                    "02:42:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    segments[0] & 0xFF,
                    segments[1] & 0xFF,
                    segments[2] & 0xFF,
                    segments[3] & 0xFF,
                    segments[4] & 0xFF,
                    segments[5] & 0xFF
                )
            }
        };

        Self {
            id: Uuid::new_v4().to_string(),
            container_id,
            network_id,
            ip,
            mac,
            interface,
            created_at: chrono::Utc::now(),
        }
    }
}

/// Firewall policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallPolicy {
    /// Allowed ports
    pub allow_ports: Vec<u16>,
    /// Trusted peers
    pub trusted_peers: Vec<IpAddr>,
    /// Rate limit in packets per second
    pub rate_limit: Option<u32>,
    /// Zero Trust policy graph
    pub zta_policy: Option<ZtaPolicyGraph>,
}

impl Default for FirewallPolicy {
    fn default() -> Self {
        Self {
            allow_ports: Vec::new(),
            trusted_peers: Vec::new(),
            rate_limit: None,
            zta_policy: None,
        }
    }
}

/// Network statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Bytes received
    pub bytes_in: u64,
    /// Bytes sent
    pub bytes_out: u64,
    /// Packets received
    pub packets_in: u64,
    /// Packets sent
    pub packets_out: u64,
    /// DNS queries
    pub dns_queries: u32,
    /// Firewall blocks
    pub firewall_blocks: u32,
    /// Last updated
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl NetworkStats {
    /// Create new network statistics
    pub fn new() -> Self {
        Self {
            last_updated: chrono::Utc::now(),
            ..Default::default()
        }
    }

    /// Update statistics
    pub fn update(&mut self, bytes_in: u64, bytes_out: u64, packets_in: u64, packets_out: u64) {
        self.bytes_in += bytes_in;
        self.bytes_out += bytes_out;
        self.packets_in += packets_in;
        self.packets_out += packets_out;
        self.last_updated = chrono::Utc::now();
    }

    /// Record a DNS query
    pub fn record_dns_query(&mut self) {
        self.dns_queries += 1;
        self.last_updated = chrono::Utc::now();
    }

    /// Record a firewall block
    pub fn record_firewall_block(&mut self) {
        self.firewall_blocks += 1;
        self.last_updated = chrono::Utc::now();
    }
}

/// Network manager state
#[derive(Debug)]
pub struct NetworkManagerState {
    /// Virtual networks
    pub networks: HashMap<String, VirtualNetwork>,
    /// Endpoints
    pub endpoints: HashMap<String, Endpoint>,
    /// Firewall policies
    pub firewall_policies: HashMap<String, FirewallPolicy>,
    /// Network statistics
    pub stats: HashMap<String, NetworkStats>,
}

impl NetworkManagerState {
    /// Create a new network manager state
    pub fn new() -> Self {
        Self {
            networks: HashMap::new(),
            endpoints: HashMap::new(),
            firewall_policies: HashMap::new(),
            stats: HashMap::new(),
        }
    }
}

/// Shared network manager state
pub type SharedNetworkManagerState = Arc<RwLock<NetworkManagerState>>;

/// Create a new shared network manager state
pub fn new_shared_state() -> SharedNetworkManagerState {
    Arc::new(RwLock::new(NetworkManagerState::new()))
}