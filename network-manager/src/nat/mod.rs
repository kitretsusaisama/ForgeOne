//! # NAT Module
//!
//! This module provides Network Address Translation functionality
//! for the Quantum-Network Fabric Layer.

use common::error::{ForgeError, Result};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

/// NAT type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// Source NAT (SNAT)
    Source,
    /// Destination NAT (DNAT)
    Destination,
    /// Masquerade (special case of SNAT)
    Masquerade,
}

/// NAT protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatProtocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
    /// All protocols
    All,
}

impl NatProtocol {
    /// Convert to string representation
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::All => "all",
        }
    }
}

/// NAT rule
#[derive(Debug, Clone)]
pub struct NatRule {
    /// Rule ID
    pub id: String,
    /// NAT type
    pub nat_type: NatType,
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    /// Destination IP address
    pub destination_ip: Option<IpAddr>,
    /// Protocol
    pub protocol: NatProtocol,
    /// Source port
    pub source_port: Option<u16>,
    /// Destination port
    pub destination_port: Option<u16>,
    /// Translated IP address
    pub translated_ip: Option<IpAddr>,
    /// Translated port
    pub translated_port: Option<u16>,
    /// External interface
    pub external_interface: Option<String>,
    /// Internal interface
    pub internal_interface: Option<String>,
    /// Network ID this rule belongs to
    pub network_id: String,
}

/// Port mapping
#[derive(Debug, Clone)]
pub struct PortMapping {
    /// Container ID
    pub container_id: String,
    /// Container port
    pub container_port: u16,
    /// Host port
    pub host_port: u16,
    /// Protocol
    pub protocol: NatProtocol,
    /// Host IP to bind to (None means all interfaces)
    pub host_ip: Option<IpAddr>,
}

/// NAT Manager configuration
#[derive(Debug, Clone)]
pub struct NatConfig {
    /// Enable IP forwarding
    pub enable_ip_forwarding: bool,
    /// Enable masquerading
    pub enable_masquerade: bool,
    /// External interface
    pub external_interface: String,
    /// Port range for dynamic port mapping
    pub port_range_start: u16,
    /// Port range for dynamic port mapping
    pub port_range_end: u16,
    /// Maximum number of NAT rules
    pub max_rules: usize,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            enable_ip_forwarding: true,
            enable_masquerade: true,
            external_interface: "eth0".to_string(),
            port_range_start: 32768,
            port_range_end: 60999,
            max_rules: 10000,
        }
    }
}

/// NAT Manager
pub struct NatManager {
    /// Configuration
    config: NatConfig,
    /// NAT rules
    rules: Arc<RwLock<HashMap<String, NatRule>>>,
    /// Port mappings
    port_mappings: Arc<RwLock<HashMap<String, PortMapping>>>,
    /// Used ports
    used_ports: Arc<RwLock<HashSet<u16>>>,
}

impl NatManager {
    /// Create a new NAT manager
    pub fn new(config: NatConfig) -> Self {
        Self {
            config,
            rules: Arc::new(RwLock::new(HashMap::new())),
            port_mappings: Arc::new(RwLock::new(HashMap::new())),
            used_ports: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Initialize the NAT manager
    pub async fn init(&self) -> Result<()> {
        info!("Initializing NAT manager");

        if self.config.enable_ip_forwarding {
            info!("Enabling IP forwarding");
            self.set_ip_forwarding(true).await?;
        }

        if self.config.enable_masquerade {
            info!(
                "Enabling masquerading on interface {}",
                self.config.external_interface
            );
            self.enable_masquerade(&self.config.external_interface).await?;
        }

        Ok(())
    }

    /// Shutdown the NAT manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down NAT manager");

        // Clean up all NAT rules
        let rules = self.rules.read().unwrap();
        for rule in rules.values() {
            self.remove_nat_rule_internal(rule).await?;
        }

        // Disable masquerading if it was enabled
        if self.config.enable_masquerade {
            info!(
                "Disabling masquerading on interface {}",
                self.config.external_interface
            );
            self.disable_masquerade(&self.config.external_interface).await?;
        }

        // Disable IP forwarding if it was enabled
        if self.config.enable_ip_forwarding {
            info!("Disabling IP forwarding");
            self.set_ip_forwarding(false).await?;
        }

        Ok(())
    }

    /// Set IP forwarding
    async fn set_ip_forwarding(&self, enable: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::File;
            use std::io::Write;

            // Set IPv4 forwarding
            let mut file = File::create("/proc/sys/net/ipv4/ip_forward").map_err(|e| {
                ForgeError::NetworkError(format!("Failed to open ip_forward: {}", e))
            })?;
            file.write_all(if enable { b"1" } else { b"0" })
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to write to ip_forward: {}", e))
                })?;

            // Set IPv6 forwarding
            let mut file = File::create("/proc/sys/net/ipv6/conf/all/forwarding").map_err(|e| {
                ForgeError::NetworkError(format!("Failed to open ipv6 forwarding: {}", e))
            })?;
            file.write_all(if enable { b"1" } else { b"0" })
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to write to ipv6 forwarding: {}",
                        e
                    ))
                })?;

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("IP forwarding is only supported on Linux");
            Err(ForgeError::NetworkError(
                "IP forwarding is only supported on Linux".to_string(),
            ))
        }
    }

    /// Enable masquerading on an interface
    async fn enable_masquerade(&self, interface: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            // Add masquerade rule using iptables
            let status = Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    interface,
                    "-j",
                    "MASQUERADE",
                ])
                .status()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to run iptables: {}", e))
                })?;

            if !status.success() {
                return Err(ForgeError::NetworkError(format!(
                    "Failed to enable masquerading: {}",
                    status
                )));
            }

            // Add masquerade rule for IPv6 using ip6tables
            let status = Command::new("ip6tables")
                .args([
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    interface,
                    "-j",
                    "MASQUERADE",
                ])
                .status()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to run ip6tables: {}", e))
                })?;

            if !status.success() {
                warn!("Failed to enable IPv6 masquerading: {}", status);
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("Masquerading is only supported on Linux");
            Err(ForgeError::NetworkError(
                "Masquerading is only supported on Linux".to_string(),
            ))
        }
    }

    /// Disable masquerading on an interface
    async fn disable_masquerade(&self, interface: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            // Remove masquerade rule using iptables
            let status = Command::new("iptables")
                .args([
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    interface,
                    "-j",
                    "MASQUERADE",
                ])
                .status()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to run iptables: {}", e))
                })?;

            if !status.success() {
                warn!("Failed to disable masquerading: {}", status);
            }

            // Remove masquerade rule for IPv6 using ip6tables
            let status = Command::new("ip6tables")
                .args([
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-o",
                    interface,
                    "-j",
                    "MASQUERADE",
                ])
                .status()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to run ip6tables: {}", e))
                })?;

            if !status.success() {
                warn!("Failed to disable IPv6 masquerading: {}", status);
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("Masquerading is only supported on Linux");
            Err(ForgeError::NetworkError(
                "Masquerading is only supported on Linux".to_string(),
            ))
        }
    }

    /// Add a NAT rule
    pub async fn add_nat_rule(&self, rule: NatRule) -> Result<()> {
        info!("Adding NAT rule: {:?}", rule);

        // Check if we've reached the maximum number of rules
        {
            let rules = self.rules.read().unwrap();
            if rules.len() >= self.config.max_rules {
                return Err(ForgeError::NetworkError(
                    "Maximum number of NAT rules reached".to_string(),
                ));
            }
        }

        // Apply the rule
        self.apply_nat_rule(&rule).await?;

        // Store the rule
        let mut rules = self.rules.write().unwrap();
        rules.insert(rule.id.clone(), rule);

        Ok(())
    }

    /// Remove a NAT rule
    pub async fn remove_nat_rule(&self, rule_id: &str) -> Result<()> {
        info!("Removing NAT rule: {}", rule_id);

        // Get the rule
        let rule = {
            let rules = self.rules.read().unwrap();
            match rules.get(rule_id) {
                Some(r) => r.clone(),
                None => {
                    return Err(ForgeError::NetworkError(format!(
                        "NAT rule {} not found",
                        rule_id
                    )))
                }
            }
        };

        // Remove the rule
        self.remove_nat_rule_internal(&rule).await?;

        // Remove from storage
        let mut rules = self.rules.write().unwrap();
        rules.remove(rule_id);

        Ok(())
    }

    /// Apply a NAT rule
    async fn apply_nat_rule(&self, rule: &NatRule) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            // Determine the iptables command based on IP version
            let is_ipv6 = match (&rule.source_ip, &rule.destination_ip, &rule.translated_ip) {
                (Some(IpAddr::V6(_)), _, _) => true,
                (_, Some(IpAddr::V6(_)), _) => true,
                (_, _, Some(IpAddr::V6(_))) => true,
                _ => false,
            };

            let iptables_cmd = if is_ipv6 { "ip6tables" } else { "iptables" };

            // Build the iptables command based on the rule type
            let mut args = vec!["-t", "nat"];

            match rule.nat_type {
                NatType::Source => {
                    args.push("-A");
                    args.push("POSTROUTING");

                    // Source specification
                    if let Some(source_ip) = &rule.source_ip {
                        args.push("-s");
                        args.push(&source_ip.to_string());
                    }

                    // Destination specification
                    if let Some(dest_ip) = &rule.destination_ip {
                        args.push("-d");
                        args.push(&dest_ip.to_string());
                    }

                    // Protocol specification
                    if rule.protocol != NatProtocol::All {
                        args.push("-p");
                        args.push(rule.protocol.to_string());

                        // Port specifications
                        if let Some(source_port) = rule.source_port {
                            args.push("--sport");
                            args.push(&source_port.to_string());
                        }

                        if let Some(dest_port) = rule.destination_port {
                            args.push("--dport");
                            args.push(&dest_port.to_string());
                        }
                    }

                    // Output interface
                    if let Some(iface) = &rule.external_interface {
                        args.push("-o");
                        args.push(iface);
                    }

                    // SNAT target
                    args.push("-j");
                    args.push("SNAT");
                    args.push("--to-source");

                    // Translated address and port
                    let mut to_source = rule
                        .translated_ip
                        .as_ref()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "0.0.0.0".to_string());

                    if let Some(port) = rule.translated_port {
                        to_source = format!("{to_source}:{port}");
                    }

                    args.push(&to_source);
                }
                NatType::Destination => {
                    args.push("-A");
                    args.push("PREROUTING");

                    // Source specification
                    if let Some(source_ip) = &rule.source_ip {
                        args.push("-s");
                        args.push(&source_ip.to_string());
                    }

                    // Destination specification
                    if let Some(dest_ip) = &rule.destination_ip {
                        args.push("-d");
                        args.push(&dest_ip.to_string());
                    }

                    // Protocol specification
                    if rule.protocol != NatProtocol::All {
                        args.push("-p");
                        args.push(rule.protocol.to_string());

                        // Port specifications
                        if let Some(source_port) = rule.source_port {
                            args.push("--sport");
                            args.push(&source_port.to_string());
                        }

                        if let Some(dest_port) = rule.destination_port {
                            args.push("--dport");
                            args.push(&dest_port.to_string());
                        }
                    }

                    // Input interface
                    if let Some(iface) = &rule.external_interface {
                        args.push("-i");
                        args.push(iface);
                    }

                    // DNAT target
                    args.push("-j");
                    args.push("DNAT");
                    args.push("--to-destination");

                    // Translated address and port
                    let mut to_dest = rule
                        .translated_ip
                        .as_ref()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "0.0.0.0".to_string());

                    if let Some(port) = rule.translated_port {
                        to_dest = format!("{to_dest}:{port}");
                    }

                    args.push(&to_dest);
                }
                NatType::Masquerade => {
                    args.push("-A");
                    args.push("POSTROUTING");

                    // Source specification
                    if let Some(source_ip) = &rule.source_ip {
                        args.push("-s");
                        args.push(&source_ip.to_string());
                    }

                    // Destination specification
                    if let Some(dest_ip) = &rule.destination_ip {
                        args.push("-d");
                        args.push(&dest_ip.to_string());
                    }

                    // Protocol specification
                    if rule.protocol != NatProtocol::All {
                        args.push("-p");
                        args.push(rule.protocol.to_string());

                        // Port specifications
                        if let Some(source_port) = rule.source_port {
                            args.push("--sport");
                            args.push(&source_port.to_string());
                        }

                        if let Some(dest_port) = rule.destination_port {
                            args.push("--dport");
                            args.push(&dest_port.to_string());
                        }
                    }

                    // Output interface
                    if let Some(iface) = &rule.external_interface {
                        args.push("-o");
                        args.push(iface);
                    }

                    // Masquerade target
                    args.push("-j");
                    args.push("MASQUERADE");
                }
            }

            // Execute the iptables command
            let status = Command::new(iptables_cmd)
                .args(args)
                .status()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to run {}: {}", iptables_cmd, e))
                })?;

            if !status.success() {
                return Err(ForgeError::NetworkError(format!(
                    "Failed to apply NAT rule: {}",
                    status
                )));
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("NAT rules are only supported on Linux");
            Err(ForgeError::NetworkError(
                "NAT rules are only supported on Linux".to_string(),
            ))
        }
    }

    /// Remove a NAT rule
    async fn remove_nat_rule_internal(&self, rule: &NatRule) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;

            // Determine the iptables command based on IP version
            let is_ipv6 = match (&rule.source_ip, &rule.destination_ip, &rule.translated_ip) {
                (Some(IpAddr::V6(_)), _, _) => true,
                (_, Some(IpAddr::V6(_)), _) => true,
                (_, _, Some(IpAddr::V6(_))) => true,
                _ => false,
            };

            let iptables_cmd = if is_ipv6 { "ip6tables" } else { "iptables" };

            // Build the iptables command based on the rule type
            let mut args = vec!["-t", "nat"];

            match rule.nat_type {
                NatType::Source => {
                    args.push("-D");
                    args.push("POSTROUTING");

                    // Source specification
                    if let Some(source_ip) = &rule.source_ip {
                        args.push("-s");
                        args.push(&source_ip.to_string());
                    }

                    // Destination specification
                    if let Some(dest_ip) = &rule.destination_ip {
                        args.push("-d");
                        args.push(&dest_ip.to_string());
                    }

                    // Protocol specification
                    if rule.protocol != NatProtocol::All {
                        args.push("-p");
                        args.push(rule.protocol.to_string());

                        // Port specifications
                        if let Some(source_port) = rule.source_port {
                            args.push("--sport");
                            args.push(&source_port.to_string());
                        }

                        if let Some(dest_port) = rule.destination_port {
                            args.push("--dport");
                            args.push(&dest_port.to_string());
                        }
                    }

                    // Output interface
                    if let Some(iface) = &rule.external_interface {
                        args.push("-o");
                        args.push(iface);
                    }

                    // SNAT target
                    args.push("-j");
                    args.push("SNAT");
                    args.push("--to-source");

                    // Translated address and port
                    let mut to_source = rule
                        .translated_ip
                        .as_ref()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "0.0.0.0".to_string());

                    if let Some(port) = rule.translated_port {
                        to_source = format!("{to_source}:{port}");
                    }

                    args.push(&to_source);
                }
                NatType::Destination => {
                    args.push("-D");
                    args.push("PREROUTING");

                    // Source specification
                    if let Some(source_ip) = &rule.source_ip {
                        args.push("-s");
                        args.push(&source_ip.to_string());
                    }

                    // Destination specification
                    if let Some(dest_ip) = &rule.destination_ip {
                        args.push("-d");
                        args.push(&dest_ip.to_string());
                    }

                    // Protocol specification
                    if rule.protocol != NatProtocol::All {
                        args.push("-p");
                        args.push(rule.protocol.to_string());

                        // Port specifications
                        if let Some(source_port) = rule.source_port {
                            args.push("--sport");
                            args.push(&source_port.to_string());
                        }

                        if let Some(dest_port) = rule.destination_port {
                            args.push("--dport");
                            args.push(&dest_port.to_string());
                        }
                    }

                    // Input interface
                    if let Some(iface) = &rule.external_interface {
                        args.push("-i");
                        args.push(iface);
                    }

                    // DNAT target
                    args.push("-j");
                    args.push("DNAT");
                    args.push("--to-destination");

                    // Translated address and port
                    let mut to_dest = rule
                        .translated_ip
                        .as_ref()
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "0.0.0.0".to_string());

                    if let Some(port) = rule.translated_port {
                        to_dest = format!("{to_dest}:{port}");
                    }

                    args.push(&to_dest);
                }
                NatType::Masquerade => {
                    args.push("-D");
                    args.push("POSTROUTING");

                    // Source specification
                    if let Some(source_ip) = &rule.source_ip {
                        args.push("-s");
                        args.push(&source_ip.to_string());
                    }

                    // Destination specification
                    if let Some(dest_ip) = &rule.destination_ip {
                        args.push("-d");
                        args.push(&dest_ip.to_string());
                    }

                    // Protocol specification
                    if rule.protocol != NatProtocol::All {
                        args.push("-p");
                        args.push(rule.protocol.to_string());

                        // Port specifications
                        if let Some(source_port) = rule.source_port {
                            args.push("--sport");
                            args.push(&source_port.to_string());
                        }

                        if let Some(dest_port) = rule.destination_port {
                            args.push("--dport");
                            args.push(&dest_port.to_string());
                        }
                    }

                    // Output interface
                    if let Some(iface) = &rule.external_interface {
                        args.push("-o");
                        args.push(iface);
                    }

                    // Masquerade target
                    args.push("-j");
                    args.push("MASQUERADE");
                }
            }

            // Execute the iptables command
            let status = Command::new(iptables_cmd)
                .args(args)
                .status()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to run {}: {}", iptables_cmd, e))
                })?;

            if !status.success() {
                warn!("Failed to remove NAT rule: {}", status);
            }

            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        {
            warn!("NAT rules are only supported on Linux");
            Err(ForgeError::NetworkError(
                "NAT rules are only supported on Linux".to_string(),
            ))
        }
    }

    /// Create a port mapping
    pub async fn create_port_mapping(
        &self,
        container_id: &str,
        container_ip: IpAddr,
        container_port: u16,
        host_port: Option<u16>,
        protocol: NatProtocol,
        host_ip: Option<IpAddr>,
    ) -> Result<PortMapping> {
        info!(
            "Creating port mapping for container {} port {}",
            container_id, container_port
        );

        // Allocate a host port if not provided
        let host_port = match host_port {
            Some(port) => {
                // Check if the port is already in use
                let used_ports = self.used_ports.read().unwrap();
                if used_ports.contains(&port) {
                    return Err(ForgeError::NetworkError(format!(
                        "Host port {} is already in use",
                        port
                    )));
                }
                port
            }
            None => self.allocate_port()?,
        };

        // Create the port mapping
        let mapping = PortMapping {
            container_id: container_id.to_string(),
            container_port,
            host_port,
            protocol,
            host_ip,
        };

        // Create a NAT rule for this port mapping
        let rule_id = format!(
            "portmap-{}-{}-{}-{}",
            container_id, container_port, host_port, protocol.to_string()
        );

        let rule = NatRule {
            id: rule_id.clone(),
            nat_type: NatType::Destination,
            source_ip: None,
            destination_ip: host_ip,
            protocol,
            source_port: None,
            destination_port: Some(host_port),
            translated_ip: Some(container_ip),
            translated_port: Some(container_port),
            external_interface: Some(self.config.external_interface.clone()),
            internal_interface: None,
            network_id: "portmap".to_string(),
        };

        // Apply the NAT rule
        self.apply_nat_rule(&rule).await?;

        // Store the rule and mapping
        {
            let mut rules = self.rules.write().unwrap();
            rules.insert(rule_id, rule);

            let mut mappings = self.port_mappings.write().unwrap();
            mappings.insert(mapping.container_id.clone(), mapping.clone());

            let mut used_ports = self.used_ports.write().unwrap();
            used_ports.insert(host_port);
        }

        Ok(mapping)
    }

    /// Remove a port mapping
    pub async fn remove_port_mapping(
        &self,
        container_id: &str,
        container_port: u16,
        protocol: NatProtocol,
    ) -> Result<()> {
        info!(
            "Removing port mapping for container {} port {}",
            container_id, container_port
        );

        // Find the mapping
        let mapping = {
            let mappings = self.port_mappings.read().unwrap();
            match mappings.get(container_id) {
                Some(m) if m.container_port == container_port && m.protocol == protocol => {
                    m.clone()
                }
                _ => {
                    return Err(ForgeError::NetworkError(format!(
                        "Port mapping for container {} port {} not found",
                        container_id, container_port
                    )))
                }
            }
        };

        // Remove the NAT rule
        let rule_id = format!(
            "portmap-{}-{}-{}-{}",
            container_id, container_port, mapping.host_port, protocol.to_string()
        );

        self.remove_nat_rule(&rule_id).await?;

        // Remove the mapping and free the port
        {
            let mut mappings = self.port_mappings.write().unwrap();
            mappings.remove(container_id);

            let mut used_ports = self.used_ports.write().unwrap();
            used_ports.remove(&mapping.host_port);
        }

        Ok(())
    }

    /// Allocate a port from the port range
    fn allocate_port(&self) -> Result<u16> {
        let mut used_ports = self.used_ports.write().unwrap();

        // Find an unused port in the range
        for port in self.config.port_range_start..=self.config.port_range_end {
            if !used_ports.contains(&port) {
                used_ports.insert(port);
                return Ok(port);
            }
        }

        Err(ForgeError::NetworkError(
            "No available ports in the port range".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_config_default() {
        let config = NatConfig::default();
        assert!(config.enable_ip_forwarding);
        assert!(config.enable_masquerade);
        assert_eq!(config.external_interface, "eth0");
        assert_eq!(config.port_range_start, 32768);
        assert_eq!(config.port_range_end, 60999);
        assert_eq!(config.max_rules, 10000);
    }

    #[test]
    fn test_nat_protocol() {
        assert_eq!(NatProtocol::Tcp.to_string(), "tcp");
        assert_eq!(NatProtocol::Udp.to_string(), "udp");
        assert_eq!(NatProtocol::Icmp.to_string(), "icmp");
        assert_eq!(NatProtocol::All.to_string(), "all");
    }

    #[test]
    fn test_nat_rule() {
        let rule = NatRule {
            id: "test-rule".to_string(),
            nat_type: NatType::Destination,
            source_ip: None,
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            protocol: NatProtocol::Tcp,
            source_port: None,
            destination_port: Some(80),
            translated_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            translated_port: Some(8080),
            external_interface: Some("eth0".to_string()),
            internal_interface: None,
            network_id: "network1".to_string(),
        };

        assert_eq!(rule.id, "test-rule");
        assert_eq!(rule.nat_type, NatType::Destination);
        assert_eq!(rule.protocol, NatProtocol::Tcp);
        assert_eq!(rule.destination_port, Some(80));
        assert_eq!(
            rule.translated_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert_eq!(rule.translated_port, Some(8080));
    }

    #[test]
    fn test_port_mapping() {
        let mapping = PortMapping {
            container_id: "container1".to_string(),
            container_port: 8080,
            host_port: 80,
            protocol: NatProtocol::Tcp,
            host_ip: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        };

        assert_eq!(mapping.container_id, "container1");
        assert_eq!(mapping.container_port, 8080);
        assert_eq!(mapping.host_port, 80);
        assert_eq!(mapping.protocol, NatProtocol::Tcp);
        assert_eq!(
            mapping.host_ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }
}