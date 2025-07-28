//! # Firewall Policy Module
//!
//! This module defines the firewall policy data structures and implementation
//! for the Zero Trust Network Manager.

use common::error::{ForgeError, Result};
use std::net::IpAddr;
use std::process::Command;
use tracing::{debug, error, info};

/// Firewall protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProtocol {
    /// TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
    /// ICMP protocol
    Icmp,
    /// Any protocol
    Any,
}

impl FirewallProtocol {
    /// Convert to string representation for iptables
    pub fn to_iptables_string(&self) -> &'static str {
        match self {
            FirewallProtocol::Tcp => "tcp",
            FirewallProtocol::Udp => "udp",
            FirewallProtocol::Icmp => "icmp",
            FirewallProtocol::Any => "all",
        }
    }

    /// Convert to string representation for nftables
    pub fn to_nftables_string(&self) -> &'static str {
        match self {
            FirewallProtocol::Tcp => "tcp",
            FirewallProtocol::Udp => "udp",
            FirewallProtocol::Icmp => "icmp",
            FirewallProtocol::Any => "ip",
        }
    }
}

/// Firewall action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    /// Allow traffic
    Allow,
    /// Deny traffic
    Deny,
    /// Log traffic
    Log,
}

impl FirewallAction {
    /// Convert to string representation for iptables
    pub fn to_iptables_string(&self) -> &'static str {
        match self {
            FirewallAction::Allow => "ACCEPT",
            FirewallAction::Deny => "DROP",
            FirewallAction::Log => "LOG",
        }
    }

    /// Convert to string representation for nftables
    pub fn to_nftables_string(&self) -> &'static str {
        match self {
            FirewallAction::Allow => "accept",
            FirewallAction::Deny => "drop",
            FirewallAction::Log => "log",
        }
    }
}

/// Firewall rule
#[derive(Debug, Clone)]
pub struct FirewallRule {
    /// Source IP address
    pub source: Option<IpAddr>,
    /// Destination IP address
    pub destination: Option<IpAddr>,
    /// Protocol
    pub protocol: FirewallProtocol,
    /// Port number
    pub port: Option<u16>,
    /// Action
    pub action: FirewallAction,
}

/// Firewall policy
#[derive(Debug, Clone)]
pub struct FirewallPolicy {
    /// Network ID
    pub network_id: String,
    /// Source ID (container, pod, etc.)
    pub source_id: String,
    /// Rules
    pub rules: Vec<FirewallRule>,
}

/// Apply a rule using iptables
pub async fn apply_iptables_rule(rule: &FirewallRule) -> Result<()> {
    let mut cmd = Command::new("iptables");
    cmd.arg("-A").arg("FORWARD");

    // Add source IP if specified
    if let Some(src) = rule.source {
        cmd.arg("-s").arg(src.to_string());
    }

    // Add destination IP if specified
    if let Some(dst) = rule.destination {
        cmd.arg("-d").arg(dst.to_string());
    }

    // Add protocol
    cmd.arg("-p").arg(rule.protocol.to_iptables_string());

    // Add port if specified
    if let Some(port) = rule.port {
        cmd.arg("--dport").arg(port.to_string());
    }

    // Add action
    cmd.arg("-j").arg(rule.action.to_iptables_string());

    // Execute the command
    let output = cmd.output().map_err(|e| {
        ForgeError::NetworkError(format!("Failed to execute iptables command: {}", e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "iptables command failed: {}",
            stderr
        )));
    }

    Ok(())
}

/// Apply a rule using nftables
pub async fn apply_nftables_rule(rule: &FirewallRule) -> Result<()> {
    let mut cmd = Command::new("nft");
    cmd.arg("add").arg("rule").arg("filter").arg("forward");

    // Add source IP if specified
    if let Some(src) = rule.source {
        cmd.arg("ip").arg("saddr").arg(src.to_string());
    }

    // Add destination IP if specified
    if let Some(dst) = rule.destination {
        cmd.arg("ip").arg("daddr").arg(dst.to_string());
    }

    // Add protocol
    cmd.arg(rule.protocol.to_nftables_string());

    // Add port if specified
    if let Some(port) = rule.port {
        cmd.arg("dport").arg(port.to_string());
    }

    // Add action
    cmd.arg(rule.action.to_nftables_string());

    // Execute the command
    let output = cmd.output().map_err(|e| {
        ForgeError::NetworkError(format!("Failed to execute nft command: {}", e))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "nft command failed: {}",
            stderr
        )));
    }

    Ok(())
}

/// Apply a policy using iptables
pub async fn apply_iptables_policy(policy: &FirewallPolicy) -> Result<()> {
    // Create a chain for this policy
    let chain_name = format!("FORGE_{}", policy.network_id.replace("-", "_"));

    // Create the chain
    let create_chain = Command::new("iptables")
        .arg("-N")
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create iptables chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !create_chain.status.success() {
        let stderr = String::from_utf8_lossy(&create_chain.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create iptables chain: {}",
                stderr
            )));
        }
    }

    // Add rules to the chain
    for rule in &policy.rules {
        let mut cmd = Command::new("iptables");
        cmd.arg("-A").arg(&chain_name);

        // Add source IP if specified
        if let Some(src) = rule.source {
            cmd.arg("-s").arg(src.to_string());
        }

        // Add destination IP if specified
        if let Some(dst) = rule.destination {
            cmd.arg("-d").arg(dst.to_string());
        }

        // Add protocol
        cmd.arg("-p").arg(rule.protocol.to_iptables_string());

        // Add port if specified
        if let Some(port) = rule.port {
            cmd.arg("--dport").arg(port.to_string());
        }

        // Add action
        cmd.arg("-j").arg(rule.action.to_iptables_string());

        // Execute the command
        let output = cmd.output().map_err(|e| {
            ForgeError::NetworkError(format!("Failed to execute iptables command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ForgeError::NetworkError(format!(
                "iptables command failed: {}",
                stderr
            )));
        }
    }

    // Add a jump to the chain from FORWARD
    let jump_cmd = Command::new("iptables")
        .arg("-A")
        .arg("FORWARD")
        .arg("-j")
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add jump to iptables chain: {}", e))
        })?;

    if !jump_cmd.status.success() {
        let stderr = String::from_utf8_lossy(&jump_cmd.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add jump to iptables chain: {}",
            stderr
        )));
    }

    Ok(())
}

/// Remove a policy using iptables
pub async fn remove_iptables_policy(policy: &FirewallPolicy) -> Result<()> {
    // Get the chain name
    let chain_name = format!("FORGE_{}", policy.network_id.replace("-", "_"));

    // Remove the jump to the chain from FORWARD
    let remove_jump = Command::new("iptables")
        .arg("-D")
        .arg("FORWARD")
        .arg("-j")
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!(
                "Failed to remove jump to iptables chain: {}",
                e
            ))
        })?;

    // Ignore if rule doesn't exist
    if !remove_jump.status.success() {
        let stderr = String::from_utf8_lossy(&remove_jump.stderr);
        if !stderr.contains("No chain/target/match by that name") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to remove jump to iptables chain: {}",
                stderr
            )));
        }
    }

    // Flush the chain
    let flush_chain = Command::new("iptables")
        .arg("-F")
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to flush iptables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !flush_chain.status.success() {
        let stderr = String::from_utf8_lossy(&flush_chain.stderr);
        if !stderr.contains("No chain/target/match by that name") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to flush iptables chain: {}",
                stderr
            )));
        }
    }

    // Delete the chain
    let delete_chain = Command::new("iptables")
        .arg("-X")
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to delete iptables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !delete_chain.status.success() {
        let stderr = String::from_utf8_lossy(&delete_chain.stderr);
        if !stderr.contains("No chain/target/match by that name") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to delete iptables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Apply a policy using nftables
pub async fn apply_nftables_policy(policy: &FirewallPolicy) -> Result<()> {
    // Create a table and chain for this policy
    let table_name = "forge";
    let chain_name = format!("forge_{}", policy.network_id.replace("-", "_"));

    // Create the table if it doesn't exist
    let create_table = Command::new("nft")
        .arg("add")
        .arg("table")
        .arg("inet")
        .arg(table_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create nftables table: {}", e))
        })?;

    // Ignore if table already exists
    if !create_table.status.success() {
        let stderr = String::from_utf8_lossy(&create_table.stderr);
        if !stderr.contains("Table already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create nftables table: {}",
                stderr
            )));
        }
    }

    // Create the chain
    let create_chain = Command::new("nft")
        .arg("add")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(&chain_name)
        .arg("{")
        .arg("type")
        .arg("filter")
        .arg("hook")
        .arg("forward")
        .arg("priority")
        .arg("0")
        .arg(";")
        .arg("}")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create nftables chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !create_chain.status.success() {
        let stderr = String::from_utf8_lossy(&create_chain.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create nftables chain: {}",
                stderr
            )));
        }
    }

    // Add rules to the chain
    for rule in &policy.rules {
        let mut cmd = Command::new("nft");
        cmd.arg("add")
            .arg("rule")
            .arg("inet")
            .arg(table_name)
            .arg(&chain_name);

        // Add source IP if specified
        if let Some(src) = rule.source {
            cmd.arg("ip").arg("saddr").arg(src.to_string());
        }

        // Add destination IP if specified
        if let Some(dst) = rule.destination {
            cmd.arg("ip").arg("daddr").arg(dst.to_string());
        }

        // Add protocol
        cmd.arg(rule.protocol.to_nftables_string());

        // Add port if specified
        if let Some(port) = rule.port {
            cmd.arg("dport").arg(port.to_string());
        }

        // Add action
        cmd.arg(rule.action.to_nftables_string());

        // Execute the command
        let output = cmd.output().map_err(|e| {
            ForgeError::NetworkError(format!("Failed to execute nft command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ForgeError::NetworkError(format!(
                "nft command failed: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Remove a policy using nftables
pub async fn remove_nftables_policy(policy: &FirewallPolicy) -> Result<()> {
    // Get the table and chain name
    let table_name = "forge";
    let chain_name = format!("forge_{}", policy.network_id.replace("-", "_"));

    // Flush the chain
    let flush_chain = Command::new("nft")
        .arg("flush")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to flush nftables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !flush_chain.status.success() {
        let stderr = String::from_utf8_lossy(&flush_chain.stderr);
        if !stderr.contains("No such file or directory") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to flush nftables chain: {}",
                stderr
            )));
        }
    }

    // Delete the chain
    let delete_chain = Command::new("nft")
        .arg("delete")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(&chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to delete nftables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !delete_chain.status.success() {
        let stderr = String::from_utf8_lossy(&delete_chain.stderr);
        if !stderr.contains("No such file or directory") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to delete nftables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Initialize iptables
pub async fn iptables_init(default_policy: &str) -> Result<()> {
    // Create the FORGE chain
    let create_chain = Command::new("iptables")
        .arg("-N")
        .arg("FORGE")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create FORGE chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !create_chain.status.success() {
        let stderr = String::from_utf8_lossy(&create_chain.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create FORGE chain: {}",
                stderr
            )));
        }
    }

    // Set the default policy for the FORGE chain
    let set_policy = Command::new("iptables")
        .arg("-P")
        .arg("FORGE")
        .arg(default_policy)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!(
                "Failed to set default policy for FORGE chain: {}",
                e
            ))
        })?;

    if !set_policy.status.success() {
        let stderr = String::from_utf8_lossy(&set_policy.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to set default policy for FORGE chain: {}",
            stderr
        )));
    }

    // Add a jump to the FORGE chain from FORWARD
    let jump_cmd = Command::new("iptables")
        .arg("-A")
        .arg("FORWARD")
        .arg("-j")
        .arg("FORGE")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!(
                "Failed to add jump to FORGE chain: {}",
                e
            ))
        })?;

    if !jump_cmd.status.success() {
        let stderr = String::from_utf8_lossy(&jump_cmd.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add jump to FORGE chain: {}",
            stderr
        )));
    }

    Ok(())
}

/// Initialize nftables
pub async fn nftables_init(default_policy: &str) -> Result<()> {
    // Create the forge table
    let create_table = Command::new("nft")
        .arg("add")
        .arg("table")
        .arg("inet")
        .arg("forge")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create forge table: {}", e))
        })?;

    // Ignore if table already exists
    if !create_table.status.success() {
        let stderr = String::from_utf8_lossy(&create_table.stderr);
        if !stderr.contains("Table already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create forge table: {}",
                stderr
            )));
        }
    }

    // Create the forward chain
    let create_chain = Command::new("nft")
        .arg("add")
        .arg("chain")
        .arg("inet")
        .arg("forge")
        .arg("forward")
        .arg("{")
        .arg("type")
        .arg("filter")
        .arg("hook")
        .arg("forward")
        .arg("priority")
        .arg("0")
        .arg(";")
        .arg("policy")
        .arg(default_policy)
        .arg(";")
        .arg("}")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create forward chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !create_chain.status.success() {
        let stderr = String::from_utf8_lossy(&create_chain.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create forward chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_protocol_conversion() {
        assert_eq!(FirewallProtocol::Tcp.to_iptables_string(), "tcp");
        assert_eq!(FirewallProtocol::Udp.to_iptables_string(), "udp");
        assert_eq!(FirewallProtocol::Icmp.to_iptables_string(), "icmp");
        assert_eq!(FirewallProtocol::Any.to_iptables_string(), "all");

        assert_eq!(FirewallProtocol::Tcp.to_nftables_string(), "tcp");
        assert_eq!(FirewallProtocol::Udp.to_nftables_string(), "udp");
        assert_eq!(FirewallProtocol::Icmp.to_nftables_string(), "icmp");
        assert_eq!(FirewallProtocol::Any.to_nftables_string(), "ip");
    }

    #[test]
    fn test_action_conversion() {
        assert_eq!(FirewallAction::Allow.to_iptables_string(), "ACCEPT");
        assert_eq!(FirewallAction::Deny.to_iptables_string(), "DROP");
        assert_eq!(FirewallAction::Log.to_iptables_string(), "LOG");

        assert_eq!(FirewallAction::Allow.to_nftables_string(), "accept");
        assert_eq!(FirewallAction::Deny.to_nftables_string(), "drop");
        assert_eq!(FirewallAction::Log.to_nftables_string(), "log");
    }

    #[test]
    fn test_firewall_rule_creation() {
        let rule = FirewallRule {
            source: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            destination: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
            protocol: FirewallProtocol::Tcp,
            port: Some(80),
            action: FirewallAction::Allow,
        };

        assert_eq!(rule.source.unwrap().to_string(), "192.168.1.1");
        assert_eq!(rule.destination.unwrap().to_string(), "192.168.1.2");
        assert_eq!(rule.protocol, FirewallProtocol::Tcp);
        assert_eq!(rule.port.unwrap(), 80);
        assert_eq!(rule.action, FirewallAction::Allow);
    }
}