//! # Firewall Module
//!
//! This module provides Zero Trust firewall functionality for the Quantum-Network Fabric Layer.
//! It implements network policy enforcement based on the Zero Trust Architecture (ZTA) model.

mod iptables;
mod nftables;
mod policy;

pub use iptables::*;
pub use nftables::*;
pub use policy::*;

use crate::model::{FirewallPolicy, VirtualNetwork};
use common::error::{ForgeError, Result};
use common::trust::{Action, ZtaPolicyGraph};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use tracing::{debug, error, info, warn};

/// Firewall backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    /// iptables (legacy)
    IpTables,
    /// nftables (modern)
    NfTables,
}

impl Default for FirewallBackend {
    fn default() -> Self {
        FirewallBackend::NfTables
    }
}

/// Firewall configuration
#[derive(Debug, Clone)]
pub struct FirewallConfig {
    /// Firewall backend
    pub backend: FirewallBackend,
    /// Default policy (allow or deny)
    pub default_policy: FirewallDefaultPolicy,
    /// Enable connection tracking
    pub enable_conntrack: bool,
    /// Enable logging
    pub enable_logging: bool,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            backend: FirewallBackend::default(),
            default_policy: FirewallDefaultPolicy::default(),
            enable_conntrack: true,
            enable_logging: true,
        }
    }
}

/// Firewall default policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallDefaultPolicy {
    /// Allow all traffic by default
    Allow,
    /// Deny all traffic by default
    Deny,
}

impl Default for FirewallDefaultPolicy {
    fn default() -> Self {
        FirewallDefaultPolicy::Deny
    }
}

/// Firewall manager
pub struct FirewallManager {
    /// Firewall configuration
    config: FirewallConfig,
    /// Network policies
    policies: Arc<RwLock<HashMap<String, FirewallPolicy>>>,
    /// ZTA policy graph
    zta_policy: Arc<RwLock<ZtaPolicyGraph>>,
}

impl FirewallManager {
    /// Create a new firewall manager
    pub fn new(
        config: FirewallConfig,
        zta_policy: Arc<RwLock<ZtaPolicyGraph>>,
    ) -> Self {
        Self {
            config,
            policies: Arc::new(RwLock::new(HashMap::new())),
            zta_policy,
        }
    }

    /// Initialize the firewall
    pub async fn init(&self) -> Result<()> {
        info!("Initializing firewall with {:?} backend", self.config.backend);

        match self.config.backend {
            FirewallBackend::IpTables => {
                // Initialize iptables
                let default_policy = match self.config.default_policy {
                    FirewallDefaultPolicy::Allow => "ACCEPT",
                    FirewallDefaultPolicy::Deny => "DROP",
                };

                // Setup base chains
                iptables_init(default_policy).await?
            }
            FirewallBackend::NfTables => {
                // Initialize nftables
                let default_policy = match self.config.default_policy {
                    FirewallDefaultPolicy::Allow => "accept",
                    FirewallDefaultPolicy::Deny => "drop",
                };

                // Setup base tables and chains
                nftables_init(default_policy).await?
            }
        }

        Ok(())
    }

    /// Apply a firewall policy
    pub async fn apply_policy(&self, policy: FirewallPolicy) -> Result<()> {
        info!("Applying firewall policy for network {}", policy.network_id);

        // Store the policy
        {
            let mut policies = self.policies.write().unwrap();
            policies.insert(policy.network_id.clone(), policy.clone());
        }

        // Apply the policy based on backend
        match self.config.backend {
            FirewallBackend::IpTables => {
                apply_iptables_policy(&policy).await?
            }
            FirewallBackend::NfTables => {
                apply_nftables_policy(&policy).await?
            }
        }

        Ok(())
    }

    /// Remove a firewall policy
    pub async fn remove_policy(&self, network_id: &str) -> Result<()> {
        info!("Removing firewall policy for network {}", network_id);

        // Get the policy
        let policy = {
            let policies = self.policies.read().unwrap();
            match policies.get(network_id) {
                Some(p) => p.clone(),
                None => {
                    return Err(ForgeError::NetworkError(format!(
                        "Firewall policy for network {} not found",
                        network_id
                    )))
                }
            }
        };

        // Remove the policy based on backend
        match self.config.backend {
            FirewallBackend::IpTables => {
                remove_iptables_policy(&policy).await?
            }
            FirewallBackend::NfTables => {
                remove_nftables_policy(&policy).await?
            }
        }

        // Remove the policy from storage
        {
            let mut policies = self.policies.write().unwrap();
            policies.remove(network_id);
        }

        Ok(())
    }

    /// Apply Zero Trust policies from the ZTA policy graph
    pub async fn apply_zta_policies(&self) -> Result<()> {
        info!("Applying Zero Trust policies");

        // Get the ZTA policy graph
        let zta_policy = self.zta_policy.read().unwrap();

        // Convert ZTA policies to firewall policies
        for (source, targets) in zta_policy.get_edges() {
            for (target, actions) in targets {
                // Check if the action includes network operations
                if actions.contains(&Action::Connect) {
                    // Create a firewall policy for this connection
                    let policy = FirewallPolicy {
                        network_id: format!("zta-{}-{}", source, target),
                        source_id: source.clone(),
                        rules: vec![FirewallRule {
                            source: None, // Will be filled in at runtime
                            destination: None, // Will be filled in at runtime
                            protocol: FirewallProtocol::Any,
                            port: None,
                            action: FirewallAction::Allow,
                        }],
                    };

                    // Apply the policy
                    self.apply_policy(policy).await?;
                }
            }
        }

        Ok(())
    }

    /// Allow traffic between two endpoints
    pub async fn allow_traffic(
        &self,
        source_ip: IpAddr,
        dest_ip: IpAddr,
        protocol: Option<FirewallProtocol>,
        port: Option<u16>,
    ) -> Result<()> {
        let proto = protocol.unwrap_or(FirewallProtocol::Any);
        let rule = FirewallRule {
            source: Some(source_ip),
            destination: Some(dest_ip),
            protocol: proto,
            port,
            action: FirewallAction::Allow,
        };

        info!(
            "Allowing traffic from {} to {} (protocol: {:?}, port: {:?})",
            source_ip, dest_ip, proto, port
        );

        // Apply the rule based on backend
        match self.config.backend {
            FirewallBackend::IpTables => {
                apply_iptables_rule(&rule).await?
            }
            FirewallBackend::NfTables => {
                apply_nftables_rule(&rule).await?
            }
        }

        Ok(())
    }

    /// Block traffic between two endpoints
    pub async fn block_traffic(
        &self,
        source_ip: IpAddr,
        dest_ip: IpAddr,
        protocol: Option<FirewallProtocol>,
        port: Option<u16>,
    ) -> Result<()> {
        let proto = protocol.unwrap_or(FirewallProtocol::Any);
        let rule = FirewallRule {
            source: Some(source_ip),
            destination: Some(dest_ip),
            protocol: proto,
            port,
            action: FirewallAction::Deny,
        };

        info!(
            "Blocking traffic from {} to {} (protocol: {:?}, port: {:?})",
            source_ip, dest_ip, proto, port
        );

        // Apply the rule based on backend
        match self.config.backend {
            FirewallBackend::IpTables => {
                apply_iptables_rule(&rule).await?
            }
            FirewallBackend::NfTables => {
                apply_nftables_rule(&rule).await?
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_firewall_config_default() {
        let config = FirewallConfig::default();
        assert_eq!(config.backend, FirewallBackend::NfTables);
        assert_eq!(config.default_policy, FirewallDefaultPolicy::Deny);
        assert!(config.enable_conntrack);
        assert!(config.enable_logging);
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