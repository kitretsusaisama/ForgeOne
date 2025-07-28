//! # Underlay Network Implementation
//!
//! This module provides functionality for creating and managing underlay networks
//! for the Quantum-Network Fabric Layer, including MacVLAN and IPVLAN support.

use crate::model::{IsolationLevel, NetworkDriverType, VirtualNetwork};
use common::error::{ForgeError, Result};
use std::net::IpAddr;
use tracing::{debug, error, info, warn};

/// MacVLAN mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacVlanMode {
    /// Private mode - no communication between MacVLAN instances on the same parent
    Private,
    /// VEPA mode - data from one MacVLAN instance to another on the same parent is transmitted
    /// over the physical interface and then received back
    Vepa,
    /// Bridge mode - allows communication between MacVLAN instances on the same parent
    Bridge,
    /// Passthru mode - allows a single VM to be connected directly to the physical interface
    Passthru,
    /// Source mode - filter traffic based on source MAC address
    Source,
}

impl Default for MacVlanMode {
    fn default() -> Self {
        Self::Bridge
    }
}

impl MacVlanMode {
    /// Convert to string representation for netlink
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Vepa => "vepa",
            Self::Bridge => "bridge",
            Self::Passthru => "passthru",
            Self::Source => "source",
        }
    }
}

/// IPVLAN mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVlanMode {
    /// L2 mode - functions like a VLAN in layer 2
    L2,
    /// L3 mode - functions like a separate network namespace in layer 3
    L3,
    /// L3S mode - functions like L3 mode but with shared routing table
    L3S,
}

impl Default for IpVlanMode {
    fn default() -> Self {
        Self::L2
    }
}

impl IpVlanMode {
    /// Convert to string representation for netlink
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::L2 => "l2",
            Self::L3 => "l3",
            Self::L3S => "l3s",
        }
    }
}

/// MacVLAN configuration
#[derive(Debug, Clone)]
pub struct MacVlanConfig {
    /// Parent interface
    pub parent_interface: String,
    /// MacVLAN mode
    pub mode: MacVlanMode,
    /// MTU
    pub mtu: u32,
    /// MAC address source flags
    pub macaddr_source: u32,
}

impl Default for MacVlanConfig {
    fn default() -> Self {
        Self {
            parent_interface: "eth0".to_string(),
            mode: MacVlanMode::default(),
            mtu: 1500,
            macaddr_source: 0,
        }
    }
}

/// IPVLAN configuration
#[derive(Debug, Clone)]
pub struct IpVlanConfig {
    /// Parent interface
    pub parent_interface: String,
    /// IPVLAN mode
    pub mode: IpVlanMode,
    /// MTU
    pub mtu: u32,
}

impl Default for IpVlanConfig {
    fn default() -> Self {
        Self {
            parent_interface: "eth0".to_string(),
            mode: IpVlanMode::default(),
            mtu: 1500,
        }
    }
}

/// Create a MacVLAN interface
async fn create_macvlan_interface(
    name: &str,
    config: &MacVlanConfig,
) -> Result<()> {
    info!(
        "Creating MacVLAN interface {} on parent {}",
        name, config.parent_interface
    );

    #[cfg(target_os = "linux")]
    {
        use rtnetlink::{new_connection, Handle};
        use futures::stream::TryStreamExt;

        // Create a netlink connection
        let (connection, handle, _) = new_connection().map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create netlink connection: {}", e))
        })?;
        tokio::spawn(connection);

        // Find the parent interface
        let links = handle
            .link()
            .get()
            .match_name(config.parent_interface.clone())
            .execute();

        let parent = links.try_next().await.map_err(|e| {
            ForgeError::NetworkError(format!("Failed to get parent interface: {}", e))
        })?;

        let parent = match parent {
            Some(link) => link,
            None => {
                return Err(ForgeError::NetworkError(format!(
                    "Parent interface {} not found",
                    config.parent_interface
                )))
            }
        };

        // Create the MacVLAN interface
        handle
            .link()
            .add()
            .macvlan(name.to_string(), parent.header.index)
            .mode(config.mode.to_string())
            .execute()
            .await
            .map_err(|e| {
                ForgeError::NetworkError(format!("Failed to create MacVLAN interface: {}", e))
            })?;

        // Find the new interface
        let links = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        let link = links.try_next().await.map_err(|e| {
            ForgeError::NetworkError(format!("Failed to get MacVLAN interface: {}", e))
        })?;

        if let Some(link) = link {
            // Set the MTU
            handle
                .link()
                .set(link.header.index)
                .mtu(config.mtu)
                .execute()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to set MacVLAN interface MTU: {}",
                        e
                    ))
                })?;

            // Set the interface up
            handle
                .link()
                .set(link.header.index)
                .up()
                .execute()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to set MacVLAN interface up: {}",
                        e
                    ))
                })?;
        } else {
            return Err(ForgeError::NetworkError(
                "MacVLAN interface not found after creation".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("MacVLAN interfaces are only supported on Linux");
        Err(ForgeError::NetworkError(
            "MacVLAN interfaces are only supported on Linux".to_string(),
        ))
    }
}

/// Delete a MacVLAN interface
async fn delete_macvlan_interface(name: &str) -> Result<()> {
    info!("Deleting MacVLAN interface {}", name);

    #[cfg(target_os = "linux")]
    {
        use rtnetlink::{new_connection, Handle};
        use futures::stream::TryStreamExt;

        // Create a netlink connection
        let (connection, handle, _) = new_connection().map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create netlink connection: {}", e))
        })?;
        tokio::spawn(connection);

        // Find the interface by name
        let links = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        let link = links.try_next().await.map_err(|e| {
            ForgeError::NetworkError(format!("Failed to get MacVLAN interface: {}", e))
        })?;

        if let Some(link) = link {
            // Delete the interface
            handle
                .link()
                .delete(link.header.index)
                .execute()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to delete MacVLAN interface: {}",
                        e
                    ))
                })?;
        } else {
            warn!("MacVLAN interface {} not found", name);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("MacVLAN interfaces are only supported on Linux");
        Err(ForgeError::NetworkError(
            "MacVLAN interfaces are only supported on Linux".to_string(),
        ))
    }
}

/// Create an IPVLAN interface
async fn create_ipvlan_interface(
    name: &str,
    config: &IpVlanConfig,
) -> Result<()> {
    info!(
        "Creating IPVLAN interface {} on parent {}",
        name, config.parent_interface
    );

    #[cfg(target_os = "linux")]
    {
        use rtnetlink::{new_connection, Handle};
        use futures::stream::TryStreamExt;

        // Create a netlink connection
        let (connection, handle, _) = new_connection().map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create netlink connection: {}", e))
        })?;
        tokio::spawn(connection);

        // Find the parent interface
        let links = handle
            .link()
            .get()
            .match_name(config.parent_interface.clone())
            .execute();

        let parent = links.try_next().await.map_err(|e| {
            ForgeError::NetworkError(format!("Failed to get parent interface: {}", e))
        })?;

        let parent = match parent {
            Some(link) => link,
            None => {
                return Err(ForgeError::NetworkError(format!(
                    "Parent interface {} not found",
                    config.parent_interface
                )))
            }
        };

        // Create the IPVLAN interface
        handle
            .link()
            .add()
            .ipvlan(name.to_string(), parent.header.index)
            .mode(config.mode.to_string())
            .execute()
            .await
            .map_err(|e| {
                ForgeError::NetworkError(format!("Failed to create IPVLAN interface: {}", e))
            })?;

        // Find the new interface
        let links = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        let link = links.try_next().await.map_err(|e| {
            ForgeError::NetworkError(format!("Failed to get IPVLAN interface: {}", e))
        })?;

        if let Some(link) = link {
            // Set the MTU
            handle
                .link()
                .set(link.header.index)
                .mtu(config.mtu)
                .execute()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to set IPVLAN interface MTU: {}",
                        e
                    ))
                })?;

            // Set the interface up
            handle
                .link()
                .set(link.header.index)
                .up()
                .execute()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to set IPVLAN interface up: {}",
                        e
                    ))
                })?;
        } else {
            return Err(ForgeError::NetworkError(
                "IPVLAN interface not found after creation".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("IPVLAN interfaces are only supported on Linux");
        Err(ForgeError::NetworkError(
            "IPVLAN interfaces are only supported on Linux".to_string(),
        ))
    }
}

/// Delete an IPVLAN interface
async fn delete_ipvlan_interface(name: &str) -> Result<()> {
    info!("Deleting IPVLAN interface {}", name);

    #[cfg(target_os = "linux")]
    {
        use rtnetlink::{new_connection, Handle};
        use futures::stream::TryStreamExt;

        // Create a netlink connection
        let (connection, handle, _) = new_connection().map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create netlink connection: {}", e))
        })?;
        tokio::spawn(connection);

        // Find the interface by name
        let links = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();

        let link = links.try_next().await.map_err(|e| {
            ForgeError::NetworkError(format!("Failed to get IPVLAN interface: {}", e))
        })?;

        if let Some(link) = link {
            // Delete the interface
            handle
                .link()
                .delete(link.header.index)
                .execute()
                .await
                .map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to delete IPVLAN interface: {}",
                        e
                    ))
                })?;
        } else {
            warn!("IPVLAN interface {} not found", name);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        warn!("IPVLAN interfaces are only supported on Linux");
        Err(ForgeError::NetworkError(
            "IPVLAN interfaces are only supported on Linux".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macvlan_mode() {
        assert_eq!(MacVlanMode::Private.to_string(), "private");
        assert_eq!(MacVlanMode::Vepa.to_string(), "vepa");
        assert_eq!(MacVlanMode::Bridge.to_string(), "bridge");
        assert_eq!(MacVlanMode::Passthru.to_string(), "passthru");
        assert_eq!(MacVlanMode::Source.to_string(), "source");

        assert_eq!(MacVlanMode::default(), MacVlanMode::Bridge);
    }

    #[test]
    fn test_ipvlan_mode() {
        assert_eq!(IpVlanMode::L2.to_string(), "l2");
        assert_eq!(IpVlanMode::L3.to_string(), "l3");
        assert_eq!(IpVlanMode::L3S.to_string(), "l3s");

        assert_eq!(IpVlanMode::default(), IpVlanMode::L2);
    }

    #[test]
    fn test_macvlan_config_default() {
        let config = MacVlanConfig::default();
        assert_eq!(config.parent_interface, "eth0");
        assert_eq!(config.mode, MacVlanMode::Bridge);
        assert_eq!(config.mtu, 1500);
        assert_eq!(config.macaddr_source, 0);
    }

    #[test]
    fn test_ipvlan_config_default() {
        let config = IpVlanConfig::default();
        assert_eq!(config.parent_interface, "eth0");
        assert_eq!(config.mode, IpVlanMode::L2);
        assert_eq!(config.mtu, 1500);
    }
}