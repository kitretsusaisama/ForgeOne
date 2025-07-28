//! # Netlink Bridge Implementation
//!
//! This module provides low-level netlink functionality for creating and managing
//! network bridges and virtual Ethernet (veth) pairs.

use common::error::{ForgeError, Result};
use futures::stream::TryStreamExt;
use rtnetlink::{new_connection, Handle, IpVersion};
use std::net::IpAddr;
use tracing::{debug, error, info};

/// Create a bridge interface
pub async fn create_bridge(name: &str, mtu: u32) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Create the bridge
    let mut request = handle.link().add().bridge().name(name.to_string());

    // Set MTU if specified
    if mtu > 0 {
        request = request.mtu(mtu);
    }

    // Execute the request
    request
        .execute()
        .await
        .map_err(|e| ForgeError::NetworkError(format!("Failed to create bridge {}: {}", name, e)))?;

    // Set the bridge up
    set_interface_up(name).await?;

    info!("Created bridge {}", name);
    Ok(())
}

/// Delete a bridge interface
pub async fn delete_bridge(name: &str) -> Result<()> {
    delete_interface(name).await
}

/// Create a veth pair
pub async fn create_veth_pair(veth1: &str, veth2: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Create the veth pair
    handle
        .link()
        .add()
        .veth(veth1.to_string(), veth2.to_string())
        .execute()
        .await
        .map_err(|e| {
            ForgeError::NetworkError(format!(
                "Failed to create veth pair {}-{}: {}",
                veth1, veth2, e
            ))
        })?;

    // Set veth1 up
    set_interface_up(veth1).await?;

    info!("Created veth pair {} <-> {}", veth1, veth2);
    Ok(())
}

/// Connect a veth interface to a bridge
pub async fn connect_veth_to_bridge(veth: &str, bridge: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the bridge index
    let bridge_index = get_interface_index(&handle, bridge).await?;

    // Get the veth index
    let veth_index = get_interface_index(&handle, veth).await?;

    // Connect veth to bridge
    handle
        .link()
        .set(veth_index)
        .master(bridge_index)
        .execute()
        .await
        .map_err(|e| {
            ForgeError::NetworkError(format!(
                "Failed to connect {} to bridge {}: {}",
                veth, bridge, e
            ))
        })?;

    info!("Connected {} to bridge {}", veth, bridge);
    Ok(())
}

/// Set an interface up
pub async fn set_interface_up(name: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let index = get_interface_index(&handle, name).await?;

    // Set the interface up
    handle
        .link()
        .set(index)
        .up()
        .execute()
        .await
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to set interface {} up: {}", name, e))
        })?;

    debug!("Set interface {} up", name);
    Ok(())
}

/// Set an interface down
pub async fn set_interface_down(name: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let index = get_interface_index(&handle, name).await?;

    // Set the interface down
    handle
        .link()
        .set(index)
        .down()
        .execute()
        .await
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to set interface {} down: {}", name, e))
        })?;

    debug!("Set interface {} down", name);
    Ok(())
}

/// Delete an interface
pub async fn delete_interface(name: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let index = get_interface_index(&handle, name).await?;

    // Delete the interface
    handle
        .link()
        .delete(index)
        .execute()
        .await
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to delete interface {}: {}", name, e))
        })?;

    info!("Deleted interface {}", name);
    Ok(())
}

/// Set an interface IP address
pub async fn set_interface_ip(name: &str, ip: IpAddr) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Get the interface index
    let index = get_interface_index(&handle, name).await?;

    // Determine prefix length based on IP version
    let prefix_len = match ip {
        IpAddr::V4(_) => 24, // /24 for IPv4
        IpAddr::V6(_) => 64, // /64 for IPv6
    };

    // Set the IP address
    let version = if ip.is_ipv4() {
        IpVersion::V4
    } else {
        IpVersion::V6
    };

    handle
        .address()
        .add(index, ip, prefix_len)
        .execute()
        .await
        .map_err(|e| {
            ForgeError::NetworkError(format!(
                "Failed to set interface {} IP to {}: {}",
                name, ip, e
            ))
        })?;

    debug!("Set interface {} IP to {}/{}", name, ip, prefix_len);
    Ok(())
}

/// Get an interface index by name
async fn get_interface_index(handle: &Handle, name: &str) -> Result<u32> {
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Some(link) = links.try_next().await.map_err(|e| {
        ForgeError::NetworkError(format!("Failed to get interface {} index: {}", name, e))
    })? {
        Ok(link.header.index)
    } else {
        Err(ForgeError::NetworkError(format!(
            "Interface {} not found",
            name
        )))
    }
}

/// Setup a veth pair for a container
pub async fn setup_veth_pair(container_id: &str, bridge_name: &str) -> Result<()> {
    let host_veth = format!("veth{}", &container_id[..12]);
    let container_veth = format!("eth0");

    // Create veth pair
    create_veth_pair(&host_veth, &container_veth).await?;

    // Connect host veth to bridge
    connect_veth_to_bridge(&host_veth, bridge_name).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // These tests require root privileges and a Linux environment
    // They are disabled by default
    #[ignore]
    #[tokio::test]
    async fn test_create_bridge() {
        let bridge_name = "testbr0";
        let result = create_bridge(bridge_name, 1500).await;
        assert!(result.is_ok());

        // Clean up
        let _ = delete_bridge(bridge_name).await;
    }

    #[ignore]
    #[tokio::test]
    async fn test_create_veth_pair() {
        let veth1 = "testveth1";
        let veth2 = "testveth2";
        let result = create_veth_pair(veth1, veth2).await;
        assert!(result.is_ok());

        // Clean up
        let _ = delete_interface(veth1).await;
    }
}