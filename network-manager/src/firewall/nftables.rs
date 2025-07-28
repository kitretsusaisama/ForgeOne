//! # NFTables Implementation
//!
//! This module provides functionality for interacting with nftables
//! for firewall rule management.

use common::error::{ForgeError, Result};
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Check if nftables is available
pub async fn check_nftables_available() -> bool {
    let output = Command::new("nft").arg("--version").output();
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Create an nftables table
pub async fn create_table(table_name: &str) -> Result<()> {
    debug!("Creating nftables table {}", table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("table")
        .arg("inet")
        .arg(table_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create nftables table: {}", e))
        })?;

    // Ignore if table already exists
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Table already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create nftables table: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Delete an nftables table
pub async fn delete_table(table_name: &str) -> Result<()> {
    debug!("Deleting nftables table {}", table_name);
    
    let output = Command::new("nft")
        .arg("delete")
        .arg("table")
        .arg("inet")
        .arg(table_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to delete nftables table: {}", e))
        })?;

    // Ignore if table doesn't exist
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No such file or directory") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to delete nftables table: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Create an nftables chain
pub async fn create_chain(table_name: &str, chain_name: &str, hook: &str, priority: i32) -> Result<()> {
    debug!("Creating nftables chain {} in table {}", chain_name, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .arg("{")
        .arg("type")
        .arg("filter")
        .arg("hook")
        .arg(hook)
        .arg("priority")
        .arg(priority.to_string())
        .arg(";")
        .arg("}")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create nftables chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create nftables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Create a regular nftables chain (without hook)
pub async fn create_regular_chain(table_name: &str, chain_name: &str) -> Result<()> {
    debug!("Creating regular nftables chain {} in table {}", chain_name, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create nftables chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create nftables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Delete an nftables chain
pub async fn delete_chain(table_name: &str, chain_name: &str) -> Result<()> {
    debug!("Deleting nftables chain {} from table {}", chain_name, table_name);
    
    // First flush the chain
    let flush_output = Command::new("nft")
        .arg("flush")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to flush nftables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !flush_output.status.success() {
        let stderr = String::from_utf8_lossy(&flush_output.stderr);
        if !stderr.contains("No such file or directory") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to flush nftables chain: {}",
                stderr
            )));
        }
        return Ok(());
    }

    // Then delete the chain
    let delete_output = Command::new("nft")
        .arg("delete")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to delete nftables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !delete_output.status.success() {
        let stderr = String::from_utf8_lossy(&delete_output.stderr);
        if !stderr.contains("No such file or directory") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to delete nftables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Add a jump rule to an nftables chain
pub async fn add_jump(table_name: &str, from_chain: &str, to_chain: &str) -> Result<()> {
    debug!("Adding jump from {} to {} in table {}", from_chain, to_chain, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("rule")
        .arg("inet")
        .arg(table_name)
        .arg(from_chain)
        .arg("jump")
        .arg(to_chain)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add nftables jump: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add nftables jump: {}",
            stderr
        )));
    }

    Ok(())
}

/// Set the default policy for an nftables chain
pub async fn set_default_policy(table_name: &str, chain_name: &str, policy: &str) -> Result<()> {
    debug!("Setting default policy for {} to {} in table {}", chain_name, policy, table_name);
    
    // In nftables, we need to recreate the chain with the policy
    // First, get the hook and priority of the chain
    let list_output = Command::new("nft")
        .arg("-j")
        .arg("list")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to list nftables chain: {}", e))
        })?;

    if !list_output.status.success() {
        let stderr = String::from_utf8_lossy(&list_output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to list nftables chain: {}",
            stderr
        )));
    }

    // Parse the JSON output to get hook and priority
    // This is a simplified approach; in a real implementation, you'd want to use a JSON parser
    let output_str = String::from_utf8_lossy(&list_output.stdout);
    let hook = if output_str.contains("\"hook\": \"input\"") {
        "input"
    } else if output_str.contains("\"hook\": \"forward\"") {
        "forward"
    } else if output_str.contains("\"hook\": \"output\"") {
        "output"
    } else {
        return Err(ForgeError::NetworkError(format!(
            "Failed to determine hook for chain {}",
            chain_name
        )));
    };

    // Extract priority (simplified approach)
    let priority = 0; // Default priority

    // Delete the chain
    delete_chain(table_name, chain_name).await?;

    // Recreate the chain with the new policy
    let output = Command::new("nft")
        .arg("add")
        .arg("chain")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .arg("{")
        .arg("type")
        .arg("filter")
        .arg("hook")
        .arg(hook)
        .arg("priority")
        .arg(priority.to_string())
        .arg(";")
        .arg("policy")
        .arg(policy)
        .arg(";")
        .arg("}")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to set nftables policy: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to set nftables policy: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to allow established connections
pub async fn allow_established_connections(table_name: &str, chain_name: &str) -> Result<()> {
    debug!("Adding rule to allow established connections in {} in table {}", chain_name, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("rule")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .arg("ct")
        .arg("state")
        .arg("established,related")
        .arg("accept")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add nftables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add nftables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to allow traffic between two interfaces
pub async fn allow_interface_traffic(table_name: &str, chain_name: &str, in_interface: &str, out_interface: &str) -> Result<()> {
    debug!("Adding rule to allow traffic from {} to {} in {} in table {}", in_interface, out_interface, chain_name, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("rule")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .arg("iifname")
        .arg(in_interface)
        .arg("oifname")
        .arg(out_interface)
        .arg("accept")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add nftables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add nftables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to allow traffic to a specific port
pub async fn allow_port(table_name: &str, chain_name: &str, protocol: &str, port: u16) -> Result<()> {
    debug!("Adding rule to allow {} port {} in {} in table {}", protocol, port, chain_name, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("rule")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .arg(protocol)
        .arg("dport")
        .arg(port.to_string())
        .arg("accept")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add nftables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add nftables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to block traffic to a specific port
pub async fn block_port(table_name: &str, chain_name: &str, protocol: &str, port: u16) -> Result<()> {
    debug!("Adding rule to block {} port {} in {} in table {}", protocol, port, chain_name, table_name);
    
    let output = Command::new("nft")
        .arg("add")
        .arg("rule")
        .arg("inet")
        .arg(table_name)
        .arg(chain_name)
        .arg(protocol)
        .arg("dport")
        .arg(port.to_string())
        .arg("drop")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add nftables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add nftables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Enable IP forwarding
pub async fn enable_ip_forwarding() -> Result<()> {
    debug!("Enabling IP forwarding");
    
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

/// Save nftables rules
pub async fn save_rules() -> Result<()> {
    debug!("Saving nftables rules");
    
    #[cfg(target_os = "linux")]
    {
        // Check if we're on a system with nft
        let output = Command::new("nft")
            .arg("list")
            .arg("ruleset")
            .arg(">")
            .arg("/etc/nftables.conf")
            .output()
            .map_err(|e| {
                ForgeError::NetworkError(format!("Failed to save nftables rules: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ForgeError::NetworkError(format!(
                "Failed to save nftables rules: {}",
                stderr
            )));
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Saving nftables rules is only supported on Linux");
    }
    
    Ok(())
}

/// Restore nftables rules
pub async fn restore_rules() -> Result<()> {
    debug!("Restoring nftables rules");
    
    #[cfg(target_os = "linux")]
    {
        // Check if we're on a system with nft
        let output = Command::new("nft")
            .arg("-f")
            .arg("/etc/nftables.conf")
            .output()
            .map_err(|e| {
                ForgeError::NetworkError(format!("Failed to restore nftables rules: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ForgeError::NetworkError(format!(
                "Failed to restore nftables rules: {}",
                stderr
            )));
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Restoring nftables rules is only supported on Linux");
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require root privileges and a Linux environment
    // They are disabled by default
    #[ignore]
    #[tokio::test]
    async fn test_create_table() {
        let table_name = "forge_test";
        let result = create_table(table_name).await;
        assert!(result.is_ok());

        // Clean up
        let _ = delete_table(table_name).await;
    }

    #[ignore]
    #[tokio::test]
    async fn test_create_chain() {
        let table_name = "forge_test";
        let chain_name = "forward";

        // Create the test table
        let _ = create_table(table_name).await;

        // Create the chain
        let result = create_chain(table_name, chain_name, "forward", 0).await;
        assert!(result.is_ok());

        // Clean up
        let _ = delete_chain(table_name, chain_name).await;
        let _ = delete_table(table_name).await;
    }
}