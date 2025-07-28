//! # IPTables Implementation
//!
//! This module provides functionality for interacting with iptables
//! for firewall rule management.

use common::error::{ForgeError, Result};
use std::process::Command;
use tracing::{debug, error, info, warn};

/// Check if iptables is available
pub async fn check_iptables_available() -> bool {
    let output = Command::new("iptables").arg("--version").output();
    match output {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Create an iptables chain
pub async fn create_chain(chain_name: &str) -> Result<()> {
    debug!("Creating iptables chain {}", chain_name);
    
    let output = Command::new("iptables")
        .arg("-N")
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to create iptables chain: {}", e))
        })?;

    // Ignore if chain already exists
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("Chain already exists") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to create iptables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Delete an iptables chain
pub async fn delete_chain(chain_name: &str) -> Result<()> {
    debug!("Deleting iptables chain {}", chain_name);
    
    // First flush the chain
    let flush_output = Command::new("iptables")
        .arg("-F")
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to flush iptables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !flush_output.status.success() {
        let stderr = String::from_utf8_lossy(&flush_output.stderr);
        if !stderr.contains("No chain/target/match by that name") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to flush iptables chain: {}",
                stderr
            )));
        }
        return Ok(());
    }

    // Then delete the chain
    let delete_output = Command::new("iptables")
        .arg("-X")
        .arg(chain_name)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to delete iptables chain: {}", e))
        })?;

    // Ignore if chain doesn't exist
    if !delete_output.status.success() {
        let stderr = String::from_utf8_lossy(&delete_output.stderr);
        if !stderr.contains("No chain/target/match by that name") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to delete iptables chain: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Add a jump rule to an iptables chain
pub async fn add_jump(from_chain: &str, to_chain: &str) -> Result<()> {
    debug!("Adding jump from {} to {}", from_chain, to_chain);
    
    let output = Command::new("iptables")
        .arg("-A")
        .arg(from_chain)
        .arg("-j")
        .arg(to_chain)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add iptables jump: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add iptables jump: {}",
            stderr
        )));
    }

    Ok(())
}

/// Remove a jump rule from an iptables chain
pub async fn remove_jump(from_chain: &str, to_chain: &str) -> Result<()> {
    debug!("Removing jump from {} to {}", from_chain, to_chain);
    
    let output = Command::new("iptables")
        .arg("-D")
        .arg(from_chain)
        .arg("-j")
        .arg(to_chain)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to remove iptables jump: {}", e))
        })?;

    // Ignore if rule doesn't exist
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.contains("No chain/target/match by that name") && 
           !stderr.contains("Bad rule") {
            return Err(ForgeError::NetworkError(format!(
                "Failed to remove iptables jump: {}",
                stderr
            )));
        }
    }

    Ok(())
}

/// Set the default policy for an iptables chain
pub async fn set_default_policy(chain: &str, policy: &str) -> Result<()> {
    debug!("Setting default policy for {} to {}", chain, policy);
    
    let output = Command::new("iptables")
        .arg("-P")
        .arg(chain)
        .arg(policy)
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to set iptables policy: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to set iptables policy: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to allow established connections
pub async fn allow_established_connections(chain: &str) -> Result<()> {
    debug!("Adding rule to allow established connections in {}", chain);
    
    let output = Command::new("iptables")
        .arg("-A")
        .arg(chain)
        .arg("-m")
        .arg("conntrack")
        .arg("--ctstate")
        .arg("ESTABLISHED,RELATED")
        .arg("-j")
        .arg("ACCEPT")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add iptables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add iptables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to allow traffic between two interfaces
pub async fn allow_interface_traffic(chain: &str, in_interface: &str, out_interface: &str) -> Result<()> {
    debug!("Adding rule to allow traffic from {} to {} in {}", in_interface, out_interface, chain);
    
    let output = Command::new("iptables")
        .arg("-A")
        .arg(chain)
        .arg("-i")
        .arg(in_interface)
        .arg("-o")
        .arg(out_interface)
        .arg("-j")
        .arg("ACCEPT")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add iptables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add iptables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to allow traffic to a specific port
pub async fn allow_port(chain: &str, protocol: &str, port: u16) -> Result<()> {
    debug!("Adding rule to allow {} port {} in {}", protocol, port, chain);
    
    let output = Command::new("iptables")
        .arg("-A")
        .arg(chain)
        .arg("-p")
        .arg(protocol)
        .arg("--dport")
        .arg(port.to_string())
        .arg("-j")
        .arg("ACCEPT")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add iptables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add iptables rule: {}",
            stderr
        )));
    }

    Ok(())
}

/// Add a rule to block traffic to a specific port
pub async fn block_port(chain: &str, protocol: &str, port: u16) -> Result<()> {
    debug!("Adding rule to block {} port {} in {}", protocol, port, chain);
    
    let output = Command::new("iptables")
        .arg("-A")
        .arg(chain)
        .arg("-p")
        .arg(protocol)
        .arg("--dport")
        .arg(port.to_string())
        .arg("-j")
        .arg("DROP")
        .output()
        .map_err(|e| {
            ForgeError::NetworkError(format!("Failed to add iptables rule: {}", e))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ForgeError::NetworkError(format!(
            "Failed to add iptables rule: {}",
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

/// Save iptables rules
pub async fn save_rules() -> Result<()> {
    debug!("Saving iptables rules");
    
    #[cfg(target_os = "linux")]
    {
        // Check if we're on a system with iptables-save
        let output = Command::new("iptables-save")
            .output()
            .map_err(|e| {
                ForgeError::NetworkError(format!("Failed to save iptables rules: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ForgeError::NetworkError(format!(
                "Failed to save iptables rules: {}",
                stderr
            )));
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Saving iptables rules is only supported on Linux");
    }
    
    Ok(())
}

/// Restore iptables rules
pub async fn restore_rules() -> Result<()> {
    debug!("Restoring iptables rules");
    
    #[cfg(target_os = "linux")]
    {
        // Check if we're on a system with iptables-restore
        let output = Command::new("iptables-restore")
            .output()
            .map_err(|e| {
                ForgeError::NetworkError(format!("Failed to restore iptables rules: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ForgeError::NetworkError(format!(
                "Failed to restore iptables rules: {}",
                stderr
            )));
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        warn!("Restoring iptables rules is only supported on Linux");
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
    async fn test_create_chain() {
        let chain_name = "FORGE_TEST";
        let result = create_chain(chain_name).await;
        assert!(result.is_ok());

        // Clean up
        let _ = delete_chain(chain_name).await;
    }

    #[ignore]
    #[tokio::test]
    async fn test_add_jump() {
        let from_chain = "FORWARD";
        let to_chain = "FORGE_TEST";

        // Create the test chain
        let _ = create_chain(to_chain).await;

        // Add the jump
        let result = add_jump(from_chain, to_chain).await;
        assert!(result.is_ok());

        // Clean up
        let _ = remove_jump(from_chain, to_chain).await;
        let _ = delete_chain(to_chain).await;
    }
}