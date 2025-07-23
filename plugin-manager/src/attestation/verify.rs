//! Verification module for the ForgeOne Plugin Manager
//!
//! Provides functions for verifying plugin signatures and hashes.

use common::crypto::{hash_sha256, verify};
use common::error::{ForgeError, Result};
use common::model::IdentityContext as Identity;
use std::path::Path;

/// Verifies the signature of a plugin package
///
/// # Arguments
///
/// * `package_path` - Path to the plugin package file
/// * `signature` - The signature to verify
/// * `public_key` - The public key to use for verification
///
/// # Returns
///
/// * `Ok(())` if the signature is valid
/// * `Err(ForgeError)` if the signature is invalid or verification fails
pub fn verify_plugin_signature<P: AsRef<Path>>(
    package_path: P,
    signature: &[u8],
    public_key: &[u8],
) -> Result<()> {
    // Read the package file
    let package_data = std::fs::read(package_path.as_ref())
        .map_err(|e| ForgeError::ConfigError(format!("Failed to read plugin package: {}", e)))?;

    // Verify the signature
    let valid = verify(&package_data, signature, public_key).map_err(|e| {
        ForgeError::CryptoError(format!("Plugin signature verification failed: {}", e))
    })?;
    if valid {
        Ok(())
    } else {
        Err(ForgeError::CryptoError(
            "Invalid plugin signature".to_string(),
        ))
    }
}

/// Verifies the hash of a plugin package
///
/// # Arguments
///
/// * `package_path` - Path to the plugin package file
/// * `expected_hash` - The expected hash value
///
/// # Returns
///
/// * `Ok(())` if the hash matches
/// * `Err(ForgeError)` if the hash doesn't match or verification fails
pub fn verify_plugin_hash<P: AsRef<Path>>(package_path: P, expected_hash: &str) -> Result<()> {
    // Read the package file
    let package_data = std::fs::read(package_path.as_ref())
        .map_err(|e| ForgeError::ConfigError(format!("Failed to read plugin package: {}", e)))?;

    // Calculate the hash
    let calculated_hash = hash_sha256(&package_data);
    let calculated_hash_hex = hex::encode(calculated_hash);

    // Compare the hashes
    if calculated_hash_hex == expected_hash {
        Ok(())
    } else {
        Err(ForgeError::CryptoError(format!(
            "Plugin hash verification failed: expected {}, got {}",
            expected_hash, calculated_hash_hex
        )))
    }
}

/// Verifies the integrity and authenticity of a plugin package
///
/// # Arguments
///
/// * `package_path` - Path to the plugin package file
/// * `expected_hash` - The expected hash value
/// * `signature` - The signature to verify
/// * `identity` - The identity containing the public key
///
/// # Returns
///
/// * `Ok(())` if both hash and signature are valid
/// * `Err(ForgeError)` if either verification fails
pub fn verify_plugin<P: AsRef<Path>>(
    package_path: P,
    expected_hash: &str,
    signature: &[u8],
    identity: &Identity,
) -> Result<()> {
    // Verify hash
    verify_plugin_hash(package_path.as_ref(), expected_hash)?;

    // Verify signature
    verify_plugin_signature(package_path.as_ref(), signature, &identity.public_key)?;

    Ok(())
}
