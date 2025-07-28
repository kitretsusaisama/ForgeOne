//! # Configuration system for ForgeOne
//! config.rs
//! This module provides a multi-layer configuration system with attestation for the ForgeOne platform.
//! It handles loading, validating, and attesting configurations.

use crate::error::{ForgeError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// A signed configuration with attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedConfig<T> {
    /// The content of this configuration
    pub content: T,
    /// The signature of this configuration
    pub signature: String,
    /// The issuer of this configuration
    pub issued_by: String,
    /// The timestamp of this configuration
    pub timestamp: DateTime<Utc>,
}

/// The main configuration for ForgeOne
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgeConfig {
    /// The name of this configuration
    pub name: String,
    /// The version of this configuration
    pub version: String,
    /// The environment of this configuration
    pub environment: String,
    /// The log level of this configuration
    pub log_level: String,
    /// The telemetry endpoint of this configuration
    pub telemetry_endpoint: Option<String>,
    /// The audit log path of this configuration
    pub audit_log_path: Option<String>,
    /// The policy file path of this configuration
    pub policy_file_path: Option<String>,
    /// Whether to enable LLM tracing
    pub enable_llm_tracing: bool,
    /// Whether to enable cryptographic verification
    pub enable_crypto_verification: bool,
    /// The trusted public keys for verification
    pub trusted_public_keys: Vec<String>,
    /// The plugin directory of this configuration
    pub plugin_dir: String,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            name: "ForgeOne".to_string(),
            version: "0.1.0".to_string(),
            environment: "development".to_string(),
            log_level: "info".to_string(),
            telemetry_endpoint: None,
            audit_log_path: None,
            policy_file_path: None,
            enable_llm_tracing: false,
            enable_crypto_verification: false,
            trusted_public_keys: Vec::new(),
            plugin_dir: "None".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    pub tenant_id: String,
    pub user_id: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorConfig {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub certificate: Vec<u8>,
}

/// Load a configuration from a file
pub fn load_config(path: &str) -> Result<ForgeConfig> {
    let path = Path::new(path);
    let content = fs::read_to_string(path)
        .map_err(|e| ForgeError::ConfigError(format!("Failed to read config file: {}", e)))?;

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&content)
            .map_err(|e| ForgeError::ConfigError(format!("Failed to parse JSON config: {}", e))),
        Some("yaml") | Some("yml") => serde_yaml::from_str(&content)
            .map_err(|e| ForgeError::ConfigError(format!("Failed to parse YAML config: {}", e))),
        _ => Err(ForgeError::ConfigError(
            "Unsupported config file format".to_string(),
        )),
    }
}

/// Load a signed configuration from a file
pub fn load_signed_config<T: for<'de> Deserialize<'de>>(path: &str) -> Result<SignedConfig<T>> {
    let path = Path::new(path);
    let content = fs::read_to_string(path).map_err(|e| {
        ForgeError::ConfigError(format!("Failed to read signed config file: {}", e))
    })?;

    match path.extension().and_then(|ext| ext.to_str()) {
        Some("json") => serde_json::from_str(&content).map_err(|e| {
            ForgeError::ConfigError(format!("Failed to parse JSON signed config: {}", e))
        }),
        Some("yaml") | Some("yml") => serde_yaml::from_str(&content).map_err(|e| {
            ForgeError::ConfigError(format!("Failed to parse YAML signed config: {}", e))
        }),
        _ => Err(ForgeError::ConfigError(
            "Unsupported signed config file format".to_string(),
        )),
    }
}

/// Verify the signature of a signed configuration
pub fn verify_signature<T: Serialize>(data: &SignedConfig<T>, public_key: &[u8]) -> Result<bool> {
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // Serialize the content to get the data that was signed
    let encoded = serde_json::to_vec(&data.content)
        .map_err(|e| ForgeError::CryptoError(format!("Failed to serialize config: {}", e)))?;

    // Ensure we have exactly 32 bytes for the public key
    if public_key.len() < 32 {
        return Err(ForgeError::CryptoError("Public key too short".to_string()));
    }

    // Convert slice to array for public key
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&public_key[..32]);

    // Create the verifying key
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ForgeError::CryptoError(format!("Invalid public key: {}", e)))?;

    // Decode the signature from base64
    let sig_bytes = match general_purpose::STANDARD.decode(&data.signature) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(false), // Invalid base64 means invalid signature
    };

    // Ensure we have exactly 64 bytes for the signature
    if sig_bytes.len() != 64 {
        return Ok(false); // Invalid length means invalid signature
    }

    // Convert signature bytes to array
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);

    // Create the signature
    // Signature::from_bytes doesn't return a Result but directly returns a Signature
    let signature = Signature::from_bytes(&sig_array);

    // Verify the signature
    match verifying_key.verify(&encoded, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub mod runtime {
    use super::{IdentityConfig, TrustAnchorConfig};
    use crate::error::{ForgeError, Result};
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    /// Runtime configuration for ForgeOne microkernel
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RuntimeConfig {
        pub name: String,
        pub version: String,
        pub start_time: DateTime<Utc>,
        pub custom: Option<serde_json::Value>,
        pub identity: IdentityConfig,
        pub trust_anchor: TrustAnchorConfig,
        pub boot_params: HashMap<String, String>,
        pub boot_mode: String,
    }

    impl Default for RuntimeConfig {
        fn default() -> Self {
            Self {
                name: "default-runtime".to_string(),
                version: "0.1.0".to_string(),
                start_time: Utc::now(),
                custom: None,
                identity: IdentityConfig {
                    tenant_id: "system".to_string(),
                    user_id: "system".to_string(),
                    role: "admin".to_string(),
                },
                trust_anchor: TrustAnchorConfig {
                    public_key: Vec::new(),
                    signature: Vec::new(),
                    certificate: Vec::new(),
                },
                boot_params: HashMap::new(),
                boot_mode: "normal".to_string(),
            }
        }
    }

    /// Load a runtime configuration from a file
    pub fn load_runtime_config(path: &str) -> Result<RuntimeConfig> {
        let path = Path::new(path);
        let content = fs::read_to_string(path).map_err(|e| {
            ForgeError::ConfigError(format!("Failed to read runtime config file: {}", e))
        })?;

        match path.extension().and_then(|ext| ext.to_str()) {
            Some("json") => serde_json::from_str(&content).map_err(|e| {
                ForgeError::ConfigError(format!("Failed to parse JSON runtime config: {}", e))
            }),
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content).map_err(|e| {
                ForgeError::ConfigError(format!("Failed to parse YAML runtime config: {}", e))
            }),
            _ => Err(ForgeError::ConfigError(
                "Unsupported runtime config file format".to_string(),
            )),
        }
    }
}
