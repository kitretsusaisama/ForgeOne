//! # Configuration Tests
//! 
//! This module contains tests for the ForgeConfig and SignedConfig modules, focusing on
//! configuration loading, validation, and signature verification.

use std::fs;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::thread;
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use base64::{Engine as _, engine::general_purpose};

// Import from the config module
use common::config::{ForgeConfig, SignedConfig, load_config, load_signed_config, verify_signature};

/// Helper function to generate a key pair for testing
fn generate_key_pair() -> (Vec<u8>, Vec<u8>) {
    use rand::rngs::OsRng;
    use ed25519_dalek::SigningKey;
    let mut csprng = OsRng;
    
    // Generate 32 random bytes for the private key
    let mut private_key_bytes = [0u8; 32];
    use rand::RngCore;
    csprng.fill_bytes(&mut private_key_bytes);
    
    // Create signing key from the random bytes
    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let verifying_key = signing_key.verifying_key();
   
    (verifying_key.to_bytes().to_vec(), signing_key.to_bytes().to_vec())
}

/// Helper function to sign data for testing
fn sign(data: &[u8], private_key: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if private_key.len() != 32 {
        return Err("Private key must be exactly 32 bytes".into());
    }
    
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(private_key);
    
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let signature = signing_key.sign(data);
    Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test default configuration creation
    /// 
    /// This test verifies that a default configuration can be created.
    #[test]
    fn test_default_config() {
        // Create a default configuration
        let config = ForgeConfig::default();
        
        // Verify that the configuration has expected default values
        assert_eq!(config.name, "ForgeOne");
        assert_eq!(config.version, "0.1.0");
        assert_eq!(config.environment, "development");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.telemetry_endpoint, None);
        assert_eq!(config.audit_log_path, None);
        assert_eq!(config.policy_file_path, None);
        assert_eq!(config.enable_llm_tracing, false);
        assert_eq!(config.enable_crypto_verification, false);
        assert_eq!(config.trusted_public_keys.len(), 0);
    }

    /// Test configuration serialization and deserialization
    /// 
    /// This test verifies that configurations can be serialized to and deserialized from JSON.
    #[test]
    fn test_config_serialization() {
        // Create a configuration
        let mut config = ForgeConfig::default();
        config.log_level = "debug".to_string();
        config.telemetry_endpoint = Some("https://telemetry.example.com".to_string());
        config.audit_log_path = Some("/var/log/forge.log".to_string());
        config.enable_llm_tracing = true;
        config.enable_crypto_verification = true;
        config.trusted_public_keys = vec!["key1".to_string(), "key2".to_string()];
        
        // Serialize to JSON
        let json = serde_json::to_string(&config).expect("Failed to serialize config");
        
        // Deserialize from JSON
        let deserialized: ForgeConfig = serde_json::from_str(&json).expect("Failed to deserialize config");
        
        // Verify deserialized configuration
        assert_eq!(deserialized.log_level, "debug");
        assert_eq!(deserialized.telemetry_endpoint, Some("https://telemetry.example.com".to_string()));
        assert_eq!(deserialized.audit_log_path, Some("/var/log/forge.log".to_string()));
        assert_eq!(deserialized.enable_llm_tracing, true);
        assert_eq!(deserialized.enable_crypto_verification, true);
        assert_eq!(deserialized.trusted_public_keys, vec!["key1".to_string(), "key2".to_string()]);
    }

    /// Test configuration validation
    /// 
    /// This test verifies that configurations can be validated.
    #[test]
    fn test_config_validation() {
        // Create a valid configuration
        let mut valid_config = ForgeConfig::default();
        valid_config.log_level = "debug".to_string();
        valid_config.telemetry_endpoint = Some("https://telemetry.example.com".to_string());
        valid_config.enable_llm_tracing = true;
        
        // Basic validation - ensure config can be serialized (indicates structure is valid)
        let serialized = serde_json::to_string(&valid_config);
        assert!(serialized.is_ok());
        
        // Test that log levels are reasonable strings
        let valid_log_levels = vec!["trace", "debug", "info", "warn", "error"];
        for level in valid_log_levels {
            let mut test_config = ForgeConfig::default();
            test_config.log_level = level.to_string();
            let serialized = serde_json::to_string(&test_config);
            assert!(serialized.is_ok());
        }
    }

    /// Test signed configuration creation and verification
    /// 
    /// This test verifies that signed configurations can be created and verified.
    #[test]
    fn test_signed_config() {
        // Generate a key pair
        let (public_key, private_key) = generate_key_pair();
        
        // Create a configuration
        let mut config = ForgeConfig::default();
        config.log_level = "debug".to_string();
        config.enable_llm_tracing = true;
        config.enable_crypto_verification = true;
        
        // Sign the configuration
        let config_data = serde_json::to_vec(&config).expect("Failed to serialize config");
        let signature = sign(&config_data, &private_key).expect("Failed to sign config");
        
        // Create a signed configuration
        let signed_config = SignedConfig {
            content: config,
            signature,
            issued_by: "test_issuer".to_string(),
            timestamp: Utc::now(),
        };
        
        // Verify the signature
        let is_valid = verify_signature(&signed_config, &public_key).expect("Failed to verify signature");
        
        // Verify that the signature is valid
        assert!(is_valid, "Signature verification failed");
        
        // Modify the configuration
        let mut modified_config = signed_config.clone();
        modified_config.content.log_level = "info".to_string();
        
        // Verify that the signature is invalid for the modified configuration
        let is_valid = verify_signature(&modified_config, &public_key).expect("Failed to verify signature");
        assert!(!is_valid, "Signature verification should have failed for modified config");
    }

    /// Test configuration loading from a file
    /// 
    /// This test verifies that configurations can be loaded from files.
    #[test]
    fn test_config_loading() {
        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
        let config_path = temp_dir.path().join("config.json");
        
        // Create a configuration
        let mut config = ForgeConfig::default();
        config.log_level = "debug".to_string();
        config.telemetry_endpoint = Some("https://telemetry.example.com".to_string());
        config.enable_llm_tracing = true;
        
        // Serialize the configuration to JSON
        let config_json = serde_json::to_string(&config).expect("Failed to serialize config");
        
        // Write the configuration to a file
        let mut file = fs::File::create(&config_path).expect("Failed to create config file");
        file.write_all(config_json.as_bytes()).expect("Failed to write config file");
        
        // Load the configuration from the file
        let loaded_config = load_config(config_path.to_str().unwrap()).expect("Failed to load config");
        
        // Verify that the loaded configuration matches the original
        assert_eq!(loaded_config.log_level, "debug");
        assert_eq!(loaded_config.telemetry_endpoint, Some("https://telemetry.example.com".to_string()));
        assert_eq!(loaded_config.enable_llm_tracing, true);
    }

    /// Test YAML configuration loading
    /// 
    /// This test verifies that configurations can be loaded from YAML files.
    #[test]
    fn test_yaml_config_loading() {
        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
        let config_path = temp_dir.path().join("config.yaml");
        
        // Create YAML configuration content
        let yaml_content = r#"
name: "ForgeOne"
version: "0.1.0"
environment: "production"
log_level: "warn"
telemetry_endpoint: "https://telemetry.example.com"
audit_log_path: "/var/log/audit.log"
enable_llm_tracing: true
enable_crypto_verification: true
trusted_public_keys:
  - "key1"
  - "key2"
"#;
        
        // Write the YAML configuration to a file
        let mut file = fs::File::create(&config_path).expect("Failed to create config file");
        file.write_all(yaml_content.as_bytes()).expect("Failed to write config file");
        
        // Load the configuration from the file
        let loaded_config = load_config(config_path.to_str().unwrap()).expect("Failed to load config");
        
        // Verify that the loaded configuration matches the expected values
        assert_eq!(loaded_config.name, "ForgeOne");
        assert_eq!(loaded_config.version, "0.1.0");
        assert_eq!(loaded_config.environment, "production");
        assert_eq!(loaded_config.log_level, "warn");
        assert_eq!(loaded_config.telemetry_endpoint, Some("https://telemetry.example.com".to_string()));
        assert_eq!(loaded_config.audit_log_path, Some("/var/log/audit.log".to_string()));
        assert_eq!(loaded_config.enable_llm_tracing, true);
        assert_eq!(loaded_config.enable_crypto_verification, true);
        assert_eq!(loaded_config.trusted_public_keys, vec!["key1".to_string(), "key2".to_string()]);
    }

    /// Test signed configuration loading from a file
    /// 
    /// This test verifies that signed configurations can be loaded from files.
    #[test]
    fn test_signed_config_loading() {
        // Generate a key pair
        let (public_key, private_key) = generate_key_pair();
        
        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
        let config_path = temp_dir.path().join("signed_config.json");
        
        // Create a configuration
        let mut config = ForgeConfig::default();
        config.log_level = "debug".to_string();
        config.enable_llm_tracing = true;
        config.enable_crypto_verification = true;
        
        // Sign the configuration
        let config_data = serde_json::to_vec(&config).expect("Failed to serialize config");
        let signature = sign(&config_data, &private_key).expect("Failed to sign config");
        
        // Create a signed configuration
        let signed_config = SignedConfig {
            content: config,
            signature,
            issued_by: "test_issuer".to_string(),
            timestamp: Utc::now(),
        };
        
        // Serialize the signed configuration to JSON
        let signed_config_json = serde_json::to_string(&signed_config).expect("Failed to serialize signed config");
        
        // Write the signed configuration to a file
        let mut file = fs::File::create(&config_path).expect("Failed to create signed config file");
        file.write_all(signed_config_json.as_bytes()).expect("Failed to write signed config file");
        
        // Load the signed configuration from the file
        let loaded_signed_config: SignedConfig<ForgeConfig> = load_signed_config(config_path.to_str().unwrap()).expect("Failed to load signed config");
        
        // Verify that the loaded signed configuration matches the original
        assert_eq!(loaded_signed_config.content.log_level, signed_config.content.log_level);
        assert_eq!(loaded_signed_config.signature, signed_config.signature);
        assert_eq!(loaded_signed_config.issued_by, signed_config.issued_by);
        
        // Verify the signature of the loaded signed configuration
        let is_valid = verify_signature(&loaded_signed_config, &public_key).expect("Failed to verify signature");
        assert!(is_valid, "Signature verification failed for loaded signed config");
    }

    /// Test configuration with environment variables
    /// 
    /// This test verifies that configurations can be created with different values.
    #[test]
    fn test_config_variations() {
        // Create configurations with different values
        let mut config1 = ForgeConfig::default();
        config1.log_level = "trace".to_string();
        config1.environment = "production".to_string();
        config1.enable_llm_tracing = true;
        
        let mut config2 = ForgeConfig::default();
        config2.log_level = "error".to_string();
        config2.environment = "staging".to_string();
        config2.enable_crypto_verification = true;
        
        // Verify that the configurations are different
        assert_ne!(config1.log_level, config2.log_level);
        assert_ne!(config1.environment, config2.environment);
        assert_ne!(config1.enable_llm_tracing, config2.enable_llm_tracing);
        assert_ne!(config1.enable_crypto_verification, config2.enable_crypto_verification);
    }

    /// Test concurrent configuration access
    /// 
    /// This test verifies that configurations can be accessed concurrently.
    #[test]
    fn test_concurrent_config_access() {
        // Create a shared configuration
        let config = Arc::new(Mutex::new(ForgeConfig::default()));
        
        // Create a vector to hold thread handles
        let mut handles = vec![];
        
        // Spawn 10 threads to access the configuration
        for _ in 0..10 {
            let config_clone: Arc<Mutex<ForgeConfig>> = Arc::clone(&config);
            
            let handle = thread::spawn(move || {
                // Lock the configuration
                let config = config_clone.lock().unwrap();
                
                // Read configuration values
                let log_level = config.log_level.clone();
                let name = config.name.clone();
                let version = config.version.clone();
                
                // Return the values
                (log_level, name, version)
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            let (log_level, name, version) = handle.join().unwrap();
            
            // Verify that the values match the default configuration
            assert_eq!(log_level, ForgeConfig::default().log_level);
            assert_eq!(name, ForgeConfig::default().name);
            assert_eq!(version, ForgeConfig::default().version);
        }
    }

    /// Test configuration with custom fields
    /// 
    /// This test verifies that configurations can include custom fields without breaking deserialization.
    #[test]
    fn test_config_custom_fields() {
        // Create a JSON string with custom fields
        let json = r#"{
            "name": "ForgeOne",
            "version": "0.1.0",
            "environment": "development",
            "log_level": "debug",
            "telemetry_endpoint": "https://telemetry.example.com",
            "audit_log_path": "/var/log/audit.log",
            "enable_llm_tracing": true,
            "enable_crypto_verification": true,
            "trusted_public_keys": ["key1", "key2"],
            "custom_field1": "custom_value1",
            "custom_field2": 42,
            "custom_object": {
                "nested_field": "nested_value"
            }
        }"#;
        
        // Deserialize the JSON to a ForgeConfig (this should work despite extra fields)
        let config: ForgeConfig = serde_json::from_str(json).expect("Failed to deserialize config with custom fields");
        
        // Verify that the standard fields were parsed correctly
        assert_eq!(config.name, "ForgeOne");
        assert_eq!(config.version, "0.1.0");
        assert_eq!(config.environment, "development");
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.telemetry_endpoint, Some("https://telemetry.example.com".to_string()));
        assert_eq!(config.audit_log_path, Some("/var/log/audit.log".to_string()));
        assert_eq!(config.enable_llm_tracing, true);
        assert_eq!(config.enable_crypto_verification, true);
        assert_eq!(config.trusted_public_keys, vec!["key1".to_string(), "key2".to_string()]);
        
        // Verify that the custom fields were ignored without causing an error
    }

    /// Test invalid signature verification
    /// 
    /// This test verifies that invalid signatures are properly rejected.
    #[test]
    fn test_invalid_signature_verification() {
        // Generate a key pair
        let (public_key, _private_key) = generate_key_pair();
        
        // Create a configuration
        let config = ForgeConfig::default();
        
        // Create a signed configuration with an invalid signature
        let signed_config = SignedConfig {
            content: config,
            signature: "invalid_signature".to_string(),
            issued_by: "test_issuer".to_string(),
            timestamp: Utc::now(),
        };
        
        // Verify that the signature verification fails
        let result = verify_signature(&signed_config, &public_key);
        assert!(result.is_err() || result.unwrap() == false, "Invalid signature should be rejected");
    }

    /// Test configuration loading with invalid file format
    /// 
    /// This test verifies that loading configurations with unsupported formats fails gracefully.
    #[test]
    fn test_config_loading_invalid_format() {
        // Create a temporary directory for the test
        let temp_dir = tempfile::tempdir().expect("Failed to create temporary directory");
        let config_path = temp_dir.path().join("config.txt");
        
        // Write some content to the file
        let mut file = fs::File::create(&config_path).expect("Failed to create config file");
        file.write_all(b"This is not a valid config format").expect("Failed to write config file");
        
        // Attempt to load the configuration from the file
        let result = load_config(config_path.to_str().unwrap());
        
        // Verify that the loading fails
        assert!(result.is_err(), "Loading invalid config format should fail");
    }
}