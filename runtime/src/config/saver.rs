//! # Configuration Saver
//!
//! This module provides functionality for saving container configurations
//! to various formats and destinations.

use crate::config::ContainerConfig;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde_json;
use std::fs;
use std::path::Path;

/// Save container configuration to file
pub fn save_config_to_file(config: &ContainerConfig, config_path: &str) -> Result<()> {
    let span = ExecutionSpan::new(
        "save_config_to_file",
        common::identity::IdentityContext::system(),
    );

    // Create parent directory if it doesn't exist
    if let Some(parent) = Path::new(config_path).parent() {
        fs::create_dir_all(parent).map_err(|e| {
            ForgeError::IoError(format!("create_dir {}: {}", parent.to_string_lossy(), e))
        })?;
    }

    // Determine file format based on extension
    let extension = Path::new(config_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    // Serialize configuration based on file format
    let config_str = match extension.to_lowercase().as_str() {
        "json" => serde_json::to_string_pretty(config).map_err(|e| ForgeError::ParseError {
            format: "json".to_string(),
            error: e.to_string(),
        }),
        "yaml" | "yml" => serde_yaml::to_string(config).map_err(|e| ForgeError::ParseError {
            format: "yaml".to_string(),
            error: e.to_string(),
        }),
        _ => Err(ForgeError::ParseError {
            format: "unknown".to_string(),
            error: format!("Unsupported file format: {}", extension),
        }),
    }?;

    // Save configuration to file
    fs::write(config_path, config_str)
        .map_err(|e| ForgeError::IoError(format!("write {}: {}", config_path, e)))?;

    Ok(())
}

/// Save container configuration to environment variables
pub fn save_config_to_env(config: &ContainerConfig, prefix: &str) -> Result<()> {
    let span = ExecutionSpan::new(
        "save_config_to_env",
        common::identity::IdentityContext::system(),
    );

    // Serialize configuration to JSON
    let json = serde_json::to_string(config).map_err(|e| ForgeError::ParseError {
        format: "json".to_string(),
        error: e.to_string(),
    })?;

    // Parse JSON to HashMap
    let config_map: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(&json).map_err(|e| ForgeError::ParseError {
            format: "json".to_string(),
            error: e.to_string(),
        })?;

    // Set environment variables
    for (key, value) in config_map {
        if !value.is_null() {
            let env_key = format!("{}{}", prefix, key.to_uppercase());
            let env_value = value.to_string();
            std::env::set_var(env_key, env_value);
        }
    }

    Ok(())
}

/// Save container configuration to registry
pub fn save_config_to_registry(config: &ContainerConfig, key: &str) -> Result<()> {
    let span = ExecutionSpan::new(
        "save_config_to_registry",
        common::identity::IdentityContext::system(),
    );

    // This is a placeholder for registry storage
    // In a real implementation, this would save the configuration to a registry
    // such as etcd, Consul, or a database

    // Serialize configuration to JSON
    let json = serde_json::to_string(config).map_err(|e| ForgeError::ParseError {
        format: "json".to_string(),
        error: e.to_string(),
    })?;

    // Log the operation for now (placeholder)
    // (logging removed)

    Ok(())
}

/// Save container configuration to multiple destinations
pub fn save_config(
    config: &ContainerConfig,
    config_path: Option<&str>,
    env_prefix: Option<&str>,
    registry_key: Option<&str>,
) -> Result<()> {
    let span = ExecutionSpan::new("save_config", common::identity::IdentityContext::system());

    // Save configuration to file if specified
    if let Some(path) = config_path {
        save_config_to_file(config, path)?;
    }

    // Save configuration to environment variables if specified
    if let Some(prefix) = env_prefix {
        save_config_to_env(config, prefix)?;
    }

    // Save configuration to registry if specified
    if let Some(key) = registry_key {
        save_config_to_registry(config, key)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MountType, NetworkMode, PortProtocol};
    use crate::dna::ResourceLimits;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn test_save_config_to_file_json() {
        // Create a temporary JSON file
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = format!("{}.json", temp_file.path().to_string_lossy());

        // Create container configuration
        let config = ContainerConfig::new("test-image:latest")
            .with_name("test-container")
            .with_command("/bin/sh")
            .with_args(vec!["-c".to_string(), "echo hello".to_string()])
            .with_resource_limits(ResourceLimits {
                cpu_millicores: 1000,
                memory_bytes: 1024 * 1024 * 100,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            });

        // Save configuration to file
        save_config_to_file(&config, &temp_path).unwrap();

        // Read file content
        let mut content = String::new();
        let mut file = fs::File::open(&temp_path).unwrap();
        file.read_to_string(&mut content).unwrap();

        // Deserialize configuration
        let loaded_config: ContainerConfig = serde_json::from_str(&content).unwrap();

        // Check loaded configuration
        assert_eq!(loaded_config.image, "test-image:latest");
        assert_eq!(loaded_config.name, Some("test-container".to_string()));
        assert_eq!(loaded_config.command, Some("/bin/sh".to_string()));
        assert_eq!(
            loaded_config.args,
            Some(vec!["-c".to_string(), "echo hello".to_string()])
        );

        // Clean up
        fs::remove_file(&temp_path).unwrap();
    }

    #[test]
    fn test_save_config_to_file_yaml() {
        // Create a temporary YAML file
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = format!("{}.yaml", temp_file.path().to_string_lossy());

        // Create container configuration
        let config = ContainerConfig::new("test-image:latest")
            .with_name("test-container")
            .with_command("/bin/sh")
            .with_args(vec!["-c".to_string(), "echo hello".to_string()])
            .with_resource_limits(ResourceLimits {
                cpu_millicores: 1000,
                memory_bytes: 1024 * 1024 * 100,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            });

        // Save configuration to file
        save_config_to_file(&config, &temp_path).unwrap();

        // Read file content
        let mut content = String::new();
        let mut file = fs::File::open(&temp_path).unwrap();
        file.read_to_string(&mut content).unwrap();

        // Deserialize configuration
        let loaded_config: ContainerConfig = serde_yaml::from_str(&content).unwrap();

        // Check loaded configuration
        assert_eq!(loaded_config.image, "test-image:latest");
        assert_eq!(loaded_config.name, Some("test-container".to_string()));
        assert_eq!(loaded_config.command, Some("/bin/sh".to_string()));
        assert_eq!(
            loaded_config.args,
            Some(vec!["-c".to_string(), "echo hello".to_string()])
        );

        // Clean up
        fs::remove_file(&temp_path).unwrap();
    }

    #[test]
    fn test_save_config_to_env() {
        // Create container configuration
        let config = ContainerConfig::new("test-image:latest")
            .with_name("test-container")
            .with_command("/bin/sh")
            .with_args(vec!["-c".to_string(), "echo hello".to_string()])
            .with_resource_limits(ResourceLimits {
                cpu_millicores: 1000,
                memory_bytes: 1024 * 1024 * 100,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            });

        // Save configuration to environment variables
        save_config_to_env(&config, "TEST_").unwrap();

        // Check environment variables
        assert_eq!(
            std::env::var("TEST_IMAGE").unwrap(),
            "\"test-image:latest\""
        );
        assert_eq!(std::env::var("TEST_NAME").unwrap(), "\"test-container\"");
        assert_eq!(std::env::var("TEST_COMMAND").unwrap(), "\"/bin/sh\"");
    }

    #[test]
    fn test_save_config() {
        // Create a temporary JSON file
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = format!("{}.json", temp_file.path().to_string_lossy());

        // Create container configuration
        let config = ContainerConfig::new("test-image:latest")
            .with_name("test-container")
            .with_command("/bin/sh")
            .with_args(vec!["-c".to_string(), "echo hello".to_string()])
            .with_resource_limits(ResourceLimits {
                cpu_millicores: 1000,
                memory_bytes: 1024 * 1024 * 100,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            });

        // Save configuration to multiple destinations
        save_config(&config, Some(&temp_path), Some("TEST2_"), Some("test-key")).unwrap();

        // Check file
        assert!(Path::new(&temp_path).exists());

        // Check environment variables
        assert_eq!(
            std::env::var("TEST2_IMAGE").unwrap(),
            "\"test-image:latest\""
        );
        assert_eq!(std::env::var("TEST2_NAME").unwrap(), "\"test-container\"");
        assert_eq!(std::env::var("TEST2_COMMAND").unwrap(), "\"/bin/sh\"");

        // Clean up
        fs::remove_file(&temp_path).unwrap();
    }
}
