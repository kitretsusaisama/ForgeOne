//! # Configuration Loader
//!
//! This module provides functionality for loading container configurations
//! from various sources, including files, environment variables, and command-line arguments.

use crate::runtime::RuntimeConfig;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde_json;
use std::fs;
use std::path::Path;

/// Load container configuration from file
pub fn load_config_from_file(config_path: &str) -> Result<RuntimeConfig> {
    let span = ExecutionSpan::new(
        "load_config_from_file",
        common::identity::IdentityContext::system(),
    );

    // Check if file exists
    if !Path::new(config_path).exists() {
        return Err(ForgeError::IOError {
            operation: "read".to_string(),
            path: config_path.to_string(),
            error: "File does not exist".to_string(),
        });
    }

    // Load configuration from file
    let config_str = fs::read_to_string(config_path).map_err(|e| ForgeError::IOError {
        operation: "read".to_string(),
        path: config_path.to_string(),
        error: e.to_string(),
    })?;

    // Determine file format based on extension
    let extension = Path::new(config_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");

    // Parse configuration based on file format
    let config = match extension.to_lowercase().as_str() {
        "json" => serde_json::from_str(&config_str).map_err(|e| ForgeError::ParseError {
            format: "json".to_string(),
            error: e.to_string(),
        }),
        "yaml" | "yml" => serde_yaml::from_str(&config_str).map_err(|e| ForgeError::ParseError {
            format: "yaml".to_string(),
            error: e.to_string(),
        }),
        _ => Err(ForgeError::ParseError {
            format: "unknown".to_string(),
            error: format!("Unsupported file format: {}", extension),
        }),
    }?;

    Ok(config)
}

/// Load container configuration from environment variables
pub fn load_config_from_env(prefix: &str) -> Result<RuntimeConfig> {
    let span = ExecutionSpan::new(
        "load_config_from_env",
        common::identity::IdentityContext::system(),
    );

    // Get all environment variables with the specified prefix
    let env_vars: std::collections::HashMap<String, String> = std::env::vars()
        .filter(|(key, _)| key.starts_with(prefix))
        .collect();

    // Convert environment variables to JSON
    let json = serde_json::to_string(&env_vars).map_err(|e| ForgeError::SerializeError {
        format: "json".to_string(),
        error: e.to_string(),
    })?;

    // Parse JSON to RuntimeConfig
    let config = serde_json::from_str(&json).map_err(|e| ForgeError::ParseError {
        format: "json".to_string(),
        error: e.to_string(),
    })?;

    Ok(config)
}

/// Load container configuration from multiple sources
pub fn load_config(config_path: Option<&str>, env_prefix: Option<&str>) -> Result<RuntimeConfig> {
    let span = ExecutionSpan::new(
        "load_config",
        common::identity::IdentityContext::system(),
    );

    // Load configuration from file if specified
    let mut config = if let Some(path) = config_path {
        load_config_from_file(path)?
    } else {
        // Default configuration
        RuntimeConfig::default()
    };

    // Load configuration from environment variables if specified
    if let Some(prefix) = env_prefix {
        let env_config = load_config_from_env(prefix)?;
        // Merge environment configuration with file configuration
        // Environment variables take precedence over file configuration
        config = merge_configs(config, env_config);
    }

    Ok(config)
}

/// Merge two configurations
fn merge_configs(base: RuntimeConfig, override_config: RuntimeConfig) -> RuntimeConfig {
    // Create a new configuration with base values
    let mut merged = base;

    // Override values from override_config
    // This is a simplified implementation, in a real-world scenario,
    // you would need to handle nested structures and arrays
    if override_config.max_containers > 0 {
        merged.max_containers = override_config.max_containers;
    }

    if let Some(limits) = override_config.default_resource_limits {
        merged.default_resource_limits = Some(limits);
    }

    if override_config.enable_metrics {
        merged.enable_metrics = true;
    }

    // Add more fields as needed

    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dna::ResourceLimits;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_config_from_file_json() {
        // Create a temporary JSON file
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_string_lossy().to_string();

        // Write JSON configuration to file
        let config_json = r#"{
            "max_containers": 10,
            "enable_metrics": true,
            "default_resource_limits": {
                "cpu_cores": 1.0,
                "memory_bytes": 104857600,
                "disk_bytes": 1073741824,
                "network_bps": 1048576
            }
        }"#;
        temp_file.write_all(config_json.as_bytes()).unwrap();

        // Load configuration from file
        let config = load_config_from_file(&temp_path).unwrap();

        // Check configuration values
        assert_eq!(config.max_containers, 10);
        assert_eq!(config.enable_metrics, true);
        assert_eq!(config.default_resource_limits.unwrap().cpu_cores, Some(1.0));
    }

    #[test]
    fn test_load_config_from_file_yaml() {
        // Create a temporary YAML file
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = format!("{}.yaml", temp_file.path().to_string_lossy());
        let yaml_file = std::fs::File::create(&temp_path).unwrap();
        let mut yaml_writer = std::io::BufWriter::new(yaml_file);

        // Write YAML configuration to file
        let config_yaml = r#"max_containers: 20
enable_metrics: true
default_resource_limits:
  cpu_cores: 2.0
  memory_bytes: 209715200
  disk_bytes: 2147483648
  network_bps: 2097152"#;
        yaml_writer.write_all(config_yaml.as_bytes()).unwrap();
        yaml_writer.flush().unwrap();

        // Load configuration from file
        let config = load_config_from_file(&temp_path).unwrap();

        // Check configuration values
        assert_eq!(config.max_containers, 20);
        assert_eq!(config.enable_metrics, true);
        assert_eq!(config.default_resource_limits.unwrap().cpu_cores, Some(2.0));

        // Clean up
        std::fs::remove_file(&temp_path).unwrap();
    }

    #[test]
    fn test_merge_configs() {
        // Create base configuration
        let base = RuntimeConfig {
            max_containers: 10,
            enable_metrics: false,
            default_resource_limits: Some(ResourceLimits {
                cpu_cores: Some(1.0),
                memory_bytes: Some(104857600),
                disk_bytes: Some(1073741824),
                network_bps: Some(1048576),
            }),
        };

        // Create override configuration
        let override_config = RuntimeConfig {
            max_containers: 20,
            enable_metrics: true,
            default_resource_limits: Some(ResourceLimits {
                cpu_cores: Some(2.0),
                memory_bytes: Some(209715200),
                disk_bytes: Some(2147483648),
                network_bps: Some(2097152),
            }),
        };

        // Merge configurations
        let merged = merge_configs(base, override_config);

        // Check merged configuration values
        assert_eq!(merged.max_containers, 20);
        assert_eq!(merged.enable_metrics, true);
        assert_eq!(merged.default_resource_limits.unwrap().cpu_cores, Some(2.0));
    }
}