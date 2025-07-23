//! # Container Configuration Module
//!
//! This module provides functionality for managing container configurations,
//! including loading, saving, and validating container configurations.

mod loader;
mod saver;
mod validator;
mod tests;

pub use loader::{load_config, load_config_from_env, load_config_from_file};
pub use saver::{save_config, save_config_to_env, save_config_to_file, save_config_to_registry};
pub use validator::{validate_config, is_valid_ip_address};

use crate::dna::ResourceLimits;
use crate::contract::zta::ExecMode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Container configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Container name
    pub name: Option<String>,
    /// Container image
    pub image: String,
    /// Container command
    pub command: Option<String>,
    /// Container arguments
    pub args: Option<Vec<String>>,
    /// Container environment variables
    pub env: Option<HashMap<String, String>>,
    /// Container working directory
    pub working_dir: Option<String>,
    /// Container resource limits
    pub resource_limits: Option<ResourceLimits>,
    /// Container trusted issuers
    pub trusted_issuers: Option<Vec<String>>,
    /// Container minimum entropy
    pub minimum_entropy: Option<f64>,
    /// Container execution mode
    pub exec_mode: Option<ExecMode>,
    /// Container mounts
    pub mounts: Option<Vec<Mount>>,
    /// Container volumes
    pub volumes: Option<Vec<Volume>>,
    /// Container network configuration
    pub network: Option<NetworkConfig>,
    /// Container labels
    pub labels: Option<HashMap<String, String>>,
    /// Container annotations
    pub annotations: Option<HashMap<String, String>>,
    /// Custom container configuration
    pub custom: Option<HashMap<String, String>>,
}

impl ContainerConfig {
    /// Create a new container configuration
    pub fn new(image: &str) -> Self {
        Self {
            name: None,
            image: image.to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: None,
            trusted_issuers: None,
            minimum_entropy: None,
            exec_mode: None,
            mounts: None,
            volumes: None,
            network: None,
            labels: None,
            annotations: None,
            custom: None,
        }
    }

    /// Set container name
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Set container command
    pub fn with_command(mut self, command: &str) -> Self {
        self.command = Some(command.to_string());
        self
    }

    /// Set container arguments
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = Some(args);
        self
    }

    /// Add container environment variable
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        let mut env = self.env.unwrap_or_default();
        env.insert(key.to_string(), value.to_string());
        self.env = Some(env);
        self
    }

    /// Set container working directory
    pub fn with_working_dir(mut self, working_dir: &str) -> Self {
        self.working_dir = Some(working_dir.to_string());
        self
    }

    /// Set container resource limits
    pub fn with_resource_limits(mut self, resource_limits: ResourceLimits) -> Self {
        self.resource_limits = Some(resource_limits);
        self
    }

    /// Set container trusted issuers
    pub fn with_trusted_issuers(mut self, trusted_issuers: Vec<String>) -> Self {
        self.trusted_issuers = Some(trusted_issuers);
        self
    }

    /// Set container minimum entropy
    pub fn with_minimum_entropy(mut self, minimum_entropy: f64) -> Self {
        self.minimum_entropy = Some(minimum_entropy);
        self
    }

    /// Set container execution mode
    pub fn with_exec_mode(mut self, exec_mode: ExecMode) -> Self {
        self.exec_mode = Some(exec_mode);
        self
    }

    /// Add container mount
    pub fn with_mount(mut self, mount: Mount) -> Self {
        let mut mounts = self.mounts.unwrap_or_default();
        mounts.push(mount);
        self.mounts = Some(mounts);
        self
    }

    /// Add container volume
    pub fn with_volume(mut self, volume: Volume) -> Self {
        let mut volumes = self.volumes.unwrap_or_default();
        volumes.push(volume);
        self.volumes = Some(volumes);
        self
    }

    /// Set container network configuration
    pub fn with_network(mut self, network: NetworkConfig) -> Self {
        self.network = Some(network);
        self
    }

    /// Add container label
    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        let mut labels = self.labels.unwrap_or_default();
        labels.insert(key.to_string(), value.to_string());
        self.labels = Some(labels);
        self
    }

    /// Add container annotation
    pub fn with_annotation(mut self, key: &str, value: &str) -> Self {
        let mut annotations = self.annotations.unwrap_or_default();
        annotations.insert(key.to_string(), value.to_string());
        self.annotations = Some(annotations);
        self
    }

    /// Add custom container configuration
    pub fn with_custom(mut self, key: &str, value: &str) -> Self {
        let mut custom = self.custom.unwrap_or_default();
        custom.insert(key.to_string(), value.to_string());
        self.custom = Some(custom);
        self
    }
}

/// Container mount
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    /// Source path
    pub source: String,
    /// Destination path
    pub destination: String,
    /// Mount type
    pub mount_type: MountType,
    /// Mount options
    pub options: Option<Vec<String>>,
    /// Read-only flag
    pub read_only: bool,
}

/// Mount type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MountType {
    /// Bind mount
    Bind,
    /// Volume mount
    Volume,
    /// Tmpfs mount
    Tmpfs,
    /// Custom mount
    Custom,
}

impl std::fmt::Display for MountType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MountType::Bind => write!(f, "bind"),
            MountType::Volume => write!(f, "volume"),
            MountType::Tmpfs => write!(f, "tmpfs"),
            MountType::Custom => write!(f, "custom"),
        }
    }
}

/// Container volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Volume name
    pub name: String,
    /// Volume path
    pub path: String,
    /// Volume driver
    pub driver: Option<String>,
    /// Volume options
    pub options: Option<HashMap<String, String>>,
}

/// Container network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network mode
    pub mode: NetworkMode,
    /// Network name
    pub name: Option<String>,
    /// Network IP address
    pub ip_address: Option<String>,
    /// Network gateway
    pub gateway: Option<String>,
    /// Network DNS servers
    pub dns: Option<Vec<String>>,
    /// Network DNS search domains
    pub dns_search: Option<Vec<String>>,
    /// Network hostname
    pub hostname: Option<String>,
    /// Network domain name
    pub domain_name: Option<String>,
    /// Network extra hosts
    pub extra_hosts: Option<HashMap<String, String>>,
    /// Network ports
    pub ports: Option<Vec<PortMapping>>,
    /// Network options
    pub options: Option<HashMap<String, String>>,
}

/// Network mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    /// Bridge network
    Bridge,
    /// Host network
    Host,
    /// None network
    None,
    /// Container network
    Container,
    /// Custom network
    Custom,
}

impl std::fmt::Display for NetworkMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkMode::Bridge => write!(f, "bridge"),
            NetworkMode::Host => write!(f, "host"),
            NetworkMode::None => write!(f, "none"),
            NetworkMode::Container => write!(f, "container"),
            NetworkMode::Custom => write!(f, "custom"),
        }
    }
}

/// Port mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Host port
    pub host_port: u16,
    /// Container port
    pub container_port: u16,
    /// Protocol
    pub protocol: PortProtocol,
    /// Host IP
    pub host_ip: Option<String>,
}

/// Port protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortProtocol {
    /// TCP protocol
    TCP,
    /// UDP protocol
    UDP,
    /// SCTP protocol
    SCTP,
}

impl std::fmt::Display for PortProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortProtocol::TCP => write!(f, "tcp"),
            PortProtocol::UDP => write!(f, "udp"),
            PortProtocol::SCTP => write!(f, "sctp"),
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::dna::ResourceLimits;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_container_config() {
        // Create container configuration
        let config = ContainerConfig::new("test-image")
            .with_name("test-container")
            .with_command("/bin/sh")
            .with_args(vec!["-c".to_string(), "echo hello".to_string()])
            .with_env("TEST_VAR", "test_value")
            .with_working_dir("/app")
            .with_resource_limits(ResourceLimits {
                cpu_cores: Some(1.0),
                memory_bytes: Some(1024 * 1024 * 100),
                disk_bytes: Some(1024 * 1024 * 1000),
                network_bps: Some(1024 * 1024),
            })
            .with_trusted_issuers(vec!["system".to_string()])
            .with_minimum_entropy(0.5)
            .with_exec_mode(ExecMode::Restricted)
            .with_mount(Mount {
                source: "/host/path".to_string(),
                destination: "/container/path".to_string(),
                mount_type: MountType::Bind,
                options: None,
                read_only: true,
            })
            .with_volume(Volume {
                name: "test-volume".to_string(),
                path: "/data".to_string(),
                driver: None,
                options: None,
            })
            .with_network(NetworkConfig {
                mode: NetworkMode::Bridge,
                name: Some("test-network".to_string()),
                ip_address: Some("172.17.0.2".to_string()),
                gateway: Some("172.17.0.1".to_string()),
                dns: Some(vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()]),
                dns_search: None,
                hostname: Some("test-container".to_string()),
                domain_name: None,
                extra_hosts: None,
                ports: Some(vec![PortMapping {
                    host_port: 8080,
                    container_port: 80,
                    protocol: PortProtocol::TCP,
                    host_ip: None,
                }]),
                options: None,
            })
            .with_label("key1", "value1")
            .with_annotation("key2", "value2")
            .with_custom("key3", "value3");

        // Check configuration values
        assert_eq!(config.image, "test-image");
        assert_eq!(config.name, Some("test-container".to_string()));
        assert_eq!(config.command, Some("/bin/sh".to_string()));
        assert_eq!(
            config.args,
            Some(vec!["-c".to_string(), "echo hello".to_string()])
        );
        assert_eq!(
            config.env,
            Some({
                let mut map = HashMap::new();
                map.insert("TEST_VAR".to_string(), "test_value".to_string());
                map
            })
        );
        assert_eq!(config.working_dir, Some("/app".to_string()));
        assert_eq!(
            config.resource_limits,
            Some(ResourceLimits {
                cpu_cores: Some(1.0),
                memory_bytes: Some(1024 * 1024 * 100),
                disk_bytes: Some(1024 * 1024 * 1000),
                network_bps: Some(1024 * 1024),
            })
        );
        assert_eq!(
            config.trusted_issuers,
            Some(vec!["system".to_string()])
        );
        assert_eq!(config.minimum_entropy, Some(0.5));
        assert_eq!(config.exec_mode, Some(ExecMode::Restricted));
        assert_eq!(config.mounts.as_ref().unwrap().len(), 1);
        assert_eq!(config.volumes.as_ref().unwrap().len(), 1);
        assert_eq!(config.network.as_ref().unwrap().mode, NetworkMode::Bridge);
        assert_eq!(
            config.labels,
            Some({
                let mut map = HashMap::new();
                map.insert("key1".to_string(), "value1".to_string());
                map
            })
        );
        assert_eq!(
            config.annotations,
            Some({
                let mut map = HashMap::new();
                map.insert("key2".to_string(), "value2".to_string());
                map
            })
        );
        assert_eq!(
            config.custom,
            Some({
                let mut map = HashMap::new();
                map.insert("key3".to_string(), "value3".to_string());
                map
            })
        );

        // Validate configuration
        assert!(validate_config(&config).is_ok());

        // Test serialization and deserialization
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ContainerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.image, config.image);
        assert_eq!(deserialized.name, config.name);
    }

    #[test]
    fn test_save_and_load_config() {
        // Create container configuration
        let config = ContainerConfig::new("test-image")
            .with_name("test-container")
            .with_command("/bin/sh")
            .with_args(vec!["-c".to_string(), "echo hello".to_string()]);

        // Create temporary file
        let mut temp_file = NamedTempFile::new().unwrap();
        let temp_path = temp_file.path().to_string_lossy().to_string();

        // Save configuration to file
        save_config(&config, &temp_path).unwrap();

        // Read file content
        let mut content = String::new();
        temp_file.as_file_mut().rewind().unwrap();
        temp_file.as_file_mut().read_to_string(&mut content).unwrap();

        // Deserialize configuration
        let loaded_config: ContainerConfig = serde_json::from_str(&content).unwrap();

        // Check loaded configuration
        assert_eq!(loaded_config.image, "test-image");
        assert_eq!(loaded_config.name, Some("test-container".to_string()));
        assert_eq!(loaded_config.command, Some("/bin/sh".to_string()));
        assert_eq!(
            loaded_config.args,
            Some(vec!["-c".to_string(), "echo hello".to_string()])
        );
    }

    #[test]
    fn test_validate_config_errors() {
        // Empty image
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: None,
            trusted_issuers: None,
            minimum_entropy: None,
            exec_mode: None,
            mounts: None,
            volumes: None,
            network: None,
            labels: None,
            annotations: None,
            custom: None,
        };
        assert!(validate_config(&config).is_err());

        // Invalid resource limits
        let config = ContainerConfig::new("test-image").with_resource_limits(ResourceLimits {
            cpu_cores: Some(-1.0),
            memory_bytes: None,
            disk_bytes: None,
            network_bps: None,
        });
        assert!(validate_config(&config).is_err());

        // Invalid minimum entropy
        let config = ContainerConfig::new("test-image").with_minimum_entropy(2.0);
        assert!(validate_config(&config).is_err());

        // Invalid mount
        let config = ContainerConfig::new("test-image").with_mount(Mount {
            source: "".to_string(),
            destination: "/container/path".to_string(),
            mount_type: MountType::Bind,
            options: None,
            read_only: true,
        });
        assert!(validate_config(&config).is_err());

        // Invalid volume
        let config = ContainerConfig::new("test-image").with_volume(Volume {
            name: "".to_string(),
            path: "/data".to_string(),
            driver: None,
            options: None,
        });
        assert!(validate_config(&config).is_err());

        // Invalid port
        let config = ContainerConfig::new("test-image").with_network(NetworkConfig {
            mode: NetworkMode::Bridge,
            name: None,
            ip_address: None,
            gateway: None,
            dns: None,
            dns_search: None,
            hostname: None,
            domain_name: None,
            extra_hosts: None,
            ports: Some(vec![PortMapping {
                host_port: 0,
                container_port: 80,
                protocol: PortProtocol::TCP,
                host_ip: None,
            }]),
            options: None,
        });
        assert!(validate_config(&config).is_err());
    }
}