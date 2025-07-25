//! # Configuration Validator
//!
//! This module provides functionality for validating container configurations,
//! ensuring that they meet the required constraints and are secure.

use crate::config::{ContainerConfig, Mount, NetworkConfig, PortMapping, Volume};
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;

/// Validate container configuration
pub fn validate_config(config: &ContainerConfig) -> Result<()> {
    let span = ExecutionSpan::new(
        "validate_container_config",
        common::identity::IdentityContext::system(),
    );

    // Validate image
    validate_image(config)?;

    // Validate resource limits
    validate_resource_limits(config)?;

    // Validate minimum entropy
    validate_minimum_entropy(config)?;

    // Validate mounts
    validate_mounts(config)?;

    // Validate volumes
    validate_volumes(config)?;

    // Validate network configuration
    validate_network(config)?;

    Ok(())
}

/// Validate container image
fn validate_image(config: &ContainerConfig) -> Result<()> {
    if config.image.is_empty() {
        return Err(ForgeError::ValidationError {
            field: "image".to_string(),
            rule: "required".to_string(),
            value: "".to_string(),
            suggestions: vec!["Provide a valid image name with tag or digest".to_string()],
        });
    }

    // Check for valid image format (e.g., name:tag)
    if !config.image.contains(':') && !config.image.contains('@') {
        return Err(ForgeError::ValidationError {
            field: "image".to_string(),
            rule: "valid_format".to_string(),
            value: config.image.clone(),
            suggestions: vec![
                "Ensure the image name includes a tag or digest".to_string(),
                "Use a valid image name with tag or digest".to_string(),
            ],
        });
    }

    Ok(())
}

/// Validate container resource limits
fn validate_resource_limits(config: &ContainerConfig) -> Result<()> {
    if let Some(resource_limits) = &config.resource_limits {
        if resource_limits.cpu_millicores <= 0 {
            return Err(ForgeError::ValidationError {
                field: "resource_limits.cpu_millicores".to_string(),
                rule: "positive".to_string(),
                value: resource_limits.cpu_millicores.to_string(),
                suggestions: vec!["Ensure CPU millicores are greater than 0".to_string()],
            });
        }
        if resource_limits.memory_bytes == 0 {
            return Err(ForgeError::ValidationError {
                field: "resource_limits.memory_bytes".to_string(),
                rule: "positive".to_string(),
                value: resource_limits.memory_bytes.to_string(),
                suggestions: vec!["Ensure memory bytes are greater than 0".to_string()],
            });
        }
        if resource_limits.disk_bytes == 0 {
            return Err(ForgeError::ValidationError {
                field: "resource_limits.disk_bytes".to_string(),
                rule: "positive".to_string(),
                value: resource_limits.disk_bytes.to_string(),
                suggestions: vec!["Ensure disk bytes are greater than 0".to_string()],
            });
        }
        if resource_limits.network_bps == 0 {
            return Err(ForgeError::ValidationError {
                field: "resource_limits.network_bps".to_string(),
                rule: "positive".to_string(),
                value: resource_limits.network_bps.to_string(),
                suggestions: vec!["Ensure network BPS is greater than 0".to_string()],
            });
        }
    }
    Ok(())
}

/// Validate container minimum entropy
fn validate_minimum_entropy(config: &ContainerConfig) -> Result<()> {
    if let Some(minimum_entropy) = config.minimum_entropy {
        if minimum_entropy < 0.0 || minimum_entropy > 1.0 {
            return Err(ForgeError::ValidationError {
                field: "minimum_entropy".to_string(),
                rule: "range".to_string(),
                value: minimum_entropy.to_string(),
                suggestions: vec!["Minimum entropy must be between 0.0 and 1.0".to_string()],
            });
        }
    }
    Ok(())
}

/// Validate container mounts
fn validate_mounts(config: &ContainerConfig) -> Result<()> {
    if let Some(mounts) = &config.mounts {
        for (i, mount) in mounts.iter().enumerate() {
            validate_mount(mount, i)?;
        }
    }

    Ok(())
}

/// Validate a single mount
fn validate_mount(mount: &Mount, index: usize) -> Result<()> {
    if mount.source.is_empty() {
        return Err(ForgeError::ValidationError {
            field: format!("mounts[{}].source", index),
            rule: "required".to_string(),
            value: "".to_string(),
            suggestions: vec!["Mount source cannot be empty".to_string()],
        });
    }
    if mount.destination.is_empty() {
        return Err(ForgeError::ValidationError {
            field: format!("mounts[{}].destination", index),
            rule: "required".to_string(),
            value: "".to_string(),
            suggestions: vec!["Mount destination cannot be empty".to_string()],
        });
    }
    if let Some(options) = &mount.options {
        for (j, option) in options.iter().enumerate() {
            if option.is_empty() {
                return Err(ForgeError::ValidationError {
                    field: format!("mounts[{}].options[{}]", index, j),
                    rule: "required".to_string(),
                    value: "".to_string(),
                    suggestions: vec!["Mount option cannot be empty".to_string()],
                });
            }
        }
    }
    Ok(())
}

/// Validate container volumes
fn validate_volumes(config: &ContainerConfig) -> Result<()> {
    if let Some(volumes) = &config.volumes {
        for (i, volume) in volumes.iter().enumerate() {
            validate_volume(volume, i)?;
        }
    }

    Ok(())
}

/// Validate a single volume
fn validate_volume(volume: &Volume, index: usize) -> Result<()> {
    if volume.name.is_empty() {
        return Err(ForgeError::ValidationError {
            field: format!("volumes[{}].name", index),
            rule: "required".to_string(),
            value: "".to_string(),
            suggestions: vec!["Volume name cannot be empty".to_string()],
        });
    }
    if volume.path.is_empty() {
        return Err(ForgeError::ValidationError {
            field: format!("volumes[{}].path", index),
            rule: "required".to_string(),
            value: "".to_string(),
            suggestions: vec!["Volume path cannot be empty".to_string()],
        });
    }
    if let Some(options) = &volume.options {
        for (key, value) in options {
            if key.is_empty() {
                return Err(ForgeError::ValidationError {
                    field: format!("volumes[{}].options.key", index),
                    rule: "required".to_string(),
                    value: "".to_string(),
                    suggestions: vec!["Volume option key cannot be empty".to_string()],
                });
            }
            if value.is_empty() {
                return Err(ForgeError::ValidationError {
                    field: format!("volumes[{}].options.{}", index, key),
                    rule: "required".to_string(),
                    value: "".to_string(),
                    suggestions: vec!["Volume option value cannot be empty".to_string()],
                });
            }
        }
    }
    Ok(())
}

/// Validate container network configuration
fn validate_network(config: &ContainerConfig) -> Result<()> {
    if let Some(network) = &config.network {
        // Validate network name
        if let Some(name) = &network.name {
            if name.is_empty() {
                return Err(ForgeError::ValidationError {
                    field: "network.name".to_string(),
                    rule: "required".to_string(),
                    value: "".to_string(),
                    suggestions: vec!["Network name cannot be empty".to_string()],
                });
            }
        }

        // Validate IP address
        if let Some(ip_address) = &network.ip_address {
            if !is_valid_ip_address(ip_address) {
                return Err(ForgeError::ValidationError {
                    field: "network.ip_address".to_string(),
                    rule: "invalid_format".to_string(),
                    value: ip_address.clone(),
                    suggestions: vec!["Invalid IP address format".to_string()],
                });
            }
        }

        // Validate gateway
        if let Some(gateway) = &network.gateway {
            if !is_valid_ip_address(gateway) {
                return Err(ForgeError::ValidationError {
                    field: "network.gateway".to_string(),
                    rule: "invalid_format".to_string(),
                    value: gateway.clone(),
                    suggestions: vec!["Invalid gateway IP address format".to_string()],
                });
            }
        }

        // Validate DNS servers
        if let Some(dns) = &network.dns {
            for (i, server) in dns.iter().enumerate() {
                if !is_valid_ip_address(server) {
                    return Err(ForgeError::ValidationError {
                        field: format!("network.dns[{}]", i),
                        rule: "invalid_format".to_string(),
                        value: server.clone(),
                        suggestions: vec!["Invalid DNS server IP address format".to_string()],
                    });
                }
            }
        }

        // Validate ports
        if let Some(ports) = &network.ports {
            for (i, port) in ports.iter().enumerate() {
                validate_port_mapping(port, i)?;
            }
        }

        // Validate network options
        if let Some(options) = &network.options {
            for (key, value) in options {
                if key.is_empty() {
                    return Err(ForgeError::ValidationError {
                        field: "network.options.key".to_string(),
                        rule: "required".to_string(),
                        value: "".to_string(),
                        suggestions: vec!["Network option key cannot be empty".to_string()],
                    });
                }
                if value.is_empty() {
                    return Err(ForgeError::ValidationError {
                        field: format!("network.options.{}", key),
                        rule: "required".to_string(),
                        value: "".to_string(),
                        suggestions: vec!["Network option value cannot be empty".to_string()],
                    });
                }
            }
        }
    }

    Ok(())
}

/// Validate a port mapping
fn validate_port_mapping(port: &PortMapping, index: usize) -> Result<()> {
    if port.host_port == 0 {
        return Err(ForgeError::ValidationError {
            field: format!("network.ports[{}].host_port", index),
            rule: "required".to_string(),
            value: "0".to_string(),
            suggestions: vec!["Host port cannot be 0".to_string()],
        });
    }

    if port.container_port == 0 {
        return Err(ForgeError::ValidationError {
            field: format!("network.ports[{}].container_port", index),
            rule: "required".to_string(),
            value: "0".to_string(),
            suggestions: vec!["Container port cannot be 0".to_string()],
        });
    }

    // Validate host IP if specified
    if let Some(host_ip) = &port.host_ip {
        if !host_ip.is_empty() && !is_valid_ip_address(host_ip) {
            return Err(ForgeError::ValidationError {
                field: format!("network.ports[{}].host_ip", index),
                rule: "invalid_format".to_string(),
                value: host_ip.clone(),
                suggestions: vec!["Invalid host IP address format".to_string()],
            });
        }
    }

    Ok(())
}

/// Check if a string is a valid IP address
fn is_valid_ip_address(ip: &str) -> bool {
    // Simple IPv4 validation
    let ipv4_regex = regex::Regex::new(
        r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    ).unwrap();

    // Simple IPv6 validation
    let ipv6_regex = regex::Regex::new(
        r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    ).unwrap();

    ipv4_regex.is_match(ip) || ipv6_regex.is_match(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{MountType, NetworkMode, PortProtocol};
    use crate::dna::ResourceLimits;

    #[test]
    fn test_validate_image() {
        // Valid image
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
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
        assert!(validate_image(&config).is_ok());

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
        assert!(validate_image(&config).is_err());

        // Image without tag
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image".to_string(),
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
        assert!(validate_image(&config).is_err());
    }

    #[test]
    fn test_validate_resource_limits() {
        // Valid resource limits
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: Some(ResourceLimits {
                cpu_millicores: 1000,
                memory_bytes: 1024 * 1024 * 100,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            }),
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
        assert!(validate_resource_limits(&config).is_ok());

        // Invalid CPU cores
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: Some(ResourceLimits {
                cpu_millicores: 0,
                memory_bytes: 1024 * 1024 * 100,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            }),
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
        assert!(validate_resource_limits(&config).is_err());

        // Invalid memory bytes
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: Some(ResourceLimits {
                cpu_millicores: 1000,
                memory_bytes: 0,
                disk_bytes: 1024 * 1024 * 1000,
                network_bps: 1024 * 1024,
            }),
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
        assert!(validate_resource_limits(&config).is_err());
    }

    #[test]
    fn test_validate_minimum_entropy() {
        // Valid minimum entropy
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: None,
            trusted_issuers: None,
            minimum_entropy: Some(0.5),
            exec_mode: None,
            mounts: None,
            volumes: None,
            network: None,
            labels: None,
            annotations: None,
            custom: None,
        };
        assert!(validate_minimum_entropy(&config).is_ok());

        // Invalid minimum entropy (negative)
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: None,
            trusted_issuers: None,
            minimum_entropy: Some(-0.5),
            exec_mode: None,
            mounts: None,
            volumes: None,
            network: None,
            labels: None,
            annotations: None,
            custom: None,
        };
        assert!(validate_minimum_entropy(&config).is_err());

        // Invalid minimum entropy (greater than 1.0)
        let config = ContainerConfig {
            name: Some("test-container".to_string()),
            image: "test-image:latest".to_string(),
            command: None,
            args: None,
            env: None,
            working_dir: None,
            resource_limits: None,
            trusted_issuers: None,
            minimum_entropy: Some(1.5),
            exec_mode: None,
            mounts: None,
            volumes: None,
            network: None,
            labels: None,
            annotations: None,
            custom: None,
        };
        assert!(validate_minimum_entropy(&config).is_err());
    }

    #[test]
    fn test_validate_mount() {
        // Valid mount
        let mount = Mount {
            source: "/host/path".to_string(),
            destination: "/container/path".to_string(),
            mount_type: MountType::Bind,
            options: None,
            read_only: true,
        };
        assert!(validate_mount(&mount, 0).is_ok());

        // Invalid mount (empty source)
        let mount = Mount {
            source: "".to_string(),
            destination: "/container/path".to_string(),
            mount_type: MountType::Bind,
            options: None,
            read_only: true,
        };
        assert!(validate_mount(&mount, 0).is_err());

        // Invalid mount (empty destination)
        let mount = Mount {
            source: "/host/path".to_string(),
            destination: "".to_string(),
            mount_type: MountType::Bind,
            options: None,
            read_only: true,
        };
        assert!(validate_mount(&mount, 0).is_err());

        // Invalid mount (empty option)
        let mount = Mount {
            source: "/host/path".to_string(),
            destination: "/container/path".to_string(),
            mount_type: MountType::Bind,
            options: Some(vec!["option1".to_string(), "".to_string()]),
            read_only: true,
        };
        assert!(validate_mount(&mount, 0).is_err());
    }

    #[test]
    fn test_validate_volume() {
        // Valid volume
        let volume = Volume {
            name: "test-volume".to_string(),
            path: "/data".to_string(),
            driver: None,
            options: None,
        };
        assert!(validate_volume(&volume, 0).is_ok());

        // Invalid volume (empty name)
        let volume = Volume {
            name: "".to_string(),
            path: "/data".to_string(),
            driver: None,
            options: None,
        };
        assert!(validate_volume(&volume, 0).is_err());

        // Invalid volume (empty path)
        let volume = Volume {
            name: "test-volume".to_string(),
            path: "".to_string(),
            driver: None,
            options: None,
        };
        assert!(validate_volume(&volume, 0).is_err());

        // Invalid volume (empty option key)
        let mut options = std::collections::HashMap::new();
        options.insert("".to_string(), "value".to_string());
        let volume = Volume {
            name: "test-volume".to_string(),
            path: "/data".to_string(),
            driver: None,
            options: Some(options),
        };
        assert!(validate_volume(&volume, 0).is_err());

        // Invalid volume (empty option value)
        let mut options = std::collections::HashMap::new();
        options.insert("key".to_string(), "".to_string());
        let volume = Volume {
            name: "test-volume".to_string(),
            path: "/data".to_string(),
            driver: None,
            options: Some(options),
        };
        assert!(validate_volume(&volume, 0).is_err());
    }

    #[test]
    fn test_validate_port_mapping() {
        // Valid port mapping
        let port = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: PortProtocol::TCP,
            host_ip: None,
        };
        assert!(validate_port_mapping(&port, 0).is_ok());

        // Invalid port mapping (host port is 0)
        let port = PortMapping {
            host_port: 0,
            container_port: 80,
            protocol: PortProtocol::TCP,
            host_ip: None,
        };
        assert!(validate_port_mapping(&port, 0).is_err());

        // Invalid port mapping (container port is 0)
        let port = PortMapping {
            host_port: 8080,
            container_port: 0,
            protocol: PortProtocol::TCP,
            host_ip: None,
        };
        assert!(validate_port_mapping(&port, 0).is_err());

        // Invalid port mapping (invalid host IP)
        let port = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: PortProtocol::TCP,
            host_ip: Some("invalid-ip".to_string()),
        };
        assert!(validate_port_mapping(&port, 0).is_err());
    }

    #[test]
    fn test_is_valid_ip_address() {
        // Valid IPv4 addresses
        assert!(is_valid_ip_address("192.168.1.1"));
        assert!(is_valid_ip_address("10.0.0.1"));
        assert!(is_valid_ip_address("172.16.0.1"));
        assert!(is_valid_ip_address("255.255.255.255"));

        // Invalid IPv4 addresses
        assert!(!is_valid_ip_address("256.0.0.1"));
        assert!(!is_valid_ip_address("192.168.1"));
        assert!(!is_valid_ip_address("192.168.1.1.1"));
        assert!(!is_valid_ip_address("192.168.1.a"));

        // Valid IPv6 addresses
        assert!(is_valid_ip_address(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ));
        assert!(is_valid_ip_address("2001:db8:85a3::8a2e:370:7334"));
        assert!(is_valid_ip_address("::1"));
        assert!(is_valid_ip_address("fe80::"));

        // Invalid IPv6 addresses
        assert!(!is_valid_ip_address(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334:7334"
        ));
        assert!(!is_valid_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370"));
        assert!(!is_valid_ip_address(
            "2001:0db8:85a3:0000:0000:8a2e:0370:zzzz"
        ));
    }
}
