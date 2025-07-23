//! # Container Configuration Tests
//!
//! This module contains integration tests for the container configuration module.

#[cfg(test)]
mod tests {
    use crate::config::*;
    use crate::contract::zta::ExecMode;
    use crate::dna::ResourceLimits;
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_container_config_creation() {
        // Create a basic container configuration
        let config = ContainerConfig::new("nginx:latest");
        assert_eq!(config.image, "nginx:latest");
        assert!(config.name.is_none());
        assert!(config.command.is_none());
        assert!(config.args.is_none());

        // Create a more complex container configuration
        let mut config = ContainerConfig::builder()
            .image("nginx:latest")
            .name("web-server")
            .command("/bin/bash")
            .args(vec!["-c", "nginx -g 'daemon off;'"])
            .working_dir("/app")
            .build();

        // Add environment variables
        let mut env = HashMap::new();
        env.insert("NGINX_PORT".to_string(), "8080".to_string());
        env.insert("DEBUG".to_string(), "true".to_string());
        config.env = Some(env);

        // Add resource limits
        let resource_limits = ResourceLimits {
            cpu_cores: Some(2.0),
            memory_bytes: Some(1024 * 1024 * 1024), // 1GB
            disk_bytes: Some(10 * 1024 * 1024 * 1024), // 10GB
            network_bps: Some(100 * 1024 * 1024), // 100Mbps
        };
        config.resource_limits = Some(resource_limits);

        // Add security settings
        config.trusted_issuers = Some(vec!["issuer1".to_string(), "issuer2".to_string()]);
        config.minimum_entropy = Some(0.8);
        config.exec_mode = Some(ExecMode::Wasm);

        // Add mounts
        let mounts = vec![
            Mount {
                source: "/host/path".to_string(),
                destination: "/container/path".to_string(),
                mount_type: MountType::Bind,
                read_only: true,
                options: None,
            },
            Mount {
                source: "config-volume".to_string(),
                destination: "/etc/nginx/conf.d".to_string(),
                mount_type: MountType::Volume,
                read_only: false,
                options: None,
            },
        ];
        config.mounts = Some(mounts);

        // Add volumes
        let volumes = vec![
            Volume {
                name: "data-volume".to_string(),
                path: "/data".to_string(),
                size_bytes: Some(5 * 1024 * 1024 * 1024), // 5GB
                options: None,
            },
        ];
        config.volumes = Some(volumes);

        // Add network configuration
        let port_mappings = vec![
            PortMapping {
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::TCP,
            },
            PortMapping {
                host_port: 8443,
                container_port: 443,
                protocol: PortProtocol::TCP,
            },
        ];

        let network_config = NetworkConfig {
            mode: Some(NetworkMode::Bridge),
            ip_address: Some("172.17.0.2".to_string()),
            gateway: Some("172.17.0.1".to_string()),
            dns_servers: Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]),
            ports: Some(port_mappings),
            options: None,
        };
        config.network = Some(network_config);

        // Add labels and annotations
        let mut labels = HashMap::new();
        labels.insert("app".to_string(), "web".to_string());
        labels.insert("environment".to_string(), "production".to_string());
        config.labels = Some(labels);

        let mut annotations = HashMap::new();
        annotations.insert("description".to_string(), "Web server".to_string());
        annotations.insert("version".to_string(), "1.0.0".to_string());
        config.annotations = Some(annotations);

        // Add custom options
        let mut custom = HashMap::new();
        custom.insert("restart_policy".to_string(), "always".to_string());
        custom.insert("log_driver".to_string(), "json-file".to_string());
        config.custom = Some(custom);

        // Verify configuration
        assert_eq!(config.image, "nginx:latest");
        assert_eq!(config.name, Some("web-server".to_string()));
        assert_eq!(config.command, Some("/bin/bash".to_string()));
        assert_eq!(
            config.args,
            Some(vec!["-c".to_string(), "nginx -g 'daemon off;'".to_string()])
        );
        assert_eq!(config.working_dir, Some("/app".to_string()));
        assert_eq!(config.env.as_ref().unwrap().get("NGINX_PORT"), Some(&"8080".to_string()));
        assert_eq!(config.resource_limits.as_ref().unwrap().cpu_cores, Some(2.0));
        assert_eq!(config.minimum_entropy, Some(0.8));
        assert_eq!(config.exec_mode, Some(ExecMode::Wasm));
        assert_eq!(config.mounts.as_ref().unwrap().len(), 2);
        assert_eq!(config.volumes.as_ref().unwrap().len(), 1);
        assert_eq!(config.network.as_ref().unwrap().ports.as_ref().unwrap().len(), 2);
        assert_eq!(config.labels.as_ref().unwrap().get("app"), Some(&"web".to_string()));
        assert_eq!(config.custom.as_ref().unwrap().get("restart_policy"), Some(&"always".to_string()));
    }

    #[test]
    fn test_config_serialization() {
        // Create a temporary directory for testing
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("config.json");

        // Create a container configuration
        let mut config = ContainerConfig::new("nginx:latest");
        config.name = Some("web-server".to_string());
        config.command = Some("/bin/bash".to_string());
        config.args = Some(vec!["-c".to_string(), "nginx -g 'daemon off;'".to_string()]);

        // Save configuration to file
        save_config_to_file(&config, config_path.to_str().unwrap(), "json").unwrap();

        // Load configuration from file
        let loaded_config = load_config_from_file(config_path.to_str().unwrap()).unwrap();

        // Verify loaded configuration
        assert_eq!(loaded_config.image, "nginx:latest");
        assert_eq!(loaded_config.name, Some("web-server".to_string()));
        assert_eq!(loaded_config.command, Some("/bin/bash".to_string()));
        assert_eq!(
            loaded_config.args,
            Some(vec!["-c".to_string(), "nginx -g 'daemon off;'".to_string()])
        );

        // Test YAML serialization
        let yaml_path = temp_dir.path().join("config.yaml");
        save_config_to_file(&config, yaml_path.to_str().unwrap(), "yaml").unwrap();

        // Load YAML configuration
        let loaded_yaml_config = load_config_from_file(yaml_path.to_str().unwrap()).unwrap();

        // Verify loaded YAML configuration
        assert_eq!(loaded_yaml_config.image, "nginx:latest");
        assert_eq!(loaded_yaml_config.name, Some("web-server".to_string()));
    }

    #[test]
    fn test_config_validation() {
        // Create an invalid configuration (empty image)
        let config = ContainerConfig {
            name: Some("test".to_string()),
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

        // Validate configuration
        let result = validate_config(&config);
        assert!(result.is_err());

        // Create a configuration with invalid resource limits
        let mut config = ContainerConfig::new("nginx:latest");
        config.resource_limits = Some(ResourceLimits {
            cpu_cores: Some(-1.0), // Invalid CPU cores
            memory_bytes: None,
            disk_bytes: None,
            network_bps: None,
        });

        // Validate configuration
        let result = validate_config(&config);
        assert!(result.is_err());

        // Create a configuration with invalid minimum entropy
        let mut config = ContainerConfig::new("nginx:latest");
        config.minimum_entropy = Some(2.0); // Invalid entropy (> 1.0)

        // Validate configuration
        let result = validate_config(&config);
        assert!(result.is_err());

        // Create a valid configuration
        let config = ContainerConfig::new("nginx:latest");

        // Validate configuration
        let result = validate_config(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_env_loading() {
        // Set environment variables
        std::env::set_var("CONTAINER_IMAGE", "redis:latest");
        std::env::set_var("CONTAINER_NAME", "cache-server");
        std::env::set_var("CONTAINER_COMMAND", "redis-server");
        std::env::set_var("CONTAINER_ARGS", "--port 6379 --appendonly yes");
        std::env::set_var("CONTAINER_ENV_REDIS_PASSWORD", "secret");
        std::env::set_var("CONTAINER_WORKING_DIR", "/data");

        // Load configuration from environment
        let config = load_config_from_env().unwrap();

        // Verify configuration
        assert_eq!(config.image, "redis:latest");
        assert_eq!(config.name, Some("cache-server".to_string()));
        assert_eq!(config.command, Some("redis-server".to_string()));
        assert_eq!(
            config.args,
            Some(vec!["--port".to_string(), "6379".to_string(), "--appendonly".to_string(), "yes".to_string()])
        );
        assert_eq!(config.env.as_ref().unwrap().get("REDIS_PASSWORD"), Some(&"secret".to_string()));
        assert_eq!(config.working_dir, Some("/data".to_string()));

        // Clean up environment variables
        std::env::remove_var("CONTAINER_IMAGE");
        std::env::remove_var("CONTAINER_NAME");
        std::env::remove_var("CONTAINER_COMMAND");
        std::env::remove_var("CONTAINER_ARGS");
        std::env::remove_var("CONTAINER_ENV_REDIS_PASSWORD");
        std::env::remove_var("CONTAINER_WORKING_DIR");
    }

    #[test]
    fn test_config_merging() {
        // Create base configuration
        let mut base_config = ContainerConfig::new("nginx:latest");
        base_config.name = Some("web-server".to_string());
        base_config.command = Some("/bin/bash".to_string());

        // Create override configuration
        let mut override_config = ContainerConfig::new("nginx:1.19");
        override_config.args = Some(vec!["-c".to_string(), "nginx -g 'daemon off;'".to_string()]);

        let mut env = HashMap::new();
        env.insert("DEBUG".to_string(), "true".to_string());
        override_config.env = Some(env);

        // Merge configurations
        let merged_config = merge_configs(&base_config, &override_config);

        // Verify merged configuration
        assert_eq!(merged_config.image, "nginx:1.19"); // Overridden
        assert_eq!(merged_config.name, Some("web-server".to_string())); // From base
        assert_eq!(merged_config.command, Some("/bin/bash".to_string())); // From base
        assert_eq!(
            merged_config.args,
            Some(vec!["-c".to_string(), "nginx -g 'daemon off;'".to_string()])
        ); // From override
        assert_eq!(merged_config.env.as_ref().unwrap().get("DEBUG"), Some(&"true".to_string())); // From override
    }

    #[test]
    fn test_network_config() {
        // Create network configuration
        let port_mappings = vec![
            PortMapping {
                host_port: 8080,
                container_port: 80,
                protocol: PortProtocol::TCP,
            },
            PortMapping {
                host_port: 8443,
                container_port: 443,
                protocol: PortProtocol::TCP,
            },
        ];

        let network_config = NetworkConfig {
            mode: Some(NetworkMode::Bridge),
            ip_address: Some("172.17.0.2".to_string()),
            gateway: Some("172.17.0.1".to_string()),
            dns_servers: Some(vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()]),
            ports: Some(port_mappings),
            options: None,
        };

        // Verify network configuration
        assert_eq!(network_config.mode, Some(NetworkMode::Bridge));
        assert_eq!(network_config.ip_address, Some("172.17.0.2".to_string()));
        assert_eq!(network_config.gateway, Some("172.17.0.1".to_string()));
        assert_eq!(network_config.dns_servers.as_ref().unwrap().len(), 2);
        assert_eq!(network_config.ports.as_ref().unwrap().len(), 2);

        // Verify port mappings
        let ports = network_config.ports.unwrap();
        assert_eq!(ports[0].host_port, 8080);
        assert_eq!(ports[0].container_port, 80);
        assert_eq!(ports[0].protocol, PortProtocol::TCP);
        assert_eq!(ports[1].host_port, 8443);
        assert_eq!(ports[1].container_port, 443);
        assert_eq!(ports[1].protocol, PortProtocol::TCP);

        // Test network mode display
        assert_eq!(format!("{}", NetworkMode::Bridge), "bridge");
        assert_eq!(format!("{}", NetworkMode::Host), "host");
        assert_eq!(format!("{}", NetworkMode::None), "none");

        // Test port protocol display
        assert_eq!(format!("{}", PortProtocol::TCP), "tcp");
        assert_eq!(format!("{}", PortProtocol::UDP), "udp");
        assert_eq!(format!("{}", PortProtocol::SCTP), "sctp");
    }

    #[test]
    fn test_mount_and_volume_config() {
        // Create mount configuration
        let mount = Mount {
            source: "/host/path".to_string(),
            destination: "/container/path".to_string(),
            mount_type: MountType::Bind,
            read_only: true,
            options: None,
        };

        // Verify mount configuration
        assert_eq!(mount.source, "/host/path");
        assert_eq!(mount.destination, "/container/path");
        assert_eq!(mount.mount_type, MountType::Bind);
        assert!(mount.read_only);

        // Create volume configuration
        let volume = Volume {
            name: "data-volume".to_string(),
            path: "/data".to_string(),
            size_bytes: Some(5 * 1024 * 1024 * 1024), // 5GB
            options: None,
        };

        // Verify volume configuration
        assert_eq!(volume.name, "data-volume");
        assert_eq!(volume.path, "/data");
        assert_eq!(volume.size_bytes, Some(5 * 1024 * 1024 * 1024));

        // Test mount type display
        assert_eq!(format!("{}", MountType::Bind), "bind");
        assert_eq!(format!("{}", MountType::Volume), "volume");
        assert_eq!(format!("{}", MountType::Tmpfs), "tmpfs");
    }
}