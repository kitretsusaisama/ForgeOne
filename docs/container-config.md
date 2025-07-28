# Container Configuration Module

## Overview

The Container Configuration Module provides a comprehensive system for managing container configurations in the ForgeOne Quantum-Grade HyperContainer Runtime. This module enables users to define, validate, load, and save container configurations in a structured and secure manner.

A visual representation of the configuration module structure is available in the `docs/runtime/diagrams/config_module.svg` file. This diagram illustrates the relationships between the core configuration components, including the `ContainerConfig` struct and its supporting modules for loading, validation, and saving configurations.

## Core Components

### ContainerConfig

The `ContainerConfig` struct is the central component of the configuration module, providing a structured way to define container settings:

```rust
pub struct ContainerConfig {
    pub name: Option<String>,
    pub image: String,
    pub command: Option<String>,
    pub args: Option<Vec<String>>,
    pub env: Option<HashMap<String, String>>,
    pub working_dir: Option<String>,
    pub resource_limits: Option<ResourceLimits>,
    pub trusted_issuers: Option<Vec<String>>,
    pub minimum_entropy: Option<f64>,
    pub exec_mode: Option<ExecMode>,
    pub mounts: Option<Vec<Mount>>,
    pub volumes: Option<Vec<Volume>>,
    pub network: Option<NetworkConfig>,
    pub labels: Option<HashMap<String, String>>,
    pub annotations: Option<HashMap<String, String>>,
    pub custom: Option<HashMap<String, String>>,
}
```

### Supporting Structures

- **Mount**: Defines how host paths or volumes are mounted into the container
- **Volume**: Defines named volumes that can be used by containers
- **NetworkConfig**: Defines network settings for the container
- **PortMapping**: Defines port mappings between host and container

## Configuration Management

### Loading Configurations

The module provides several methods for loading container configurations:

- **load_config_from_file**: Loads configuration from a JSON or YAML file
- **load_config_from_env**: Loads configuration from environment variables
- **merge_configs**: Merges two configurations, with the second taking precedence

### Saving Configurations

Configurations can be saved in various formats:

- **save_config_to_file**: Saves configuration to a JSON or YAML file
- **save_config_to_env**: Saves configuration to environment variables
- **save_config_to_registry**: Saves configuration to a container registry

### Validation

The `validate_config` function ensures that container configurations meet the required standards:

- Validates that the image is not empty
- Validates resource limits (CPU cores, memory, disk, network)
- Validates minimum entropy (between 0.0 and 1.0)
- Validates mount points (source and destination)
- Validates volumes (name and path)
- Validates network settings (IP addresses, ports)

## Integration with Other Modules

The Container Configuration Module integrates with several other modules in the runtime:

- **DNA Module**: Resource limits from the configuration are used to create the container DNA
- **Contract Module**: Trusted issuers, minimum entropy, and execution mode are used to create the container contract
- **Registry Module**: The configuration is used when creating and registering containers
- **Lifecycle Module**: The configuration influences the container lifecycle

## Security Considerations

### Validation

All configurations undergo strict validation to ensure they meet security requirements:

- Resource limits prevent resource exhaustion attacks
- Minimum entropy requirements ensure adequate randomness for security operations
- Trusted issuers limit which entities can sign and verify container contracts

### Zero Trust Architecture

The configuration module supports the Zero Trust Architecture principles:

- Explicit verification of container properties before execution
- Fine-grained control over container capabilities
- Secure configuration storage and transmission

### Resource Limits

Resource limits can be specified to prevent containers from consuming excessive resources:

```rust
pub struct ResourceLimits {
    pub cpu_cores: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub disk_bytes: Option<u64>,
    pub network_bps: Option<u64>,
}
```

### Secure Storage

Configurations can be stored securely:

- File-based configurations can use file system permissions
- Registry-based configurations can use the registry's security mechanisms
- Environment variables can be protected using system security mechanisms

## Best Practices

### Configuration Creation

- Use the builder pattern for creating complex configurations:

```rust
let config = ContainerConfig::builder()
    .image("nginx:latest")
    .name("web-server")
    .command("/bin/bash")
    .args(vec!["-c", "nginx -g 'daemon off;'"])
    .working_dir("/app")
    .build();
```

### Resource Limits

- Always specify resource limits to prevent resource exhaustion
- Set reasonable limits based on the container's expected workload
- Consider the host system's capabilities when setting limits

### Network Configuration

- Use the bridge network mode for most containers
- Explicitly specify port mappings rather than using automatic port assignment
- Consider using host network mode only for performance-critical applications

### Security Settings

- Specify trusted issuers to limit which entities can sign and verify container contracts
- Set a minimum entropy requirement appropriate for the container's security needs
- Use the most restrictive execution mode that meets the container's requirements

## Future Enhancements

### Schema Validation

Future versions may include JSON Schema validation for configuration files, providing more detailed validation and better error messages.

### Configuration Versioning

A versioning system for configurations would allow for backward compatibility and smooth upgrades.

### Encrypted Configurations

Support for encrypted configuration files would enhance security for sensitive configuration data.

### Remote Configuration

The ability to load configurations from remote sources (e.g., HTTP, S3) would provide more flexibility in deployment scenarios.

### Configuration Templates

Support for configuration templates would make it easier to create multiple similar configurations.

## Example Usage

### Creating and Saving a Configuration

```rust
// Create a container configuration
let mut config = ContainerConfig::new("nginx:latest");
config.name = Some("web-server".to_string());
config.command = Some("/bin/bash".to_string());
config.args = Some(vec!["-c".to_string(), "nginx -g 'daemon off;'".to_string()]);

// Add environment variables
let mut env = HashMap::new();
env.insert("NGINX_PORT".to_string(), "8080".to_string());
config.env = Some(env);

// Save configuration to file
save_config_to_file(&config, "config.json", "json").unwrap();
```

### Loading and Validating a Configuration

```rust
// Load configuration from file
let config = load_config_from_file("config.json").unwrap();

// Validate configuration
validate_config(&config).unwrap();

// Use configuration to create a container
let container_id = registry::create_container("nginx:latest", None, Some(&config)).unwrap();
```

### Merging Configurations

```rust
// Load base configuration
let base_config = load_config_from_file("base-config.json").unwrap();

// Load environment-specific configuration
let env_config = load_config_from_file("prod-config.json").unwrap();

// Merge configurations
let merged_config = merge_configs(&base_config, &env_config);

// Use merged configuration
validate_config(&merged_config).unwrap();
```

## Conclusion

The Container Configuration Module provides a flexible, secure, and comprehensive system for managing container configurations in the ForgeOne Quantum-Grade HyperContainer Runtime. By following the best practices outlined in this document, users can create secure and efficient container configurations that meet their specific needs.