# ForgeOne Plugin Manager

A hyper-optimized, production-ready containerization platform with Zero Trust Architecture (ZTA) enforcement for the ForgeOne platform. An advanced alternative to Docker/Podman for 2026 and beyond.

## Enterprise-Grade Features

- **Military-grade ZTA**: Every plugin operation is verified against cryptographic identity and policy with immutable audit trails.
- **Production-scale modularity**: Designed for enterprise environments with 10,000+ developers and millions of containers.
- **File-level clarity**: Each component has a single, well-defined responsibility with comprehensive documentation.
- **Hyper-optimization**: Performance metrics collected at every level with real-time telemetry and observability.
- **Secure ABI bridge**: Sandboxed communication between host and plugins with cryptographic attestation.
- **Plugin attestation**: Cryptographic verification of plugin integrity with signed certificates.
- **Secure syscall bus**: Policy-enforced system calls with comprehensive audit logging and anomaly detection.
- **Linux namespaces support**: Secure sandboxing with advanced containerization capabilities.
- **WASM plugin support**: WASI-compliant WebAssembly plugins for maximum portability and security.

## Architecture

The Plugin Manager consists of the following core components, tightly integrated with the ForgeOne Microkernel and Common modules:

- **ABI**: Application Binary Interface for host-plugin communication with cryptographic verification
- **Attestation**: Plugin signature and hash verification with certificate chain validation
- **Loader**: Plugin package loading and extraction with integrity checks
- **Runtime**: WebAssembly execution environment with WASI compliance
- **Sandbox**: Resource limits and capability restrictions with Linux namespaces support
- **Syscall**: Secure system call interface integrated with the Microkernel syscall bridge
- **Lifecycle**: Plugin initialization, starting, stopping, and unloading with telemetry
- **Metrics**: Performance monitoring and telemetry with Prometheus integration
- **Plugin**: Plugin instance and manifest management with dependency resolution
- **Registry**: Plugin registration and discovery with marketplace integration
- **Extension**: Plugin extension system with runtime self-registration

### Integration with Microkernel

The Plugin Manager leverages the ForgeOne Microkernel for secure syscall execution and trust evaluation:

```rust
// Example of microkernel integration
use microkernel::syscall_bridge::execute_syscall;
use microkernel::trust::evaluate_syscall;

// Execute a syscall through the microkernel
let result = execute_syscall("file_read", &args, &plugin_identity);

// Evaluate a syscall against ZTA policies
let action = evaluate_syscall("file_read", &args, plugin_identity)?;
```

### Common Module Integration

The Plugin Manager uses the Common module for telemetry, identity, and error handling:

```rust
// Example of common module integration
use common::telemetry::record_event;
use common::identity::IdentityContext;

// Record a telemetry event
let event = TelemetryEvent::new("plugin.lifecycle", MetricType::Counter, 1.0, labels);
common::telemetry::record_event(event);
```

## Plugin Extension Strategy

The ForgeOne Plugin Manager supports a flexible extension strategy with the following features:

- **ForgePlugin API Specification**: A standardized API for plugin development and integration
- **Optional `plugin.toml` Manifest**: Declarative plugin configuration with dependency management
- **Runtime Self-Registration**: Plugins can register themselves at runtime
- **Secure Sandboxing**: Linux namespaces for isolation and resource control

```toml
# Example plugin.toml manifest
[plugin]
name = "example-plugin"
version = "1.0.0"
description = "Example plugin for ForgeOne"
author = "ForgeOne Team"
license = "MIT"

[dependencies]
common = "^1.0.0"
microkernel = "^1.0.0"

[permissions]
filesystem = ["read", "write"]
network = ["connect"]

[entry_points]
init = "plugin_init"
start = "plugin_start"
stop = "plugin_stop"
```

## Hyper Optimized Plugin Extensions

Plugins can be registered and loaded in multiple ways:

- **Dynamic Registration**: `PluginManager::register(plugin)`
- **Static Loading**: Pre-compiled plugins loaded at startup
- **Dynamic Loading**: Plugins loaded at runtime from `.forgepkg` files
- **Lazy Static Initialization**: Thread-safe plugin initialization with minimal overhead
- **Thread Pool Execution**: Parallel plugin execution with resource control

## Usage

### Loading a Plugin

```rust
use plugin_manager::registry::PluginRegistry;
use common::identity::IdentityContext;
use microkernel::trust::TrustContext;

// Create a plugin registry with microkernel integration
let mut registry = PluginRegistry::new_with_config("config.yaml");

// Create an identity context for verification
let identity = IdentityContext::new("plugin-manager");

// Create a trust context for ZTA enforcement
let trust = TrustContext::new(&identity);

// Load a plugin from a file with trust verification
let plugin_id = registry.load_plugin("/path/to/plugin.forgepkg", &identity, &trust)?;

// Initialize the plugin with telemetry
let timer = metrics::telemetry::StartupTimer::new(&plugin_id.to_string(), "example-plugin", "1.0.0");
registry.initialize_plugin(plugin_id)?;
timer.stop();

// Start the plugin
registry.start_plugin(plugin_id)?;
```

### Creating a Plugin

Plugins are WebAssembly modules that export the following functions:

- `init()`: Called when the plugin is initialized
- `start()`: Called when the plugin is started
- `stop()`: Called when the plugin is stopped
- `pause()`: Called when the plugin is paused
- `resume()`: Called when the plugin is resumed
- `unload()`: Called when the plugin is unloaded

See the [sample plugin](examples/sample-plugin) for an example.

## Plugin Package Format

Plugins are packaged as `.forgepkg` files, which are tar.gz archives containing:

- `manifest.json`: Plugin metadata and permissions
- `plugin.wasm`: WebAssembly module
- `plugin.toml`: Optional extended manifest
- Other supporting files

## Future Scope

The ForgeOne Plugin Manager roadmap includes:

- **WASI-compliant WASM Plugin Support**: Full support for the WebAssembly System Interface
- **Plugin Dependency Tree Validator**: Automatic resolution and validation of plugin dependencies
- **Plugin Execution Audit**: Comprehensive audit trail of all plugin operations
- **Signed Plugin Certificates**: Enhanced security with certificate chain validation
- **Plugin Marketplace/Discovery Interface**: Centralized repository for plugin discovery and distribution

## Testing Support

The Plugin Manager includes comprehensive testing support:

- **Unit Tests**: `#[cfg(test)]` in `plugin.rs` for isolated testing
- **Mock Plugins**: Test plugins for integration testing
- **Plugin CI**: Continuous integration for plugin validation

```rust
// Example test code
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_mock_plugin;

    #[test]
    fn test_plugin_lifecycle() {
        let plugin = create_mock_plugin("test-plugin", "1.0.0");
        assert_eq!(plugin.state(), PluginState::Created);
        
        // Test initialization
        plugin.update_state(PluginState::Initializing);
        plugin.update_state(PluginState::Ready);
        assert_eq!(plugin.state(), PluginState::Ready);
        
        // Test start/stop
        plugin.update_state(PluginState::Running);
        assert_eq!(plugin.state(), PluginState::Running);
        plugin.update_state(PluginState::Stopping);
        plugin.update_state(PluginState::Stopped);
        assert_eq!(plugin.state(), PluginState::Stopped);
    }
}
```

## Config File Example

```yaml
# plugin-manager.yaml
plugin_manager:
  plugin_directory: "/var/lib/forgeone/plugins"
  temp_directory: "/tmp/forgeone/plugins"
  max_plugins: 1000
  default_timeout: 30s
  
  sandbox:
    memory_limit: 512MB
    cpu_limit: 2
    file_descriptor_limit: 1024
    network_access: restricted
    
  telemetry:
    metrics_enabled: true
    tracing_enabled: true
    log_level: info
    prometheus_endpoint: "/metrics"
    
  security:
    verify_signatures: true
    enforce_permissions: true
    audit_logging: true
    namespace_isolation: true
```

## Minimal Dependencies

The Plugin Manager is designed with minimal dependencies:

- **Core Dependencies**: serde, anyhow, tracing, dashmap, parking_lot
- **Optional Dependencies**: tokio, hyper (only when required)
- **Internal Dependencies**: common, microkernel

## Metrics & Observability

The Plugin Manager is integrated with the ForgeOne telemetry and audit modules:

- **Logs**: Plugin lifecycle events, security events, error events
- **Metrics**: Total plugins, active plugins, failed plugins, resource usage
- **Tracing**: Per-plugin execution spans with context propagation

```rust
// Example telemetry integration
use common::telemetry::{TelemetryEvent, MetricType};

// Record plugin startup event
let event = TelemetryEvent::new(
    "plugin.lifecycle.start",
    MetricType::Counter,
    1.0,
    vec![
        ("plugin_id".to_string(), plugin_id.to_string()),
        ("plugin_name".to_string(), plugin_name.to_string()),
        ("version".to_string(), version.to_string()),
    ],
);
common::telemetry::record_event(event);
```

## Security

The Plugin Manager enforces security at multiple levels:

1. **Package verification**: Plugins are verified against their manifest hash and signature
2. **Sandboxing**: Plugins run in a sandboxed environment with Linux namespaces
3. **Capability-based security**: Plugins must declare permissions in their manifest
4. **Syscall enforcement**: All system calls are verified against ZTA policy
5. **Audit logging**: All plugin operations are logged for compliance and regulatory review
6. **Cryptographic attestation**: Plugins are cryptographically attested before execution

## License

MIT