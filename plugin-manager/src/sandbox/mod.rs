//! Sandbox module for the ForgeOne Plugin Manager
//!
//! Provides secure sandboxing for plugin execution, including resource limits,
//! capability restrictions, and isolation.
//! Includes Linux namespaces support for advanced containerization.

use crate::runtime::execution::PluginContext;
use common::error::{ForgeError, Result};
use microkernel::trust::evaluate_syscall;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

// Re-export linux_namespaces module
#[cfg(target_os = "linux")]
pub mod linux_namespaces;

/// Resource limits for a sandboxed plugin
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Maximum memory usage in bytes
    pub memory_limit: usize,
    /// Maximum CPU time in milliseconds
    pub time_limit: u64,
    /// Maximum number of instructions
    pub instruction_limit: Option<u64>,
    /// Maximum number of threads
    pub thread_limit: Option<u32>,
    /// Maximum number of file descriptors
    pub fd_limit: Option<u32>,
    /// CPU usage limit in percentage (0-100)
    pub cpu_limit: Option<u32>,
    /// Disk I/O operations per second limit
    pub io_ops_limit: Option<u32>,
    /// Network bandwidth limit in bytes per second
    pub network_bandwidth_limit: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_limit: 128 * 1024 * 1024,        // 128 MB
            time_limit: 30000,                      // 30 seconds
            instruction_limit: Some(1_000_000_000), // 1 billion instructions
            thread_limit: Some(4),
            fd_limit: Some(64),
            cpu_limit: Some(100),
            io_ops_limit: Some(1000),
            network_bandwidth_limit: Some(1000000),
        }
    }
}

/// Capability permissions for a sandboxed plugin
#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    /// File system access permissions
    pub fs_access: FsAccess,
    /// Network access permissions
    pub network_access: NetworkAccess,
    /// Process creation permissions
    pub process_access: ProcessAccess,
    /// Environment variable access
    pub env_vars: HashMap<String, String>,
    /// Allowed syscalls
    pub allowed_syscalls: Option<Vec<String>>,
    /// Namespace isolation (Linux only)
    pub namespace_isolation: bool,
    /// Seccomp filtering (Linux only)
    pub seccomp_filtering: bool,
    /// Capability dropping (Linux only)
    pub capability_dropping: bool,
}

/// File system access permissions
#[derive(Debug, Clone, Default)]
pub struct FsAccess {
    /// Allowed read paths
    pub read_paths: Vec<String>,
    /// Allowed write paths
    pub write_paths: Vec<String>,
    /// Allowed execute paths
    pub exec_paths: Vec<String>,
}

/// Network access permissions
#[derive(Debug, Clone, Default)]
pub struct NetworkAccess {
    /// Allowed outbound hosts
    pub outbound_hosts: Vec<String>,
    /// Allowed inbound ports
    pub inbound_ports: Vec<u16>,
    /// Allowed outbound ports
    pub outbound_ports: Vec<u16>,
}

/// Process creation permissions
#[derive(Debug, Clone, Default)]
pub struct ProcessAccess {
    /// Allowed executables
    pub allowed_executables: Vec<String>,
    /// Maximum number of processes
    pub max_processes: Option<u32>,
}

/// Sandbox configuration for a plugin
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Resource limits
    pub resource_limits: ResourceLimits,
    /// Capability permissions
    pub capabilities: Capabilities,
    /// Namespace configuration (Linux only)
    #[cfg(target_os = "linux")]
    pub namespace_config: Option<linux_namespaces::NamespaceConfig>,
    /// Root directory for the sandbox
    pub root_directory: Option<PathBuf>,
    /// Temporary directory for the sandbox
    pub temp_directory: Option<PathBuf>,
    /// Plugin-specific configuration
    pub plugin_config: HashMap<String, String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            resource_limits: ResourceLimits::default(),
            capabilities: Capabilities::default(),
            root_directory: None,
            temp_directory: None,
            plugin_config: HashMap::new(),
        }
    }
}

/// Creates a sandboxed plugin context
///
/// # Arguments
///
/// * `context` - The plugin context to sandbox
/// * `config` - The sandbox configuration
/// * `plugin` - The plugin instance to sandbox
///
/// # Returns
///
/// * `Ok(PluginContext)` - The sandboxed plugin context
/// * `Err(ForgeError)` - If sandboxing fails
pub fn create_sandbox(
    context: PluginContext,
    config: SandboxConfig,
    plugin: &crate::plugin::PluginInstance,
) -> Result<PluginContext> {
    // Create a new context with the sandbox configuration
    let mut sandboxed_context = context;

    tracing::info!(
        plugin_id = %plugin.id,
        plugin_name = %plugin.name(),
        "Creating sandbox for plugin"
    );

    // Apply resource limits
    sandboxed_context.memory_limit = config.resource_limits.memory_limit;
    sandboxed_context.time_limit = config.resource_limits.time_limit;

    if let Some(instruction_limit) = config.resource_limits.instruction_limit {
        sandboxed_context.set_instruction_limit(instruction_limit);
    }

    if let Some(thread_limit) = config.resource_limits.thread_limit {
        sandboxed_context.set_thread_limit(thread_limit);
    }

    if let Some(fd_limit) = config.resource_limits.fd_limit {
        sandboxed_context.set_fd_limit(fd_limit);
    }

    // Apply environment variables
    sandboxed_context.env_vars = config.capabilities.env_vars;

    // Apply Linux namespaces if enabled
    #[cfg(target_os = "linux")]
    if config.capabilities.namespace_isolation {
        let namespace_config = match &config.namespace_config {
            Some(config) => config.clone(),
            None => linux_namespaces::namespace_config_from_sandbox(&config),
        };

        linux_namespaces::create_namespace(plugin, &namespace_config)?;
    }

    // Record telemetry
    let labels = vec![
        ("plugin_id".to_string(), plugin.id.to_string()),
        ("plugin_name".to_string(), plugin.name().to_string()),
        ("version".to_string(), plugin.version().to_string()),
    ];

    let event = common::telemetry::TelemetryEvent {
        name: "plugin.sandbox.create".to_string(), // or the appropriate event name
        time: chrono::Utc::now(),
        attributes: labels.into_iter().collect(),
    };

    common::telemetry::record_counter(
        "plugin.sandbox.create",
        "Sandbox created for plugin",
        1,
        event.attributes.clone(),
    )?;

    Ok(sandboxed_context)
}

/// Executes a function within the sandbox
///
/// # Arguments
///
/// * `context` - The sandboxed plugin context
/// * `plugin` - The plugin instance
/// * `func` - The function to execute
///
/// # Returns
///
/// * `Ok(T)` - The result of the function execution
/// * `Err(ForgeError)` - If execution fails
pub fn execute_in_sandbox<F, T>(
    context: &PluginContext,
    plugin: &crate::plugin::PluginInstance,
    func: F,
) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    tracing::debug!(
        plugin_id = %plugin.id,
        plugin_name = %plugin.name(),
        "Executing function in sandbox"
    );

    // Start monitoring resource usage
    let start_time = std::time::Instant::now();
    let start_memory = get_current_memory_usage();

    // Execute the function
    let result = func();

    // Check resource usage
    let elapsed = start_time.elapsed();
    let memory_used = get_current_memory_usage() - start_memory;

    // Record telemetry
    let labels = vec![
        ("plugin_id".to_string(), plugin.id.to_string()),
        ("plugin_name".to_string(), plugin.name().to_string()),
        (
            "execution_time_ms".to_string(),
            elapsed.as_millis().to_string(),
        ),
        ("memory_used_bytes".to_string(), memory_used.to_string()),
    ];

    let event = common::telemetry::TelemetryEvent {
        name: "plugin.sandbox.execute".to_string(),
        time: chrono::Utc::now(),
        attributes: labels.into_iter().collect(),
    };
    common::telemetry::record_counter(
        "plugin.sandbox.execute",
        "Function executed in sandbox",
        1,
        event.attributes.clone(),
    )?;

    result
}

/// Cleans up sandbox resources
///
/// # Arguments
///
/// * `context` - The sandboxed plugin context
/// * `plugin` - The plugin instance
///
/// # Returns
///
/// * `Ok(())` - If cleanup succeeds
/// * `Err(ForgeError)` - If cleanup fails
pub fn cleanup_sandbox(
    context: &PluginContext,
    plugin: &crate::plugin::PluginInstance,
) -> Result<()> {
    tracing::info!(
        plugin_id = %plugin.id,
        plugin_name = %plugin.name(),
        "Cleaning up sandbox resources"
    );

    // Clean up Linux namespaces if enabled
    #[cfg(target_os = "linux")]
    if context.namespace_isolation {
        linux_namespaces::cleanup_namespace(plugin)?;
    }

    // Release any temporary resources
    if let Some(temp_dir) = &context.temp_directory {
        if temp_dir.exists() {
            std::fs::remove_dir_all(temp_dir).map_err(|e| {
                ForgeError::IoError(format!("Failed to remove temporary directory: {}", e))
            })?;
        }
    }

    // Record telemetry
    let labels = vec![
        ("plugin_id".to_string(), plugin.id.to_string()),
        ("plugin_name".to_string(), plugin.name().to_string()),
    ];

    let event = common::telemetry::TelemetryEvent {
        name: "plugin.sandbox.cleanup".to_string(),
        time: chrono::Utc::now(),
        attributes: labels.into_iter().collect(),
    };
    common::telemetry::record_counter(
        "plugin.sandbox.cleanup",
        "Sandbox resources cleaned up",
        1,
        event.attributes.clone(),
    )?;

    Ok(())
}

// Helper function to get current memory usage
fn get_current_memory_usage() -> usize {
    #[cfg(target_os = "linux")]
    {
        use std::fs::File;
        use std::io::Read;

        let mut status = String::new();
        if let Ok(mut file) = File::open("/proc/self/status") {
            if file.read_to_string(&mut status).is_ok() {
                if let Some(line) = status.lines().find(|l| l.starts_with("VmRSS:")) {
                    if let Some(kb_str) = line.split_whitespace().nth(1) {
                        if let Ok(kb) = kb_str.parse::<usize>() {
                            return kb * 1024;
                        }
                    }
                }
            }
        }
    }

    // Fallback or non-Linux platforms
    0
}

/// Validates that a plugin's requested permissions are allowed by the system policy
///
/// # Arguments
///
/// * `requested_permissions` - The permissions requested by the plugin
/// * `system_policy` - The system policy that defines allowed permissions
///
/// # Returns
///
/// * `Ok(())` - If the requested permissions are allowed
/// * `Err(ForgeError)` - If any requested permission is not allowed
pub fn validate_permissions(
    requested_permissions: &[String],
    system_policy: &HashMap<String, bool>,
) -> Result<()> {
    for permission in requested_permissions {
        match system_policy.get(permission) {
            Some(true) => continue,
            Some(false) => {
                return Err(ForgeError::SecurityError(format!(
                    "Permission '{}' is explicitly denied by system policy",
                    permission
                )))
            }
            None => {
                return Err(ForgeError::SecurityError(format!(
                    "Permission '{}' is not recognized by system policy",
                    permission
                )))
            }
        }
    }

    Ok(())
}
