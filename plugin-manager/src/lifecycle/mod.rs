//! Lifecycle module for the ForgeOne Plugin Manager
//!
//! Provides functionality for managing the lifecycle of plugins, including
//! initialization, starting, stopping, and unloading.

use crate::plugin::{PluginInstance, PluginState};
use crate::runtime::execution::{EngineType, PluginContext, PluginRuntime, Val};
use common::error::{ForgeError, Result};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::Mutex; // Ensure this is imported
use tracing::{error, info, warn};
/// Initializes a plugin
///
/// # Arguments
///
/// * `plugin` - The plugin to initialize
///
/// # Returns
///
/// * `Ok(())` - If initialization succeeds
/// * `Err(ForgeError)` - If initialization fails
pub fn initialize_plugin(plugin: &mut PluginInstance) -> Result<()> {
    info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Initializing plugin");

    // Check if the plugin is in the correct state
    if plugin.state != PluginState::Created {
        return Err(ForgeError::ValidationError {
            field: "state".to_string(),
            rule: "created".to_string(),
            value: format!(
                "Plugin '{}' is not in the Created state",
                plugin.manifest.name
            ),
            suggestions: vec![],
        });
    }

    // Update the plugin state
    plugin.update_state(PluginState::Initializing);

    // Create a runtime for the plugin
    let context = PluginContext {
        plugin_id: plugin.id,
        plugin_name: plugin.manifest.name.clone(),
        memory_limit: 128 * 1024 * 1024, // 128MB default
        time_limit: 30_000,              // 30 seconds default
        identity: plugin.identity.clone(),
        env_vars: HashMap::new(),
        state: HashMap::new(),
        instruction_limit: None,
        thread_limit: None,
        fd_limit: None,
        cpu_limit: None,
        io_ops_limit: None,
        network_bandwidth_limit: None,
        filesystem_access: false,
        network_access: false,
        process_access: false,
        allowed_syscalls: None,
        #[cfg(target_os = "linux")]
        namespace_isolation: false,
        #[cfg(target_os = "linux")]
        seccomp_filtering: false,
        #[cfg(target_os = "linux")]
        capability_dropping: false,
        temp_directory: None,
    };
    let engine_type = EngineType::Wasmtime;
    let mut runtime = PluginRuntime::new(engine_type, context);

    runtime.load_module(&plugin.source_path)?;
    plugin.runtime = Arc::new(Mutex::new(runtime));
    // Call the plugin's init function
    match call_plugin_function(plugin, "init", &[]) {
        Ok(_) => {
            // Update the plugin state
            plugin.update_state(PluginState::Ready);
            info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Plugin initialized");
            Ok(())
        }
        Err(e) => {
            // Update the plugin state
            plugin.update_state(PluginState::Failed);
            error!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, error = %e, "Failed to initialize plugin");
            Err(e)
        }
    }
}

/// Starts a plugin
///
/// # Arguments
///
/// * `plugin` - The plugin to start
///
/// # Returns
///
/// * `Ok(())` - If starting succeeds
/// * `Err(ForgeError)` - If starting fails
pub fn start_plugin(plugin: &mut PluginInstance) -> Result<()> {
    info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Starting plugin");

    // Check if the plugin is in the correct state
    if plugin.state != PluginState::Ready && plugin.state != PluginState::Paused {
        return Err(ForgeError::ValidationError {
            field: "state".to_string(),
            rule: "ready_or_paused".to_string(),
            value: format!(
                "Plugin '{}' is not in the Ready or Paused state",
                plugin.manifest.name
            ),
            suggestions: vec![],
        });
    }

    // Call the plugin's start function
    match call_plugin_function(plugin, "start", &[]) {
        Ok(_) => {
            // Update the plugin state
            plugin.update_state(PluginState::Running);
            info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Plugin started");
            Ok(())
        }
        Err(e) => {
            // Update the plugin state
            plugin.update_state(PluginState::Failed);
            error!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, error = %e, "Failed to start plugin");
            Err(e)
        }
    }
}

/// Stops a plugin
///
/// # Arguments
///
/// * `plugin` - The plugin to stop
///
/// # Returns
///
/// * `Ok(())` - If stopping succeeds
/// * `Err(ForgeError)` - If stopping fails
pub fn stop_plugin(plugin: &mut PluginInstance) -> Result<()> {
    info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Stopping plugin");

    // Check if the plugin is in the correct state
    if plugin.state != PluginState::Running {
        return Err(ForgeError::ValidationError {
            field: "state".to_string(),
            rule: "running".to_string(),
            value: format!(
                "Plugin '{}' is not in the Running state",
                plugin.manifest.name
            ),
            suggestions: vec![],
        });
    }

    // Update the plugin state
    plugin.update_state(PluginState::Stopping);

    // Call the plugin's stop function
    match call_plugin_function(plugin, "stop", &[]) {
        Ok(_) => {
            // Update the plugin state
            plugin.update_state(PluginState::Stopped);
            info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Plugin stopped");
            Ok(())
        }
        Err(e) => {
            // Update the plugin state
            plugin.update_state(PluginState::Failed);
            error!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, error = %e, "Failed to stop plugin");
            Err(e)
        }
    }
}

/// Unloads a plugin
///
/// # Arguments
///
/// * `plugin` - The plugin to unload
///
/// # Returns
///
/// * `Ok(())` - If unloading succeeds
/// * `Err(ForgeError)` - If unloading fails
pub fn unload_plugin(plugin: &mut PluginInstance) -> Result<()> {
    info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Unloading plugin");

    // Check if the plugin is in the correct state
    if plugin.state == PluginState::Running {
        warn!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Unloading a running plugin");
        stop_plugin(plugin)?;
    }

    // Call the plugin's unload function
    match call_plugin_function(plugin, "unload", &[]) {
        Ok(_) => {
            // Clear the runtime
            plugin.clear_runtime();

            // Update the plugin state
            plugin.update_state(PluginState::Created);

            info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Plugin unloaded");
            Ok(())
        }
        Err(e) => {
            // Update the plugin state
            plugin.update_state(PluginState::Failed);
            error!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, error = %e, "Failed to unload plugin");
            Err(e)
        }
    }
}

/// Pauses a plugin
///
/// # Arguments
///
/// * `plugin` - The plugin to pause
///
/// # Returns
///
/// * `Ok(())` - If pausing succeeds
/// * `Err(ForgeError)` - If pausing fails
pub fn pause_plugin(plugin: &mut PluginInstance) -> Result<()> {
    info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Pausing plugin");

    // Check if the plugin is in the correct state
    if plugin.state != PluginState::Running {
        return Err(ForgeError::ValidationError {
            field: "state".to_string(),
            rule: "running".to_string(),
            value: format!(
                "Plugin '{}' is not in the Running state",
                plugin.manifest.name
            ),
            suggestions: vec![],
        });
    }

    // Call the plugin's pause function
    match call_plugin_function(plugin, "pause", &[]) {
        Ok(_) => {
            // Update the plugin state
            plugin.update_state(PluginState::Paused);
            info!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, "Plugin paused");
            Ok(())
        }
        Err(e) => {
            // Keep the plugin in the running state
            error!(plugin_id = %plugin.id, plugin_name = %plugin.manifest.name, error = %e, "Failed to pause plugin");
            Err(e)
        }
    }
}

/// Calls a function in a plugin
///
/// # Arguments
///
/// * `plugin` - The plugin to call the function in
/// * `function_name` - The name of the function to call
/// * `args` - The arguments to pass to the function
///
/// # Returns
///
/// * `Ok(Val)` - The return value of the function
/// * `Err(ForgeError)` - If the function call fails
fn call_plugin_function(
    plugin: &mut PluginInstance,
    function_name: &str,
    args: &[Val],
) -> Result<Val> {
    let mut runtime = plugin
        .runtime
        .lock()
        .map_err(|_| ForgeError::ValidationError {
            field: "runtime".to_string(),
            rule: "lock".to_string(),
            value: format!(
                "Failed to lock runtime for plugin '{}'",
                plugin.manifest.name
            ),
            suggestions: vec![],
        })?;
    let mut results = runtime.call_func(function_name, args)?;
    // Return the first value if present, else error
    results
        .into_iter()
        .next()
        .ok_or_else(|| ForgeError::ValidationError {
            field: "plugin function call".to_string(),
            rule: "return value".to_string(),
            value: format!(
                "No return value from function '{}' in plugin '{}'",
                function_name, plugin.manifest.name
            ),
            suggestions: vec![],
        })
}
