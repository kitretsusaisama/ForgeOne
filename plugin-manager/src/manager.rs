//! Plugin Manager for the ForgeOne Plugin Manager
//!
//! Provides functionality for managing plugin lifecycle, including loading,
//! starting, stopping, and unloading plugins.

use crate::plugin::{Plugin, PluginInstance, PluginManifest, PluginState};
use crate::runtime::execution::PluginContext;
use crate::runtime::wasm_plugin::{load_wasm_plugin, WasmPlugin};
use crate::sandbox::{cleanup_sandbox, create_sandbox, execute_in_sandbox, SandboxConfig};
use chrono::Utc;
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use common::telemetry::{TelemetryEvent, TelemetryManager};
use microkernel::trust::TrustContext;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

#[inline]
fn get_plugin_instance(p: &mut Box<dyn Plugin + Send + Sync>) -> &crate::plugin::PluginInstance {
    if let Some(wasm_plugin) = p
        .as_any()
        .downcast_ref::<crate::runtime::wasm_plugin::WasmPlugin>()
    {
        wasm_plugin.instance()
    } else if let Some(instance) = p.as_any().downcast_ref::<crate::plugin::PluginInstance>() {
        instance
    } else {
        panic!("Unknown plugin type for sandboxing");
    }
}

/// Plugin Manager
pub struct PluginManager {
    plugins: RwLock<HashMap<Uuid, Arc<Mutex<Box<dyn Plugin + Send + Sync>>>>>,
    registry_paths: Vec<PathBuf>,
    trust_context: Arc<TrustContext>,
    default_sandbox_config: SandboxConfig,
    telemetry: Arc<TelemetryManager>,
}

impl PluginManager {
    /// Create a new plugin manager
    pub fn new(
        registry_paths: Vec<PathBuf>,
        telemetry: Arc<TelemetryManager>,
        trust_context: Arc<TrustContext>,
        default_sandbox_config: SandboxConfig,
    ) -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
            registry_paths,
            trust_context,
            default_sandbox_config,
            telemetry,
        }
    }
    /// Load a plugin from a path
    pub fn load_plugin<P: AsRef<Path>>(
        &self,
        manifest_path: P,
        identity_context: IdentityContext,
    ) -> Result<Uuid> {
        let manifest_path = manifest_path.as_ref();
        info!("Loading plugin from manifest: {}", manifest_path.display());

        // Find the WASM file in the same directory as the manifest
        let manifest_dir = manifest_path.parent().ok_or_else(|| {
            ForgeError::NotFound(format!(
                "Manifest has no parent directory: {}",
                manifest_path.display()
            ))
        })?;
        let wasm_file = std::fs::read_dir(manifest_dir)
            .map_err(|e| ForgeError::IoError(format!("Failed to read manifest directory: {}", e)))?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().map_or(false, |ext| ext == "wasm"))
            .ok_or_else(|| {
                ForgeError::NotFound(format!("No .wasm file found in {}", manifest_dir.display()))
            })?;

        // Use tenant_id and user_id from IdentityContext
        let tenant_id = identity_context.tenant_id.clone();
        let user_id = identity_context.user_id.clone();

        // Load the plugin
        let plugin = load_wasm_plugin(manifest_path, &wasm_file, tenant_id, user_id)?;
        let plugin_id = plugin.id();

        // Add the plugin to the registry as a trait object
        let mut plugins = self.plugins.write().map_err(|_| {
            ForgeError::Other("Failed to acquire write lock on plugin registry".to_string())
        })?;

        plugins.insert(plugin_id, Arc::new(Mutex::new(Box::new(plugin))));
        info!("Plugin loaded with ID: {}", plugin_id);

        Ok(plugin_id)
    }

    /// Initialize a plugin
    pub fn initialize_plugin(&self, plugin_id: Uuid) -> Result<()> {
        info!("Initializing plugin with ID: {}", plugin_id);

        // Get the plugin
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        let plugin = plugins.get(&plugin_id).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
        })?;

        // Lock plugin and execute everything within the same scope
        let mut plugin_guard = plugin.lock().map_err(|_| {
            ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
        })?;
        let plugin_id_val = plugin_guard.id();
        let plugin_name_val = plugin_guard.name().to_string();
        let plugin_identity_val = plugin_guard.identity().clone();
        let plugin_instance_val = get_plugin_instance(&mut *plugin_guard).clone();
        // drop(plugin_guard); // Drop the lock before the closure
        let plugin_context =
            PluginContext::new(plugin_id_val, plugin_name_val, plugin_identity_val);
        let sandboxed_context = create_sandbox(
            plugin_context,
            self.default_sandbox_config.clone(),
            plugin_instance_val.clone(),
        )?;
        execute_in_sandbox(&sandboxed_context, plugin_instance_val, || {
            let mut plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;
            plugin_guard.initialize()
        })?;
        Ok(())
    }

    /// Start a plugin
    pub fn start_plugin(&self, plugin_id: Uuid) -> Result<()> {
        info!("Starting plugin with ID: {}", plugin_id);

        // Get the plugin
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        let plugin = plugins.get(&plugin_id).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
        })?;

        // Lock plugin and execute everything within the same scope
        let mut plugin_guard = plugin.lock().map_err(|_| {
            ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
        })?;
        let plugin_id_val = plugin_guard.id();
        let plugin_name_val = plugin_guard.name().to_string();
        let plugin_identity_val = plugin_guard.identity().clone();
        let plugin_instance_val = get_plugin_instance(&mut *plugin_guard).clone();
        // drop(plugin_guard); // Drop the lock before the closure
        let plugin_context =
            PluginContext::new(plugin_id_val, plugin_name_val, plugin_identity_val);
        let sandboxed_context = create_sandbox(
            plugin_context,
            self.default_sandbox_config.clone(),
            plugin_instance_val.clone(),
        )?;
        execute_in_sandbox(&sandboxed_context, plugin_instance_val, || {
            let mut plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;
            plugin_guard.start()
        })?;

        Ok(())
    }

    /// Stop a plugin
    pub fn stop_plugin(&self, plugin_id: Uuid) -> Result<()> {
        info!("Stopping plugin with ID: {}", plugin_id);

        // Get the plugin
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        let plugin = plugins.get(&plugin_id).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
        })?;

        // Lock plugin and execute everything within the same scope
        let mut plugin_guard = plugin.lock().map_err(|_| {
            ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
        })?;
        let plugin_id_val = plugin_guard.id();
        let plugin_name_val = plugin_guard.name().to_string();
        let plugin_identity_val = plugin_guard.identity().clone();
        let plugin_instance_val = get_plugin_instance(&mut *plugin_guard).clone();
        // drop(plugin_guard); // Drop the lock before the closure
        let plugin_context =
            PluginContext::new(plugin_id_val, plugin_name_val, plugin_identity_val);
        let sandboxed_context = create_sandbox(
            plugin_context,
            self.default_sandbox_config.clone(),
            plugin_instance_val.clone(),
        )?;
        execute_in_sandbox(&sandboxed_context, plugin_instance_val, || {
            let mut plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;
            plugin_guard.stop()
        })?;

        // Clean up the sandbox regardless of the result
        cleanup_sandbox(&sandboxed_context, plugin_instance_val)?;

        Ok(())
    }

    /// Pause a plugin
    pub fn pause_plugin(&self, plugin_id: Uuid) -> Result<()> {
        info!("Pausing plugin with ID: {}", plugin_id);

        // Get the plugin
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        let plugin = plugins.get(&plugin_id).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
        })?;

        // Lock plugin and execute everything within the same scope
        let mut plugin_guard = plugin.lock().map_err(|_| {
            ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
        })?;
        let plugin_id_val = plugin_guard.id();
        let plugin_name_val = plugin_guard.name().to_string();
        let plugin_identity_val = plugin_guard.identity().clone();
        let plugin_instance_val = get_plugin_instance(&mut *plugin_guard).clone();
        // drop(plugin_guard); // Drop the lock before the closure
        let plugin_context =
            PluginContext::new(plugin_id_val, plugin_name_val, plugin_identity_val);
        let sandboxed_context = create_sandbox(
            plugin_context,
            self.default_sandbox_config.clone(),
            plugin_instance_val.clone(),
        )?;
        execute_in_sandbox(&sandboxed_context, plugin_instance_val, || {
            let mut plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;
            plugin_guard.pause()
        })?;

        Ok(())
    }

    /// Resume a plugin
    pub fn resume_plugin(&self, plugin_id: Uuid) -> Result<()> {
        info!("Resuming plugin with ID: {}", plugin_id);

        // Get the plugin
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        let plugin = plugins.get(&plugin_id).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
        })?;

        // Lock plugin and execute everything within the same scope
        let mut plugin_guard = plugin.lock().map_err(|_| {
            ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
        })?;
        let plugin_id_val = plugin_guard.id();
        let plugin_name_val = plugin_guard.name().to_string();
        let plugin_identity_val = plugin_guard.identity().clone();
        let plugin_instance_val = get_plugin_instance(&mut *plugin_guard).clone();
        // drop(plugin_guard); // Drop the lock before the closure
        let plugin_context =
            PluginContext::new(plugin_id_val, plugin_name_val, plugin_identity_val);
        let sandboxed_context = create_sandbox(
            plugin_context,
            self.default_sandbox_config.clone(),
            plugin_instance_val.clone(),
        )?;
        execute_in_sandbox(&sandboxed_context, plugin_instance_val, || {
            let mut plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;
            plugin_guard.resume()
        })?;

        Ok(())
    }

    /// Unload a plugin
    pub fn unload_plugin(&self, plugin_id: Uuid) -> Result<()> {
        info!("Unloading plugin with ID: {}", plugin_id);

        // First, check if the plugin is running by getting a read lock
        let plugin_state = {
            let plugins = self.plugins.read().map_err(|_| {
                ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
            })?;

            let plugin = plugins.get(&plugin_id).ok_or_else(|| {
                ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
            })?;

            let plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;

            plugin_guard.state()
        }; // Read lock is dropped here

        if plugin_state == PluginState::Running || plugin_state == PluginState::Paused {
            return Err(ForgeError::InvalidState(format!(
                "Cannot unload plugin in state: {:?}",
                plugin_state
            )));
        }

        // Record telemetry event
        let mut attributes = HashMap::new();
        attributes.insert("plugin_id".to_string(), plugin_id.to_string());
        self.telemetry.record_event(TelemetryEvent {
            name: "PluginUnload".to_string(),
            time: chrono::Utc::now(),
            attributes,
        });

        // Now get a write lock to remove the plugin
        let mut plugins = self.plugins.write().map_err(|_| {
            ForgeError::IoError("Failed to acquire write lock on plugin registry".to_string())
        })?;

        // Remove the plugin from the registry
        plugins.remove(&plugin_id);
        debug!("Plugin unloaded with ID: {}", plugin_id);

        Ok(())
    }

    /// Get a plugin by ID
    pub fn get_plugin(&self, plugin_id: Uuid) -> Result<Arc<Mutex<Box<dyn Plugin + Send + Sync>>>> {
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        plugins
            .get(&plugin_id)
            .cloned()
            .ok_or_else(|| ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id)))
    }

    /// Get all plugins
    pub fn get_all_plugins(&self) -> Result<Vec<Arc<Mutex<Box<dyn Plugin + Send + Sync>>>>> {
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        Ok(plugins.values().cloned().collect())
    }

    /// Scan registry paths for plugins
    pub fn scan_registry(&self, identity_context: IdentityContext) -> Result<Vec<Uuid>> {
        info!("Scanning plugin registry paths");
        let mut loaded_plugins = Vec::new();

        for path in &self.registry_paths {
            debug!("Scanning registry path: {}", path.display());

            if !path.exists() || !path.is_dir() {
                warn!(
                    "Registry path does not exist or is not a directory: {}",
                    path.display()
                );
                continue;
            }

            // Walk the directory and find plugin manifests
            for entry in walkdir::WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();

                // Check if this is a plugin manifest file
                if entry_path.is_file()
                    && (entry_path
                        .file_name()
                        .map_or(false, |name| name == "plugin.toml")
                        || entry_path
                            .file_name()
                            .map_or(false, |name| name == "plugin.json"))
                {
                    debug!("Found plugin manifest: {}", entry_path.display());

                    // Load the plugin from the directory containing the manifest
                    if let Some(plugin_dir) = entry_path.parent() {
                        match self.load_plugin(plugin_dir, identity_context.clone()) {
                            Ok(plugin_id) => {
                                loaded_plugins.push(plugin_id);
                            }
                            Err(err) => {
                                error!(
                                    "Failed to load plugin from {}: {}",
                                    plugin_dir.display(),
                                    err
                                );
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded {} plugins from registry", loaded_plugins.len());
        Ok(loaded_plugins)
    }

    /// Call a function on a plugin
    pub fn call_plugin_function(
        &self,
        plugin_id: Uuid,
        function_name: &str,
        args: Vec<String>,
    ) -> Result<String> {
        info!(
            "Calling function '{}' on plugin with ID: {}",
            function_name, plugin_id
        );

        // Get the plugin
        let plugins = self.plugins.read().map_err(|_| {
            ForgeError::IoError("Failed to acquire read lock on plugin registry".to_string())
        })?;

        let plugin = plugins.get(&plugin_id).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with ID {} not found", plugin_id))
        })?;

        // Lock plugin and execute everything within the same scope
        let mut plugin_guard = plugin.lock().map_err(|_| {
            ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
        })?;
        let plugin_id_val = plugin_guard.id();
        let plugin_name_val = plugin_guard.name().to_string();
        let plugin_identity_val = plugin_guard.identity().clone();
        let plugin_instance_val = get_plugin_instance(&mut *plugin_guard).clone();
        // drop(plugin_guard); // Drop the lock before the closure
        let plugin_context =
            PluginContext::new(plugin_id_val, plugin_name_val, plugin_identity_val);
        let sandboxed_context = create_sandbox(
            plugin_context,
            self.default_sandbox_config.clone(),
            plugin_instance_val.clone(),
        )?;
        let result = execute_in_sandbox(&sandboxed_context, plugin_instance_val, || {
            let mut plugin_guard = plugin.lock().map_err(|_| {
                ForgeError::IoError(format!("Failed to acquire lock on plugin {}", plugin_id))
            })?;
            plugin_guard.call_function(function_name, args)
        })?;

        Ok(result)
    }
}
