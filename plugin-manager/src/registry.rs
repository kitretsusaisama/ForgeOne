//! Plugin registry for the ForgeOne Plugin Manager
//!
//! Provides a registry for managing plugin instances, including loading,
//! unloading, and querying plugins.

use crate::loader::forgepkg::load_plugin;
use crate::plugin::{PluginInstance, PluginState};
use common::config::ForgeConfig as Config;
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

/// Plugin registry
#[derive(Debug)]
pub struct PluginRegistry {
    /// Registered plugins by ID
    plugins: RwLock<HashMap<Uuid, Arc<Mutex<PluginInstance>>>>,
    /// Registered plugins by name
    plugins_by_name: RwLock<HashMap<String, Arc<Mutex<PluginInstance>>>>,
    /// Plugin directory
    plugin_dir: PathBuf,
    /// Registry configuration
    config: Option<Config>,
}

impl PluginRegistry {
    /// Create a new plugin registry with default configuration
    pub fn new() -> Self {
        let plugin_dir = PathBuf::from("plugins");
        Self {
            plugins: RwLock::new(HashMap::new()),
            plugins_by_name: RwLock::new(HashMap::new()),
            plugin_dir,
            config: None,
        }
    }

    /// Create a new plugin registry with custom configuration
    pub fn new_with_config(config: &Config) -> Self {
        let plugin_dir = PathBuf::from(&config.plugin_dir);
        Self {
            plugins: RwLock::new(HashMap::new()),
            plugins_by_name: RwLock::new(HashMap::new()),
            plugin_dir,
            config: Some(config.clone()),
        }
    }

    /// Register a plugin
    pub fn register(&self, plugin: PluginInstance) -> Result<Arc<Mutex<PluginInstance>>> {
        let plugin_arc = Arc::new(Mutex::new(plugin));
        let plugin_id;
        let plugin_name;

        {
            let plugin = plugin_arc.lock().unwrap();
            plugin_id = plugin.id;
            plugin_name = plugin.name().to_string();
        }

        // Check if plugin with same name already exists
        if self
            .plugins_by_name
            .read()
            .unwrap()
            .contains_key(&plugin_name)
        {
            return Err(ForgeError::AlreadyExists(format!(
                "Plugin with name '{}' already exists",
                plugin_name
            )));
        }

        // Register plugin
        self.plugins
            .write()
            .unwrap()
            .insert(plugin_id, plugin_arc.clone());
        self.plugins_by_name
            .write()
            .unwrap()
            .insert(plugin_name, plugin_arc.clone());

        tracing::info!(plugin_id = %plugin_id, "Plugin registered");
        Ok(plugin_arc)
    }

    /// Unregister a plugin
    pub fn unregister(&self, id: Uuid) -> Result<()> {
        let mut plugins = self.plugins.write().unwrap();
        let mut plugins_by_name = self.plugins_by_name.write().unwrap();

        // Get plugin
        let plugin = plugins
            .get(&id)
            .ok_or_else(|| ForgeError::NotFound(format!("Plugin with ID '{}' not found", id)))?;

        // Get plugin name
        let plugin_name = plugin.lock().unwrap().name().to_string();

        // Remove plugin
        plugins.remove(&id);
        plugins_by_name.remove(&plugin_name);

        tracing::info!(plugin_id = %id, "Plugin unregistered");
        Ok(())
    }

    /// Get a plugin by ID
    pub fn get(&self, id: Uuid) -> Result<Arc<Mutex<PluginInstance>>> {
        let plugins = self.plugins.read().unwrap();
        let plugin = plugins
            .get(&id)
            .ok_or_else(|| ForgeError::NotFound(format!("Plugin with ID '{}' not found", id)))?;
        Ok(plugin.clone())
    }

    /// Get a plugin by name
    pub fn get_by_name(&self, name: &str) -> Result<Arc<Mutex<PluginInstance>>> {
        let plugins_by_name = self.plugins_by_name.read().unwrap();
        let plugin = plugins_by_name.get(name).ok_or_else(|| {
            ForgeError::NotFound(format!("Plugin with name '{}' not found", name))
        })?;
        Ok(plugin.clone())
    }

    /// Get all plugins
    pub fn get_all(&self) -> Vec<Arc<Mutex<PluginInstance>>> {
        let plugins = self.plugins.read().unwrap();
        plugins.values().cloned().collect()
    }

    /// Load a plugin from a file
    pub fn load_plugin<P: AsRef<Path>>(
        &self,
        path: P,
        identity: IdentityContext,
    ) -> Result<Arc<Mutex<PluginInstance>>> {
        // Load plugin
        let plugin = load_plugin(path.as_ref(), identity)?;

        // Register plugin
        self.register(plugin)
    }

    /// Load all plugins from the plugin directory
    pub fn load_all_plugins(
        &self,
        identity: IdentityContext,
    ) -> Result<Vec<Arc<Mutex<PluginInstance>>>> {
        let mut loaded_plugins = Vec::new();

        // Create plugin directory if it doesn't exist
        if !self.plugin_dir.exists() {
            std::fs::create_dir_all(&self.plugin_dir)
                .map_err(|e| ForgeError::IoError(format!("Failed to create plugin dir: {}", e)))?;
        }

        // Iterate over all files in the plugin directory
        for entry in std::fs::read_dir(&self.plugin_dir)
            .map_err(|e| ForgeError::IoError(format!("Failed to read plugin dir: {}", e)))?
        {
            let entry = entry
                .map_err(|e| ForgeError::IoError(format!("Failed to read dir entry: {}", e)))?;
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Skip non-forgepkg files
            if path.extension().map_or(true, |ext| ext != "forgepkg") {
                continue;
            }

            // Load plugin
            match self.load_plugin(&path, identity.clone()) {
                Ok(plugin) => {
                    loaded_plugins.push(plugin);
                }
                Err(err) => {
                    tracing::error!(path = %path.display(), error = %err, "Failed to load plugin");
                }
            }
        }

        Ok(loaded_plugins)
    }

    /// Initialize all plugins
    pub fn initialize_all(&self) -> Result<()> {
        let plugins = self.get_all();
        for plugin in plugins {
            let mut plugin = plugin.lock().unwrap();
            if plugin.state == PluginState::Created {
                match crate::lifecycle::initialize_plugin(&mut plugin) {
                    Ok(_) => {
                        tracing::info!(plugin_id = %plugin.id, "Plugin initialized");
                    }
                    Err(err) => {
                        tracing::error!(plugin_id = %plugin.id, error = %err, "Failed to initialize plugin");
                    }
                }
            }
        }
        Ok(())
    }

    /// Start all plugins
    pub fn start_all(&self) -> Result<()> {
        let plugins = self.get_all();
        for plugin in plugins {
            let mut plugin = plugin.lock().unwrap();
            if plugin.state == PluginState::Ready {
                match crate::lifecycle::start_plugin(&mut plugin) {
                    Ok(_) => {
                        tracing::info!(plugin_id = %plugin.id, "Plugin started");
                    }
                    Err(err) => {
                        tracing::error!(plugin_id = %plugin.id, error = %err, "Failed to start plugin");
                    }
                }
            }
        }
        Ok(())
    }

    /// Stop all plugins
    pub fn stop_all(&self) -> Result<()> {
        let plugins = self.get_all();
        for plugin in plugins {
            let mut plugin = plugin.lock().unwrap();
            if plugin.state == PluginState::Running {
                match crate::lifecycle::stop_plugin(&mut plugin) {
                    Ok(_) => {
                        tracing::info!(plugin_id = %plugin.id, "Plugin stopped");
                    }
                    Err(err) => {
                        tracing::error!(plugin_id = %plugin.id, error = %err, "Failed to stop plugin");
                    }
                }
            }
        }
        Ok(())
    }

    /// Unload all plugins
    pub fn unload_all(&self) -> Result<()> {
        let plugins = self.get_all();
        for plugin in plugins {
            let plugin_id;
            {
                let plugin = plugin.lock().unwrap();
                plugin_id = plugin.id;
            }
            match self.unregister(plugin_id) {
                Ok(_) => {
                    tracing::info!(plugin_id = %plugin_id, "Plugin unloaded");
                }
                Err(err) => {
                    tracing::error!(plugin_id = %plugin_id, error = %err, "Failed to unload plugin");
                }
            }
        }
        Ok(())
    }
}
