//! # Plugin Bridge Module
//!
//! This module provides the interface for bridging plugins with the runtime.
//!
//! It allows dynamic registration, initialization, and lifecycle management of plugins.

use common::error::{ForgeError, Result};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Trait that all plugins must implement
pub trait RuntimePlugin: Send + Sync {
    /// Called when the plugin is registered
    fn on_register(&self) -> Result<()> {
        Ok(())
    }
    /// Called when the plugin is initialized
    fn on_init(&self) -> Result<()> {
        Ok(())
    }
    /// Called when the plugin is shutdown
    fn on_shutdown(&self) -> Result<()> {
        Ok(())
    }
    /// Plugin name
    fn name(&self) -> &str;
    /// Plugin version
    fn version(&self) -> &str;
}

/// Plugin registration info
#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
}

/// The main plugin bridge manager
pub struct PluginBridge {
    plugins: RwLock<HashMap<String, Arc<dyn RuntimePlugin>>>,
}

impl PluginBridge {
    /// Create a new plugin bridge
    pub fn new() -> Self {
        Self {
            plugins: RwLock::new(HashMap::new()),
        }
    }

    /// Register a plugin
    pub fn register_plugin(&self, plugin: Arc<dyn RuntimePlugin>) -> Result<PluginInfo> {
        let name = plugin.name().to_string();
        let version = plugin.version().to_string();
        plugin.on_register()?;
        self.plugins.write().unwrap().insert(name.clone(), plugin);
        Ok(PluginInfo { name, version })
    }

    /// Initialize all registered plugins
    pub fn initialize_plugins(&self) -> Result<()> {
        for plugin in self.plugins.read().unwrap().values() {
            plugin.on_init()?;
        }
        Ok(())
    }

    /// Shutdown all registered plugins
    pub fn shutdown_plugins(&self) -> Result<()> {
        for plugin in self.plugins.read().unwrap().values() {
            plugin.on_shutdown()?;
        }
        Ok(())
    }

    /// Get a plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<Arc<dyn RuntimePlugin>> {
        self.plugins.read().unwrap().get(name).cloned()
    }

    /// List all registered plugins
    pub fn list_plugins(&self) -> Vec<PluginInfo> {
        self.plugins
            .read()
            .unwrap()
            .values()
            .map(|p| PluginInfo {
                name: p.name().to_string(),
                version: p.version().to_string(),
            })
            .collect()
    }
}

/// Global plugin bridge instance
use std::sync::OnceLock;
static PLUGIN_BRIDGE: OnceLock<Arc<PluginBridge>> = OnceLock::new();

/// Initialize the plugin bridge (singleton)
pub fn init_plugin_bridge() -> Arc<PluginBridge> {
    PLUGIN_BRIDGE
        .get_or_init(|| Arc::new(PluginBridge::new()))
        .clone()
}

/// Register a plugin globally
pub fn register_plugin(plugin: Arc<dyn RuntimePlugin>) -> Result<PluginInfo> {
    let bridge = init_plugin_bridge();
    bridge.register_plugin(plugin)
}

/// Initialize all plugins globally
pub fn initialize_plugins() -> Result<()> {
    let bridge = init_plugin_bridge();
    bridge.initialize_plugins()
}

/// Shutdown all plugins globally
pub fn shutdown_plugins() -> Result<()> {
    let bridge = init_plugin_bridge();
    bridge.shutdown_plugins()
}

/// List all registered plugins globally
pub fn list_plugins() -> Vec<PluginInfo> {
    let bridge = init_plugin_bridge();
    bridge.list_plugins()
}
