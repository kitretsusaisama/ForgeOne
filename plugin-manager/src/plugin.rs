//! Plugin module for the ForgeOne Plugin Manager
//!
//! Defines the Plugin trait and PluginInstance struct for managing plugins.
//! Provides functionality for loading, managing plugin manifests, and handling
//! plugin lifecycle.

//use crate::plugin::PluginState;
use crate::runtime::execution::PluginRuntime;
use crate::runtime::execution::Val;
use crate::runtime::wasm_plugin::WasmPlugin;
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Plugin instance state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginState {
    /// Plugin is created but not initialized
    Created,
    /// Plugin is initializing
    Initializing,
    /// Plugin is initialized and ready
    Ready,
    /// Plugin is running
    Running,
    /// Plugin is paused
    Paused,
    /// Plugin is stopping
    Stopping,
    /// Plugin is stopped
    Stopped,
    /// Plugin has failed
    Failed,
}

/// Plugin manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin description
    pub description: String,
    /// Plugin author
    pub author: String,
    /// Plugin license
    pub license: String,
    /// Plugin homepage
    pub homepage: Option<String>,
    /// Plugin repository
    pub repository: Option<String>,
    /// Plugin dependencies
    pub dependencies: Option<HashMap<String, String>>,
    /// Plugin permissions
    pub permissions: Option<Vec<String>>,
    /// Plugin entry point
    pub entry_point: String,
    /// Plugin hash
    pub hash: Option<String>,
    /// Plugin signature
    pub signature: Option<String>,
    /// Plugin capabilities
    pub capabilities: Option<Vec<String>>,
    /// Plugin configuration schema
    pub config_schema: Option<serde_json::Value>,
}

impl PluginManifest {
    /// Load a plugin manifest from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut file = File::open(path)
            .map_err(|e| ForgeError::IoError(format!("Failed to open manifest file: {}", e)))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| ForgeError::IoError(format!("Failed to read manifest file: {}", e)))?;

        if path.extension().map_or(false, |ext| ext == "toml") {
            Self::from_toml(&contents)
        } else if path.extension().map_or(false, |ext| ext == "json") {
            Self::from_json(&contents)
        } else {
            Err(ForgeError::IoError(
                "Unsupported manifest format. Expected .toml or .json".to_string(),
            ))
        }
    }

    /// Load a plugin manifest from TOML
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        toml::from_str(toml_str)
            .map_err(|e| ForgeError::IoError(format!("Failed to parse TOML manifest: {}", e)))
    }

    /// Load a plugin manifest from JSON
    pub fn from_json(json_str: &str) -> Result<Self> {
        serde_json::from_str(json_str)
            .map_err(|e| ForgeError::IoError(format!("Failed to parse JSON manifest: {}", e)))
    }

    /// Validate the plugin manifest
    pub fn validate(&self) -> Result<()> {
        // Check required fields
        if self.name.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "name".to_string(),
                rule: "required".to_string(),
                value: self.name.clone(),
                suggestions: vec![],
            });
        }

        if self.version.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "version".to_string(),
                rule: "required".to_string(),
                value: self.version.clone(),
                suggestions: vec![],
            });
        }

        if self.description.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "description".to_string(),
                rule: "required".to_string(),
                value: self.description.clone(),
                suggestions: vec![],
            });
        }

        if self.author.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "author".to_string(),
                rule: "required".to_string(),
                value: self.author.clone(),
                suggestions: vec![],
            });
        }

        if self.license.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "license".to_string(),
                rule: "required".to_string(),
                value: self.license.clone(),
                suggestions: vec![],
            });
        }

        if self.entry_point.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "entry_point".to_string(),
                rule: "required".to_string(),
                value: self.entry_point.clone(),
                suggestions: vec![],
            });
        }

        // Validate version format
        if semver::Version::parse(&self.version).is_err() {
            return Err(ForgeError::ValidationError {
                field: "version".to_string(),
                rule: "invalid".to_string(),
                value: self.version.clone(),
                suggestions: vec![],
            });
        }

        Ok(())
    }
}

/// Plugin instance
#[derive(Debug)]
pub struct PluginInstance {
    /// Unique identifier for this plugin instance
    pub id: Uuid,
    /// Plugin manifest
    pub manifest: PluginManifest,
    /// Plugin state
    pub state: PluginState,
    /// Plugin runtime
    pub runtime: Arc<Mutex<PluginRuntime>>,
    /// Plugin identity context
    pub identity: Arc<IdentityContext>,
    /// Plugin creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Plugin last updated time
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// Plugin source path
    pub source_path: PathBuf,
    /// Plugin metadata
    pub metadata: HashMap<String, String>,
}

impl PluginInstance {
    /// Create a new plugin instance
    pub fn new(
        manifest: PluginManifest,
        runtime: PluginRuntime,
        source_path: PathBuf,
        identity: IdentityContext,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: Uuid::new_v4(),
            manifest,
            state: PluginState::Created,
            runtime: Arc::new(Mutex::new(runtime)),
            identity: Arc::new(identity),
            created_at: now,
            updated_at: now,
            source_path,
            metadata: HashMap::new(),
        }
    }

    /// Get the plugin name
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// Get the plugin version
    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// Get the plugin description
    pub fn description(&self) -> &str {
        &self.manifest.description
    }

    /// Update the plugin state
    pub fn update_state(&mut self, state: PluginState) {
        self.state = state;
        self.updated_at = chrono::Utc::now();
    }

    /// Add metadata to the plugin
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
        self.updated_at = chrono::Utc::now();
    }

    /// Get metadata from the plugin
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Check if the plugin has the specified permission
    pub fn has_permission(&self, permission: &str) -> bool {
        match &self.manifest.permissions {
            Some(permissions) => permissions.contains(&permission.to_string()),
            None => false,
        }
    }

    /// Initialize the plugin
    pub fn initialize(&mut self) -> Result<()> {
        self.update_state(PluginState::Initializing);
        // Perform initialization logic here
        self.update_state(PluginState::Ready);
        Ok(())
    }

    /// Start the plugin
    pub fn start(&mut self) -> Result<()> {
        if self.state != PluginState::Ready && self.state != PluginState::Stopped {
            return Err(ForgeError::InvalidState(format!(
                "Cannot start plugin from state: {:?}",
                self.state
            )));
        }

        self.update_state(PluginState::Running);
        Ok(())
    }

    /// Stop the plugin
    pub fn stop(&mut self) -> Result<()> {
        if self.state != PluginState::Running && self.state != PluginState::Paused {
            return Err(ForgeError::InvalidState(format!(
                "Cannot stop plugin from state: {:?}",
                self.state
            )));
        }

        self.update_state(PluginState::Stopping);
        // Perform stopping logic here
        self.update_state(PluginState::Stopped);
        Ok(())
    }

    /// Pause the plugin
    pub fn pause(&mut self) -> Result<()> {
        if self.state != PluginState::Running {
            return Err(ForgeError::InvalidState(format!(
                "Cannot pause plugin from state: {:?}",
                self.state
            )));
        }

        self.update_state(PluginState::Paused);
        Ok(())
    }

    /// Resume the plugin
    pub fn resume(&mut self) -> Result<()> {
        if self.state != PluginState::Paused {
            return Err(ForgeError::InvalidState(format!(
                "Cannot resume plugin from state: {:?}",
                self.state
            )));
        }

        self.update_state(PluginState::Running);
        Ok(())
    }

    /// Clear the plugin runtime
    pub fn clear_runtime(&mut self) {
        // Step 1: Extract what we need while the lock is held
        let (engine_type, context) = {
            let guard = self.runtime.lock().unwrap();
            let engine_type = guard.engine_type.clone();
            let context = guard.context.lock().unwrap().clone();
            (engine_type, context)
        }; // 🔓 `guard` is dropped here!

        // Step 2: Reconstruct new runtime
        let new_runtime = PluginRuntime::new(engine_type, context);

        // Step 3: Safely assign to self.runtime now
        self.runtime = Arc::new(Mutex::new(new_runtime));
    }
}

/// Plugin trait defining the interface for all plugins
pub trait Plugin: Send + Sync {
    /// Get the plugin ID
    fn id(&self) -> Uuid;

    /// Get the plugin name
    fn name(&self) -> &str;

    /// Get the plugin version
    fn version(&self) -> &str;

    /// Get the plugin description
    fn description(&self) -> &str;

    /// Initialize the plugin
    fn initialize(&mut self) -> Result<()>;

    /// Start the plugin
    fn start(&mut self) -> Result<()>;

    /// Stop the plugin
    fn stop(&mut self) -> Result<()>;

    /// Pause the plugin
    fn pause(&mut self) -> Result<()>;

    /// Resume the plugin
    fn resume(&mut self) -> Result<()>;

    /// Shutdown the plugin
    fn shutdown(&mut self) -> Result<()>;

    /// Get plugin capabilities
    fn capabilities(&self) -> Vec<String>;

    /// Check if plugin has a specific capability
    fn has_capability(&self, capability: &str) -> bool {
        self.capabilities().contains(&capability.to_string())
    }

    /// Get plugin permissions
    fn permissions(&self) -> Vec<String>;

    /// Check if plugin has a specific permission
    fn has_permission(&self, permission: &str) -> bool {
        self.permissions().contains(&permission.to_string())
    }

    fn as_any(&self) -> &dyn Any;
    fn identity(&self) -> Arc<IdentityContext>;
    fn state(&self) -> PluginState;
    fn call_function(&mut self, function_name: &str, args: Vec<String>) -> Result<String>;
}

impl Plugin for PluginInstance {
    fn id(&self) -> Uuid {
        self.id
    }
    fn name(&self) -> &str {
        &self.manifest.name
    }
    fn version(&self) -> &str {
        &self.manifest.version
    }
    fn description(&self) -> &str {
        &self.manifest.description
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn identity(&self) -> Arc<IdentityContext> {
        self.identity.clone()
    }
    fn state(&self) -> PluginState {
        self.state
    }
    fn initialize(&mut self) -> Result<()> {
        PluginInstance::initialize(self)
    }
    fn start(&mut self) -> Result<()> {
        PluginInstance::start(self)
    }
    fn stop(&mut self) -> Result<()> {
        PluginInstance::stop(self)
    }
    fn pause(&mut self) -> Result<()> {
        PluginInstance::pause(self)
    }
    fn resume(&mut self) -> Result<()> {
        PluginInstance::resume(self)
    }
    fn shutdown(&mut self) -> Result<()> {
        PluginInstance::stop(self) // or implement a specific shutdown if needed
    }
    fn capabilities(&self) -> Vec<String> {
        self.manifest.capabilities.clone().unwrap_or_default()
    }
    fn permissions(&self) -> Vec<String> {
        self.manifest.permissions.clone().unwrap_or_default()
    }
    fn call_function(&mut self, function_name: &str, args: Vec<String>) -> Result<String> {
        let mut guard = self.runtime.lock().unwrap();
        let args_val: Vec<Val> = args.into_iter().map(Val::String).collect();
        let result_vec = guard.call_func(function_name, &args_val)?;
        Ok(format!("{:?}", result_vec))
    }
}
