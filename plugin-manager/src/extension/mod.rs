//! Extension module for the ForgeOne Plugin Manager
//!
//! Provides support for the ForgePlugin API specification, allowing plugins to
//! register themselves at runtime and define their capabilities through manifests.

use crate::plugin::{PluginInstance, PluginManifest, PluginState};
use common::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use uuid::Uuid;

/// Plugin extension API version
pub const EXTENSION_API_VERSION: &str = "1.0.0";

/// Plugin extension manifest format (TOML)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginExtensionManifest {
    /// API version
    pub api_version: String,
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
    /// Plugin entry points
    pub entry_points: HashMap<String, String>,
    /// Plugin capabilities
    pub capabilities: Option<Vec<String>>,
    /// Plugin configuration schema
    pub config_schema: Option<serde_json::Value>,
    /// Plugin hash
    pub hash: Option<String>,
    /// Plugin signature
    pub signature: Option<String>,
}

/// Plugin extension registration
#[derive(Debug, Clone)]
pub struct PluginExtension {
    /// Extension ID
    pub id: Uuid,
    /// Extension manifest
    pub manifest: PluginExtensionManifest,
    /// Extension plugin instance
    pub plugin: Arc<Mutex<PluginInstance>>,
    /// Extension registration time
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Extension metadata
    pub metadata: HashMap<String, String>,
}

impl PluginExtension {
    /// Create a new plugin extension
    pub fn new(manifest: PluginExtensionManifest, plugin: Arc<Mutex<PluginInstance>>) -> Self {
        Self {
            id: Uuid::new_v4(),
            manifest,
            plugin,
            registered_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    /// Get the extension name
    pub fn name(&self) -> &str {
        &self.manifest.name
    }

    /// Get the extension version
    pub fn version(&self) -> &str {
        &self.manifest.version
    }

    /// Get the extension description
    pub fn description(&self) -> &str {
        &self.manifest.description
    }

    /// Add metadata to the extension
    pub fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Get metadata from the extension
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Check if the extension has the specified capability
    pub fn has_capability(&self, capability: &str) -> bool {
        match &self.manifest.capabilities {
            Some(capabilities) => capabilities.contains(&capability.to_string()),
            None => false,
        }
    }

    /// Get the entry point for the specified name
    pub fn get_entry_point(&self, name: &str) -> Option<&String> {
        self.manifest.entry_points.get(name)
    }
}

/// Plugin extension registry
#[derive(Debug)]
pub struct ExtensionRegistry {
    /// Registered extensions by ID
    extensions: RwLock<HashMap<Uuid, Arc<Mutex<PluginExtension>>>>,
    /// Registered extensions by name
    extensions_by_name: RwLock<HashMap<String, Arc<Mutex<PluginExtension>>>>,
}

impl ExtensionRegistry {
    /// Create a new extension registry
    pub fn new() -> Self {
        Self {
            extensions: RwLock::new(HashMap::new()),
            extensions_by_name: RwLock::new(HashMap::new()),
        }
    }

    /// Register a plugin extension
    pub fn register(&self, extension: PluginExtension) -> Result<Arc<Mutex<PluginExtension>>> {
        let extension_arc = Arc::new(Mutex::new(extension));
        let extension_id;
        let extension_name;

        {
            let extension = extension_arc.lock().unwrap();
            extension_id = extension.id;
            extension_name = extension.name().to_string();
        }

        // Check if extension with same name already exists
        if self
            .extensions_by_name
            .read()
            .unwrap()
            .contains_key(&extension_name)
        {
            return Err(ForgeError::AlreadyExists(format!(
                "Extension with name '{}' already exists",
                extension_name
            )));
        }

        // Register extension
        self.extensions
            .write()
            .unwrap()
            .insert(extension_id, extension_arc.clone());
        self.extensions_by_name
            .write()
            .unwrap()
            .insert(extension_name, extension_arc.clone());

        tracing::info!(extension_id = %extension_id, "Plugin extension registered");
        Ok(extension_arc)
    }

    /// Unregister a plugin extension
    pub fn unregister(&self, id: Uuid) -> Result<()> {
        let mut extensions = self.extensions.write().unwrap();
        let mut extensions_by_name = self.extensions_by_name.write().unwrap();

        // Get extension
        let extension = extensions
            .get(&id)
            .ok_or_else(|| ForgeError::NotFound(format!("Extension with ID '{}' not found", id)))?;

        // Get extension name
        let extension_name = extension.lock().unwrap().name().to_string();

        // Remove extension
        extensions.remove(&id);
        extensions_by_name.remove(&extension_name);

        tracing::info!(extension_id = %id, "Plugin extension unregistered");
        Ok(())
    }

    /// Get a plugin extension by ID
    pub fn get(&self, id: Uuid) -> Result<Arc<Mutex<PluginExtension>>> {
        let extensions = self.extensions.read().unwrap();
        let extension = extensions
            .get(&id)
            .ok_or_else(|| ForgeError::NotFound(format!("Extension with ID '{}' not found", id)))?;
        Ok(extension.clone())
    }

    /// Get a plugin extension by name
    pub fn get_by_name(&self, name: &str) -> Result<Arc<Mutex<PluginExtension>>> {
        let extensions_by_name = self.extensions_by_name.read().unwrap();
        let extension = extensions_by_name.get(name).ok_or_else(|| {
            ForgeError::NotFound(format!("Extension with name '{}' not found", name))
        })?;
        Ok(extension.clone())
    }

    /// Get all plugin extensions
    pub fn get_all(&self) -> Vec<Arc<Mutex<PluginExtension>>> {
        let extensions = self.extensions.read().unwrap();
        extensions.values().cloned().collect()
    }

    /// Get all plugin extensions with the specified capability
    pub fn get_by_capability(&self, capability: &str) -> Vec<Arc<Mutex<PluginExtension>>> {
        let extensions = self.extensions.read().unwrap();
        extensions
            .values()
            .filter(|ext| ext.lock().unwrap().has_capability(capability))
            .cloned()
            .collect()
    }
}

/// Load a plugin extension manifest from a TOML file
pub fn load_extension_manifest<P: AsRef<Path>>(path: P) -> Result<PluginExtensionManifest> {
    let path = path.as_ref();

    // Check if the file exists
    if !path.exists() {
        return Err(ForgeError::IoError(format!("File does not exist: {}", path.display())));
    }

    // Read the manifest file
    let manifest_data =
        std::fs::read_to_string(path).map_err(|e| ForgeError::IoError(e.to_string()))?;

    // Parse the manifest
    let manifest: PluginExtensionManifest =
        toml::from_str(&manifest_data).map_err(|e| ForgeError::ValidationError {
            field: "manifest".to_string(),
            rule: "parse".to_string(),
            value: e.to_string(),
            suggestions: vec![],
        })?;

    // Validate API version
    if !is_api_version_compatible(&manifest.api_version, EXTENSION_API_VERSION) {
        return Err(ForgeError::ValidationError {
            field: "manifest".to_string(),
            rule: "api_version".to_string(),
            value: format!(
                "Incompatible API version: {} (expected {})",
                manifest.api_version, EXTENSION_API_VERSION
            ),
            suggestions: vec![],
        });
    }

    Ok(manifest)
}

/// Check if the API version is compatible
fn is_api_version_compatible(version: &str, expected: &str) -> bool {
    // Parse versions
    let version = semver::Version::parse(version).unwrap_or_else(|_| semver::Version::new(0, 0, 0));
    let expected =
        semver::Version::parse(expected).unwrap_or_else(|_| semver::Version::new(0, 0, 0));
    // Check major version compatibility
    version.major == expected.major
}

/// Convert a plugin extension manifest to a plugin manifest
pub fn extension_to_plugin_manifest(ext_manifest: &PluginExtensionManifest) -> PluginManifest {
    PluginManifest {
        name: ext_manifest.name.clone(),
        version: ext_manifest.version.clone(),
        description: ext_manifest.description.clone(),
        author: ext_manifest.author.clone(),
        license: ext_manifest.license.clone(),
        homepage: ext_manifest.homepage.clone(),
        repository: ext_manifest.repository.clone(),
        dependencies: ext_manifest.dependencies.clone(),
        permissions: ext_manifest.permissions.clone(),
        entry_point: ext_manifest
            .entry_points
            .get("init")
            .cloned()
            .unwrap_or_else(|| "init".to_string()),
        hash: ext_manifest.hash.clone(),
        signature: ext_manifest.signature.clone(),
        capabilities: ext_manifest
            .capabilities
            .clone()
            .or_else(|| Some(Vec::new())),
        config_schema: ext_manifest.config_schema.clone(),
    }
}
