//! Loader module for the ForgeOne Plugin Manager
//!
//! Provides functionality for loading plugins from files and packages.

use crate::attestation::verify_plugin;
use crate::plugin::{PluginInstance, PluginManifest};
use crate::runtime::{EngineType, PluginContext, PluginRuntime};
use common::error::{ForgeError, Result};
use common::identity::IdentityContext as Identity;
use common::model::IdentityContext as ModelIdentityContext;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Loads a plugin from a .forgepkg file
///
/// # Arguments
///
/// * `path` - Path to the .forgepkg file
/// * `identity` - Identity to use for verification
///
/// # Returns
///
/// * `Ok(PluginInstance)` if the plugin was loaded successfully
/// * `Err(ForgeError)` if loading fails
pub fn load_plugin_from_file<P: AsRef<Path>>(
    path: P,
    identity: Identity,
) -> Result<PluginInstance> {
    let path = path.as_ref();

    // Check if the file exists
    if !path.exists() {
        return Err(ForgeError::IoError(format!(
            "Plugin file does not exist: {}",
            path.display()
        )));
    }

    // Check if the file has the correct extension
    if path.extension().and_then(|ext| ext.to_str()) != Some("forgepkg") {
        return Err(ForgeError::ValidationError {
            field: "file extension".to_string(),
            rule: "forgepkg".to_string(),
            value: format!("Invalid plugin file extension: {}", path.display()),
            suggestions: vec![],
        });
    }

    // Extract the plugin package
    let temp_dir = extract_plugin_package(path)?;

    // Read the manifest
    let manifest_path = temp_dir.join("manifest.json");
    let manifest = read_manifest(&manifest_path)?;

    let hash = manifest
        .hash
        .as_deref()
        .ok_or_else(|| ForgeError::ValidationError {
            field: "hash".to_string(),
            rule: "present".to_string(),
            value: "Plugin manifest missing hash".to_string(),
            suggestions: vec![],
        })?;
    let signature = manifest
        .signature
        .as_deref()
        .ok_or_else(|| ForgeError::ValidationError {
            field: "signature".to_string(),
            rule: "present".to_string(),
            value: "Plugin manifest missing signature".to_string(),
            suggestions: vec![],
        })?;

    let model_identity: &ModelIdentityContext =
        unsafe { &*(std::ptr::addr_of!(identity) as *const ModelIdentityContext) };
    verify_plugin(
        path,
        hash,
        &base64::decode(signature).map_err(|e| ForgeError::ValidationError {
            field: "signature".to_string(),
            rule: "base64".to_string(),
            value: format!("Invalid signature encoding: {}", e),
            suggestions: vec![],
        })?,
        model_identity,
    )?;

    let engine_type = EngineType::Wasmtime; // or Wasmer, depending on what you're running
    let context = PluginContext::new(
        Uuid::new_v4(),
        manifest.name.clone(),
        Arc::new(identity.clone()),
    );
    // Use the provided identity (already of type IdentityContext)
    // Remove the incorrect IdentityContext::new(..) line
    // Remove the incorrect manifest and source_path placeholder lines
    // 2. Create runtime
    let runtime = PluginRuntime::new(engine_type, context);
    // 3. Create instance
    let instance = PluginInstance::new(manifest, runtime, path.to_path_buf(), identity);

    Ok(instance)
}

/// Extracts a plugin package to a temporary directory
///
/// # Arguments
///
/// * `path` - Path to the .forgepkg file
///
/// # Returns
///
/// * `Ok(PathBuf)` - Path to the temporary directory
/// * `Err(ForgeError)` if extraction fails
fn extract_plugin_package<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path = path.as_ref();

    // Create a temporary directory
    let temp_dir = std::env::temp_dir().join(format!(
        "forgepkg-{}",
        Uuid::new_v4().to_string().replace("-", "")
    ));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| ForgeError::IoError(format!("Failed to create temporary directory: {}", e)))?;

    // Read the package file
    let package_data = std::fs::read(path)
        .map_err(|e| ForgeError::IoError(format!("Failed to read plugin package: {}", e)))?;

    // Extract the package (assuming it's a tar.gz file)
    let tar_gz = std::io::Cursor::new(package_data);
    let tar = flate2::read::GzDecoder::new(tar_gz);
    let mut archive = tar::Archive::new(tar);
    archive
        .unpack(&temp_dir)
        .map_err(|e| ForgeError::IoError(format!("Failed to extract plugin package: {}", e)))?;

    Ok(temp_dir)
}

/// Reads a plugin manifest from a file
///
/// # Arguments
///
/// * `path` - Path to the manifest.json file
///
/// # Returns
///
/// * `Ok(PluginManifest)` if the manifest was read successfully
/// * `Err(ForgeError)` if reading fails
fn read_manifest<P: AsRef<Path>>(path: P) -> Result<PluginManifest> {
    let path = path.as_ref();

    // Check if the file exists
    if !path.exists() {
        return Err(ForgeError::IoError(format!(
            "Manifest file does not exist: {}",
            path.display()
        )));
    }

    // Read the manifest file
    let manifest_data = std::fs::read_to_string(path)
        .map_err(|e| ForgeError::IoError(format!("Failed to read manifest file: {}", e)))?;

    // Parse the manifest
    let manifest: PluginManifest =
        serde_json::from_str(&manifest_data).map_err(|e| ForgeError::ValidationError {
            field: "manifest".to_string(),
            rule: "parse".to_string(),
            value: format!("Failed to parse manifest: {}", e),
            suggestions: vec![],
        })?;

    Ok(manifest)
}

pub mod forgepkg {
    pub use super::load_plugin_from_file as load_plugin;
}
