//! # Container State Module
//!
//! This module provides functionality for managing container state persistence,
//! including checkpointing, restoration, and state synchronization.

use crate::lifecycle::ContainerState;
use crate::registry::ContainerRegistration;
use common::crypto::generate_id;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Container checkpoint type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckpointType {
    /// Full checkpoint
    Full,
    /// Incremental checkpoint
    Incremental,
    /// Memory-only checkpoint
    MemoryOnly,
    /// Filesystem-only checkpoint
    FilesystemOnly,
}

impl std::fmt::Display for CheckpointType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointType::Full => write!(f, "full"),
            CheckpointType::Incremental => write!(f, "incremental"),
            CheckpointType::MemoryOnly => write!(f, "memory-only"),
            CheckpointType::FilesystemOnly => write!(f, "filesystem-only"),
        }
    }
}

/// Container checkpoint options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointOptions {
    /// Checkpoint type
    pub checkpoint_type: CheckpointType,
    /// Whether to leave the container running after checkpointing
    pub leave_running: bool,
    /// Whether to include container's filesystem in the checkpoint
    pub include_filesystem: bool,
    /// Whether to include container's network connections in the checkpoint
    pub include_network: bool,
    /// Additional options
    pub options: HashMap<String, String>,
}

impl Default for CheckpointOptions {
    fn default() -> Self {
        Self {
            checkpoint_type: CheckpointType::Full,
            leave_running: false,
            include_filesystem: true,
            include_network: true,
            options: HashMap::new(),
        }
    }
}

/// Container checkpoint metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointMetadata {
    /// Checkpoint ID
    pub id: String,
    /// Container ID
    pub container_id: String,
    /// Checkpoint type
    pub checkpoint_type: CheckpointType,
    /// Checkpoint creation time in seconds since epoch
    pub created_at: u64,
    /// Container status at checkpoint time
    pub container_status: ContainerState,
    /// Whether the checkpoint includes container's filesystem
    pub includes_filesystem: bool,
    /// Whether the checkpoint includes container's network connections
    pub includes_network: bool,
    /// Checkpoint size in bytes
    pub size: u64,
    /// Checkpoint description
    pub description: Option<String>,
    /// Checkpoint labels
    pub labels: HashMap<String, String>,
}

/// Container checkpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint metadata
    pub metadata: CheckpointMetadata,
    /// Checkpoint path
    pub path: PathBuf,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(
        id: &str,
        container_id: &str,
        checkpoint_type: CheckpointType,
        container_status: ContainerState,
        includes_filesystem: bool,
        includes_network: bool,
        path: PathBuf,
        size: u64,
        description: Option<String>,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = CheckpointMetadata {
            id: id.to_string(),
            container_id: container_id.to_string(),
            checkpoint_type,
            created_at: now,
            container_status,
            includes_filesystem,
            includes_network,
            size,
            description,
            labels: HashMap::new(),
        };

        Self { metadata, path }
    }

    /// Add a label
    pub fn add_label(&mut self, key: &str, value: &str) {
        self.metadata
            .labels
            .insert(key.to_string(), value.to_string());
    }

    /// Remove a label
    pub fn remove_label(&mut self, key: &str) -> Option<String> {
        self.metadata.labels.remove(key)
    }
}

/// Container restore options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreOptions {
    /// Whether to restore container's filesystem
    pub restore_filesystem: bool,
    /// Whether to restore container's network connections
    pub restore_network: bool,
    /// Whether to start the container after restoration
    pub start_after_restore: bool,
    /// Additional options
    pub options: HashMap<String, String>,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            restore_filesystem: true,
            restore_network: true,
            start_after_restore: true,
            options: HashMap::new(),
        }
    }
}

/// State manager
#[derive(Debug)]
pub struct StateManager {
    /// Base directory for state storage
    base_dir: PathBuf,
    /// Map of container ID to checkpoints
    checkpoints: Arc<RwLock<HashMap<String, Vec<Checkpoint>>>>,
}

impl StateManager {
    /// Create a new state manager
    pub fn new(base_dir: PathBuf) -> Result<Self> {
        // Create base directory if it doesn't exist
        if !base_dir.exists() {
            fs::create_dir_all(&base_dir).map_err(|e| {
                ForgeError::IoError(format!("create_dir {}: {}", base_dir.to_string_lossy(), e))
            })?;
        }

        Ok(Self {
            base_dir,
            checkpoints: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a checkpoint
    pub fn create_checkpoint(
        &self,
        container_id: &str,
        options: CheckpointOptions,
        description: Option<String>,
    ) -> Result<Checkpoint> {
        let span = ExecutionSpan::new(
            "create_checkpoint",
            common::identity::IdentityContext::system(),
        );

        // Get container status
        let container_status = crate::lifecycle::get_container_status(container_id)?;

        // Generate checkpoint ID
        let checkpoint_id = format!(
            "cp_{}_{}_{}",
            container_id,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            generate_id(container_id, 8)
        );

        // Create checkpoint directory
        let checkpoint_dir = self.base_dir.join(container_id).join(&checkpoint_id);
        fs::create_dir_all(&checkpoint_dir).map_err(|e| {
            ForgeError::IoError(format!(
                "create_dir {}: {}",
                checkpoint_dir.to_string_lossy(),
                e
            ))
        })?;

        // TODO: Implement actual checkpoint creation logic
        // This would involve serializing container state, memory, filesystem, etc.

        // For now, we'll just create a placeholder file
        let placeholder_file = checkpoint_dir.join("checkpoint.meta");
        fs::write(&placeholder_file, "checkpoint placeholder").map_err(|e| {
            ForgeError::IoError(format!(
                "write {}: {}",
                placeholder_file.to_string_lossy(),
                e
            ))
        })?;

        // Get checkpoint size (in a real implementation, this would be the size of all checkpoint files)
        let size = 1024; // Placeholder size

        // Create checkpoint object
        let checkpoint = Checkpoint::new(
            &checkpoint_id,
            container_id,
            options.checkpoint_type,
            container_status,
            options.include_filesystem,
            options.include_network,
            checkpoint_dir,
            size,
            description,
        );

        // Add checkpoint to map
        let mut checkpoints = self
            .checkpoints
            .write()
            .map_err(|_| ForgeError::InternalError("checkpoints lock poisoned".to_string()))?;

        let container_checkpoints = checkpoints
            .entry(container_id.to_string())
            .or_insert_with(Vec::new);

        container_checkpoints.push(checkpoint.clone());

        Ok(checkpoint)
    }

    /// Remove a checkpoint
    pub fn remove_checkpoint(&self, container_id: &str, checkpoint_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_checkpoint",
            common::identity::IdentityContext::system(),
        );

        // Get checkpoints
        let mut checkpoints = self
            .checkpoints
            .write()
            .map_err(|_| ForgeError::InternalError("checkpoints lock poisoned".to_string()))?;

        let container_checkpoints = checkpoints
            .get_mut(container_id)
            .ok_or(ForgeError::NotFound(format!("container: {}", container_id)))?;

        // Find checkpoint index
        let checkpoint_index = container_checkpoints
            .iter()
            .position(|cp| cp.metadata.id == checkpoint_id)
            .ok_or(ForgeError::NotFound(format!(
                "checkpoint: {}",
                checkpoint_id
            )))?;

        // Get checkpoint
        let checkpoint = container_checkpoints.remove(checkpoint_index);

        // Remove checkpoint directory
        if checkpoint.path.exists() {
            fs::remove_dir_all(&checkpoint.path).map_err(|e| {
                ForgeError::IoError(format!(
                    "remove_dir_all {}: {}",
                    checkpoint.path.to_string_lossy(),
                    e
                ))
            })?;
        }

        // Remove container from checkpoints if it has no checkpoints
        if container_checkpoints.is_empty() {
            checkpoints.remove(container_id);
        }

        Ok(())
    }

    /// Get a checkpoint
    pub fn get_checkpoint(&self, container_id: &str, checkpoint_id: &str) -> Result<Checkpoint> {
        let span = ExecutionSpan::new(
            "get_checkpoint",
            common::identity::IdentityContext::system(),
        );

        // Get checkpoints
        let checkpoints = self
            .checkpoints
            .read()
            .map_err(|_| ForgeError::InternalError("checkpoints lock poisoned".to_string()))?;

        let container_checkpoints = checkpoints
            .get(container_id)
            .ok_or(ForgeError::NotFound(format!("container: {}", container_id)))?;

        // Find checkpoint
        let checkpoint = container_checkpoints
            .iter()
            .find(|cp| cp.metadata.id == checkpoint_id)
            .ok_or(ForgeError::NotFound(format!(
                "checkpoint: {}",
                checkpoint_id
            )))?;

        Ok(checkpoint.clone())
    }

    /// List checkpoints for a container
    pub fn list_checkpoints(&self, container_id: &str) -> Result<Vec<Checkpoint>> {
        let span = ExecutionSpan::new(
            "list_checkpoints",
            common::identity::IdentityContext::system(),
        );

        // Get checkpoints
        let checkpoints = self
            .checkpoints
            .read()
            .map_err(|_| ForgeError::InternalError("checkpoints lock poisoned".to_string()))?;

        let container_checkpoints = checkpoints
            .get(container_id)
            .ok_or(ForgeError::NotFound(format!("container: {}", container_id)))?;

        Ok(container_checkpoints.clone())
    }

    /// Restore a container from a checkpoint
    pub fn restore_container(
        &self,
        container_id: &str,
        checkpoint_id: &str,
        options: RestoreOptions,
    ) -> Result<()> {
        let span = ExecutionSpan::new(
            "restore_container",
            common::identity::IdentityContext::system(),
        );

        // Get checkpoint
        let checkpoint = self.get_checkpoint(container_id, checkpoint_id)?;

        // TODO: Implement actual container restoration logic
        // This would involve deserializing container state, memory, filesystem, etc.

        // Start container if requested
        if options.start_after_restore {
            crate::lifecycle::start_container(container_id)?;
        }

        Ok(())
    }

    /// Clean up container checkpoints
    pub fn cleanup_container(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "cleanup_container",
            common::identity::IdentityContext::system(),
        );

        // Get checkpoints
        let mut checkpoints = self
            .checkpoints
            .write()
            .map_err(|_| ForgeError::InternalError("checkpoints lock poisoned".to_string()))?;

        // Remove container from checkpoints
        if let Some(container_checkpoints) = checkpoints.remove(container_id) {
            // Remove checkpoint directories
            for checkpoint in container_checkpoints {
                if checkpoint.path.exists() {
                    let _ = fs::remove_dir_all(&checkpoint.path);
                }
            }

            // Remove container directory
            let container_dir = self.base_dir.join(container_id);
            if container_dir.exists() {
                let _ = fs::remove_dir_all(&container_dir);
            }
        }

        Ok(())
    }

    /// Load checkpoints from disk
    pub fn load_checkpoints(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "load_checkpoints",
            common::identity::IdentityContext::system(),
        );

        // Check if base directory exists
        if !self.base_dir.exists() {
            return Ok(());
        }

        // Iterate over container directories
        for container_entry in fs::read_dir(&self.base_dir).map_err(|e| {
            ForgeError::IoError(format!(
                "read_dir {}: {}",
                self.base_dir.to_string_lossy(),
                e
            ))
        })? {
            let container_entry = container_entry.map_err(|e| {
                ForgeError::IoError(format!(
                    "read_dir_entry {}: {}",
                    self.base_dir.to_string_lossy(),
                    e
                ))
            })?;

            let container_path = container_entry.path();
            if !container_path.is_dir() {
                continue;
            }

            let container_id = container_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(ForgeError::InternalError(format!(
                    "Invalid container directory name: {}",
                    container_path.display()
                )))?;

            // Iterate over checkpoint directories
            let mut container_checkpoints = Vec::new();
            for checkpoint_entry in fs::read_dir(&container_path).map_err(|e| {
                ForgeError::IoError(format!(
                    "read_dir {}: {}",
                    container_path.to_string_lossy(),
                    e
                ))
            })? {
                let checkpoint_entry = checkpoint_entry.map_err(|e| {
                    ForgeError::IoError(format!(
                        "read_dir_entry {}: {}",
                        container_path.to_string_lossy(),
                        e
                    ))
                })?;

                let checkpoint_path = checkpoint_entry.path();
                if !checkpoint_path.is_dir() {
                    continue;
                }

                let checkpoint_id = checkpoint_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(ForgeError::InternalError(format!(
                        "Invalid checkpoint directory name: {}",
                        checkpoint_path.display()
                    )))?;

                // Load checkpoint metadata
                let metadata_path = checkpoint_path.join("checkpoint.meta");
                if !metadata_path.exists() {
                    // Skip checkpoints without metadata
                    continue;
                }

                // TODO: In a real implementation, we would deserialize the checkpoint metadata
                // For now, we'll create a placeholder checkpoint

                let checkpoint = Checkpoint::new(
                    checkpoint_id,
                    container_id,
                    CheckpointType::Full,
                    ContainerState::Stopping,
                    true,
                    true,
                    checkpoint_path.clone(),
                    1024, // Placeholder size
                    None,
                );

                container_checkpoints.push(checkpoint);
            }

            // Add container checkpoints to map
            if !container_checkpoints.is_empty() {
                let mut checkpoints = self.checkpoints.write().map_err(|_| {
                    ForgeError::InternalError("checkpoints lock poisoned".to_string())
                })?;

                checkpoints.insert(container_id.to_string(), container_checkpoints);
            }
        }

        Ok(())
    }
}

/// Global state manager instance
static mut STATE_MANAGER: Option<StateManager> = None;

/// Initialize the state manager
pub fn init(base_dir: &Path) -> Result<()> {
    let span = ExecutionSpan::new(
        "init_state_manager",
        common::identity::IdentityContext::system(),
    );

    // Create state manager
    let manager = StateManager::new(base_dir.to_path_buf())?;

    // Load checkpoints
    manager.load_checkpoints()?;

    // Store the state manager
    unsafe {
        if STATE_MANAGER.is_none() {
            STATE_MANAGER = Some(manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "state_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the state manager
pub fn get_state_manager() -> Result<&'static StateManager> {
    unsafe {
        match &STATE_MANAGER {
            Some(manager) => Ok(manager),
            None => Err(ForgeError::InternalError(
                "state_manager not initialized".to_string(),
            )),
        }
    }
}

/// Create a checkpoint
pub fn create_checkpoint(
    container_id: &str,
    options: CheckpointOptions,
    description: Option<String>,
) -> Result<Checkpoint> {
    let manager = get_state_manager()?;
    manager.create_checkpoint(container_id, options, description)
}

/// Remove a checkpoint
pub fn remove_checkpoint(container_id: &str, checkpoint_id: &str) -> Result<()> {
    let manager = get_state_manager()?;
    manager.remove_checkpoint(container_id, checkpoint_id)
}

/// Get a checkpoint
pub fn get_checkpoint(container_id: &str, checkpoint_id: &str) -> Result<Checkpoint> {
    let manager = get_state_manager()?;
    manager.get_checkpoint(container_id, checkpoint_id)
}

/// List checkpoints for a container
pub fn list_checkpoints(container_id: &str) -> Result<Vec<Checkpoint>> {
    let manager = get_state_manager()?;
    manager.list_checkpoints(container_id)
}

/// Restore a container from a checkpoint
pub fn restore_container(
    container_id: &str,
    checkpoint_id: &str,
    options: RestoreOptions,
) -> Result<()> {
    let manager = get_state_manager()?;
    manager.restore_container(container_id, checkpoint_id, options)
}

/// Clean up container checkpoints
pub fn cleanup_container(container_id: &str) -> Result<()> {
    let manager = get_state_manager()?;
    manager.cleanup_container(container_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_state_manager() {
        // Create temporary directory for state storage
        let temp_dir = tempdir().unwrap();
        let base_dir = temp_dir.path().to_path_buf();

        // Initialize state manager
        init(base_dir.as_path()).unwrap();
        let manager = get_state_manager().unwrap();

        // Mock container ID
        let container_id = "test-container";

        // Create checkpoint options
        let options = CheckpointOptions {
            checkpoint_type: CheckpointType::Full,
            leave_running: true,
            include_filesystem: true,
            include_network: true,
            options: HashMap::new(),
        };

        // Create checkpoint
        let checkpoint = manager
            .create_checkpoint(container_id, options, Some("Test checkpoint".to_string()))
            .unwrap();

        // Get checkpoint
        let retrieved_checkpoint = manager
            .get_checkpoint(container_id, &checkpoint.metadata.id)
            .unwrap();

        assert_eq!(retrieved_checkpoint.metadata.id, checkpoint.metadata.id);
        assert_eq!(retrieved_checkpoint.metadata.container_id, container_id);
        assert_eq!(
            retrieved_checkpoint.metadata.checkpoint_type,
            CheckpointType::Full
        );

        // List checkpoints
        let checkpoints = manager.list_checkpoints(container_id).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].metadata.id, checkpoint.metadata.id);

        // Remove checkpoint
        manager
            .remove_checkpoint(container_id, &checkpoint.metadata.id)
            .unwrap();

        // Check checkpoint is removed
        let result = manager.get_checkpoint(container_id, &checkpoint.metadata.id);
        assert!(result.is_err());
    }
}
