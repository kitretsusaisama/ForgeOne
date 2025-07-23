//! # Container Filesystem Module
//!
//! This module provides functionality for managing container filesystems,
//! including overlay mounts, snapshots, and secure volume management.

use crate::dna::ContainerDNA;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Filesystem driver type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FSDriverType {
    /// Overlay filesystem
    Overlay,
    /// Bind mount
    Bind,
    /// Tmpfs
    Tmpfs,
    /// Device mount
    Device,
    /// Custom filesystem
    Custom,
}

impl std::fmt::Display for FSDriverType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FSDriverType::Overlay => write!(f, "overlay"),
            FSDriverType::Bind => write!(f, "bind"),
            FSDriverType::Tmpfs => write!(f, "tmpfs"),
            FSDriverType::Device => write!(f, "device"),
            FSDriverType::Custom => write!(f, "custom"),
        }
    }
}

/// Mount options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountOptions {
    /// Read-only mount
    pub readonly: bool,
    /// Propagation mode (private, shared, slave, unbindable)
    pub propagation: String,
    /// Mount flags
    pub flags: Vec<String>,
    /// Mount options
    pub options: Vec<String>,
    /// Custom mount options
    pub custom: HashMap<String, String>,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            readonly: false,
            propagation: "private".to_string(),
            flags: Vec::new(),
            options: Vec::new(),
            custom: HashMap::new(),
        }
    }
}

/// Volume type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VolumeType {
    /// Named volume
    Named,
    /// Anonymous volume
    Anonymous,
    /// Host path
    HostPath,
    /// Tmpfs
    Tmpfs,
    /// Encrypted volume
    Encrypted,
    /// Custom volume
    Custom,
}

impl std::fmt::Display for VolumeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VolumeType::Named => write!(f, "named"),
            VolumeType::Anonymous => write!(f, "anonymous"),
            VolumeType::HostPath => write!(f, "hostpath"),
            VolumeType::Tmpfs => write!(f, "tmpfs"),
            VolumeType::Encrypted => write!(f, "encrypted"),
            VolumeType::Custom => write!(f, "custom"),
        }
    }
}

/// Volume encryption options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeEncryption {
    /// Encryption algorithm
    pub algorithm: String,
    /// Key ID
    pub key_id: String,
    /// Initialization vector
    pub iv: Option<String>,
    /// Custom encryption options
    pub custom: HashMap<String, String>,
}

/// Volume
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Volume ID
    pub id: String,
    /// Volume name
    pub name: String,
    /// Volume type
    pub volume_type: VolumeType,
    /// Source path (for host path volumes)
    pub source: Option<String>,
    /// Destination path (in container)
    pub destination: String,
    /// Mount options
    pub mount_options: MountOptions,
    /// Volume encryption (for encrypted volumes)
    pub encryption: Option<VolumeEncryption>,
    /// Volume labels
    pub labels: HashMap<String, String>,
    /// Volume creation time
    pub created_at: u64,
    /// Volume size in bytes
    pub size_bytes: Option<u64>,
    /// Custom volume options
    pub custom: HashMap<String, String>,
}

/// Mount
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    /// Mount ID
    pub id: String,
    /// Source path
    pub source: String,
    /// Destination path
    pub destination: String,
    /// Filesystem driver type
    pub driver_type: FSDriverType,
    /// Mount options
    pub options: MountOptions,
    /// Mount creation time
    pub created_at: u64,
    /// Custom mount options
    pub custom: HashMap<String, String>,
}

/// Snapshot type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// Full snapshot
    Full,
    /// Incremental snapshot
    Incremental,
    /// Differential snapshot
    Differential,
    /// Custom snapshot
    Custom,
}

impl std::fmt::Display for SnapshotType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotType::Full => write!(f, "full"),
            SnapshotType::Incremental => write!(f, "incremental"),
            SnapshotType::Differential => write!(f, "differential"),
            SnapshotType::Custom => write!(f, "custom"),
        }
    }
}

/// Snapshot compression type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    /// No compression
    None,
    /// Gzip compression
    Gzip,
    /// Zstd compression
    Zstd,
    /// LZ4 compression
    Lz4,
    /// Custom compression
    Custom,
}

impl std::fmt::Display for CompressionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionType::None => write!(f, "none"),
            CompressionType::Gzip => write!(f, "gzip"),
            CompressionType::Zstd => write!(f, "zstd"),
            CompressionType::Lz4 => write!(f, "lz4"),
            CompressionType::Custom => write!(f, "custom"),
        }
    }
}

/// Snapshot options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotOptions {
    /// Snapshot type
    pub snapshot_type: SnapshotType,
    /// Compression type
    pub compression: CompressionType,
    /// Compression level
    pub compression_level: Option<u32>,
    /// Encryption enabled
    pub encryption_enabled: bool,
    /// Encryption options
    pub encryption: Option<VolumeEncryption>,
    /// Custom snapshot options
    pub custom: HashMap<String, String>,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            snapshot_type: SnapshotType::Full,
            compression: CompressionType::Zstd,
            compression_level: Some(3),
            encryption_enabled: false,
            encryption: None,
            custom: HashMap::new(),
        }
    }
}

/// Snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot ID
    pub id: String,
    /// Container ID
    pub container_id: String,
    /// Snapshot type
    pub snapshot_type: SnapshotType,
    /// Parent snapshot ID (for incremental/differential snapshots)
    pub parent_id: Option<String>,
    /// Snapshot path
    pub path: String,
    /// Snapshot size in bytes
    pub size_bytes: u64,
    /// Snapshot creation time
    pub created_at: u64,
    /// Snapshot options
    pub options: SnapshotOptions,
    /// Snapshot labels
    pub labels: HashMap<String, String>,
    /// Custom snapshot options
    pub custom: HashMap<String, String>,
}

/// Container filesystem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerFS {
    /// Container ID
    pub container_id: String,
    /// Root filesystem path
    pub rootfs_path: String,
    /// Mounts
    pub mounts: Vec<Mount>,
    /// Volumes
    pub volumes: Vec<Volume>,
    /// Snapshots
    pub snapshots: Vec<Snapshot>,
    /// Custom filesystem options
    pub custom: HashMap<String, String>,
}

impl ContainerFS {
    /// Create a new container filesystem
    pub fn new(container_id: &str, rootfs_path: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            rootfs_path: rootfs_path.to_string(),
            mounts: Vec::new(),
            volumes: Vec::new(),
            snapshots: Vec::new(),
            custom: HashMap::new(),
        }
    }

    /// Add a mount
    pub fn add_mount(&mut self, mount: Mount) -> Result<()> {
        // Check if mount already exists
        if self.mounts.iter().any(|m| m.id == mount.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "mount".to_string(),
                id: mount.id.clone(),
            });
        }

        self.mounts.push(mount);
        Ok(())
    }

    /// Remove a mount
    pub fn remove_mount(&mut self, mount_id: &str) -> Result<Mount> {
        let index = self
            .mounts
            .iter()
            .position(|m| m.id == mount_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "mount".to_string(),
                id: mount_id.to_string(),
            })?;

        Ok(self.mounts.remove(index))
    }

    /// Add a volume
    pub fn add_volume(&mut self, volume: Volume) -> Result<()> {
        // Check if volume already exists
        if self.volumes.iter().any(|v| v.id == volume.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "volume".to_string(),
                id: volume.id.clone(),
            });
        }

        self.volumes.push(volume);
        Ok(())
    }

    /// Remove a volume
    pub fn remove_volume(&mut self, volume_id: &str) -> Result<Volume> {
        let index = self
            .volumes
            .iter()
            .position(|v| v.id == volume_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "volume".to_string(),
                id: volume_id.to_string(),
            })?;

        Ok(self.volumes.remove(index))
    }

    /// Add a snapshot
    pub fn add_snapshot(&mut self, snapshot: Snapshot) -> Result<()> {
        // Check if snapshot already exists
        if self.snapshots.iter().any(|s| s.id == snapshot.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "snapshot".to_string(),
                id: snapshot.id.clone(),
            });
        }

        self.snapshots.push(snapshot);
        Ok(())
    }

    /// Remove a snapshot
    pub fn remove_snapshot(&mut self, snapshot_id: &str) -> Result<Snapshot> {
        let index = self
            .snapshots
            .iter()
            .position(|s| s.id == snapshot_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "snapshot".to_string(),
                id: snapshot_id.to_string(),
            })?;

        Ok(self.snapshots.remove(index))
    }

    /// Get a mount by ID
    pub fn get_mount(&self, mount_id: &str) -> Result<&Mount> {
        self.mounts
            .iter()
            .find(|m| m.id == mount_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "mount".to_string(),
                id: mount_id.to_string(),
            })
    }

    /// Get a volume by ID
    pub fn get_volume(&self, volume_id: &str) -> Result<&Volume> {
        self.volumes
            .iter()
            .find(|v| v.id == volume_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "volume".to_string(),
                id: volume_id.to_string(),
            })
    }

    /// Get a snapshot by ID
    pub fn get_snapshot(&self, snapshot_id: &str) -> Result<&Snapshot> {
        self.snapshots
            .iter()
            .find(|s| s.id == snapshot_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "snapshot".to_string(),
                id: snapshot_id.to_string(),
            })
    }

    /// List all mounts
    pub fn list_mounts(&self) -> Vec<&Mount> {
        self.mounts.iter().collect()
    }

    /// List all volumes
    pub fn list_volumes(&self) -> Vec<&Volume> {
        self.volumes.iter().collect()
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Vec<&Snapshot> {
        self.snapshots.iter().collect()
    }
}

/// Filesystem manager
#[derive(Debug)]
pub struct FSManager {
    /// Container filesystems
    container_fs: Arc<RwLock<HashMap<String, ContainerFS>>>,
    /// Base path for container filesystems
    base_path: PathBuf,
}

impl FSManager {
    /// Create a new filesystem manager
    pub fn new(base_path: &Path) -> Self {
        Self {
            container_fs: Arc::new(RwLock::new(HashMap::new())),
            base_path: base_path.to_path_buf(),
        }
    }

    /// Create a container filesystem
    pub fn create_container_fs(&self, container_id: &str, dna: &ContainerDNA) -> Result<PathBuf> {
        let span = ExecutionSpan::new(
            "create_container_fs",
            common::identity::IdentityContext::system(),
        );

        // Create container directory
        let container_path = self.base_path.join(container_id);
        std::fs::create_dir_all(&container_path).map_err(|e| ForgeError::IOError {
            operation: "create_dir".to_string(),
            path: container_path.to_string_lossy().to_string(),
            error: e.to_string(),
        })?;

        // Create rootfs directory
        let rootfs_path = container_path.join("rootfs");
        std::fs::create_dir_all(&rootfs_path).map_err(|e| ForgeError::IOError {
            operation: "create_dir".to_string(),
            path: rootfs_path.to_string_lossy().to_string(),
            error: e.to_string(),
        })?;

        // Create container filesystem
        let container_fs = ContainerFS::new(container_id, rootfs_path.to_string_lossy().as_ref());

        // Add container filesystem
        let mut container_fs_map = self.container_fs.write().map_err(|_| ForgeError::LockError {
            resource: "container_fs".to_string(),
        })?;

        container_fs_map.insert(container_id.to_string(), container_fs);

        Ok(rootfs_path)
    }

    /// Remove a container filesystem
    pub fn remove_container_fs(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_container_fs",
            common::identity::IdentityContext::system(),
        );

        // Remove container filesystem from map
        let mut container_fs_map = self.container_fs.write().map_err(|_| ForgeError::LockError {
            resource: "container_fs".to_string(),
        })?;

        if !container_fs_map.contains_key(container_id) {
            return Err(ForgeError::NotFoundError {
                resource: "container_fs".to_string(),
                id: container_id.to_string(),
            });
        }

        container_fs_map.remove(container_id);

        // Remove container directory
        let container_path = self.base_path.join(container_id);
        std::fs::remove_dir_all(&container_path).map_err(|e| ForgeError::IOError {
            operation: "remove_dir_all".to_string(),
            path: container_path.to_string_lossy().to_string(),
            error: e.to_string(),
        })?;

        Ok(())
    }

    /// Get a container filesystem
    pub fn get_container_fs(&self, container_id: &str) -> Result<ContainerFS> {
        let span = ExecutionSpan::new(
            "get_container_fs",
            common::identity::IdentityContext::system(),
        );

        let container_fs_map = self.container_fs.read().map_err(|_| ForgeError::LockError {
            resource: "container_fs".to_string(),
        })?;

        let container_fs = container_fs_map.get(container_id).ok_or(ForgeError::NotFoundError {
            resource: "container_fs".to_string(),
            id: container_id.to_string(),
        })?;

        Ok(container_fs.clone())
    }

    /// Update a container filesystem
    pub fn update_container_fs(&self, container_fs: ContainerFS) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_container_fs",
            common::identity::IdentityContext::system(),
        );

        let mut container_fs_map = self.container_fs.write().map_err(|_| ForgeError::LockError {
            resource: "container_fs".to_string(),
        })?;

        if !container_fs_map.contains_key(&container_fs.container_id) {
            return Err(ForgeError::NotFoundError {
                resource: "container_fs".to_string(),
                id: container_fs.container_id.clone(),
            });
        }

        container_fs_map.insert(container_fs.container_id.clone(), container_fs);

        Ok(())
    }

    /// Create a mount
    pub fn create_mount(
        &self,
        container_id: &str,
        source: &str,
        destination: &str,
        driver_type: FSDriverType,
        options: MountOptions,
    ) -> Result<Mount> {
        let span = ExecutionSpan::new(
            "create_mount",
            common::identity::IdentityContext::system(),
        );

        // Get container filesystem
        let mut container_fs = self.get_container_fs(container_id)?;

        // Create mount ID
        let mount_id = format!("{}-{}", container_id, uuid::Uuid::new_v4());

        // Create mount
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mount = Mount {
            id: mount_id,
            source: source.to_string(),
            destination: destination.to_string(),
            driver_type,
            options,
            created_at: now,
            custom: HashMap::new(),
        };

        // Add mount to container filesystem
        container_fs.add_mount(mount.clone())?;

        // Update container filesystem
        self.update_container_fs(container_fs)?;

        Ok(mount)
    }

    /// Remove a mount
    pub fn remove_mount(&self, container_id: &str, mount_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_mount",
            common::identity::IdentityContext::system(),
        );

        // Get container filesystem
        let mut container_fs = self.get_container_fs(container_id)?;

        // Remove mount
        container_fs.remove_mount(mount_id)?;

        // Update container filesystem
        self.update_container_fs(container_fs)?;

        Ok(())
    }

    /// Create a volume
    pub fn create_volume(
        &self,
        container_id: &str,
        name: &str,
        volume_type: VolumeType,
        source: Option<&str>,
        destination: &str,
        mount_options: MountOptions,
        encryption: Option<VolumeEncryption>,
    ) -> Result<Volume> {
        let span = ExecutionSpan::new(
            "create_volume",
            common::identity::IdentityContext::system(),
        );

        // Get container filesystem
        let mut container_fs = self.get_container_fs(container_id)?;

        // Create volume ID
        let volume_id = format!("{}-{}", container_id, uuid::Uuid::new_v4());

        // Create volume
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let volume = Volume {
            id: volume_id,
            name: name.to_string(),
            volume_type,
            source: source.map(|s| s.to_string()),
            destination: destination.to_string(),
            mount_options,
            encryption,
            labels: HashMap::new(),
            created_at: now,
            size_bytes: None,
            custom: HashMap::new(),
        };

        // Add volume to container filesystem
        container_fs.add_volume(volume.clone())?;

        // Update container filesystem
        self.update_container_fs(container_fs)?;

        Ok(volume)
    }

    /// Remove a volume
    pub fn remove_volume(&self, container_id: &str, volume_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_volume",
            common::identity::IdentityContext::system(),
        );

        // Get container filesystem
        let mut container_fs = self.get_container_fs(container_id)?;

        // Remove volume
        container_fs.remove_volume(volume_id)?;

        // Update container filesystem
        self.update_container_fs(container_fs)?;

        Ok(())
    }

    /// Create a snapshot
    pub fn create_snapshot(
        &self,
        container_id: &str,
        snapshot_type: SnapshotType,
        parent_id: Option<&str>,
        options: SnapshotOptions,
    ) -> Result<Snapshot> {
        let span = ExecutionSpan::new(
            "create_snapshot",
            common::identity::IdentityContext::system(),
        );

        // Get container filesystem
        let mut container_fs = self.get_container_fs(container_id)?;

        // Create snapshot ID
        let snapshot_id = format!("{}-{}", container_id, uuid::Uuid::new_v4());

        // Create snapshot path
        let snapshot_path = self
            .base_path
            .join(container_id)
            .join("snapshots")
            .join(&snapshot_id);

        // Create snapshot directory
        std::fs::create_dir_all(snapshot_path.parent().unwrap()).map_err(|e| ForgeError::IOError {
            operation: "create_dir".to_string(),
            path: snapshot_path.parent().unwrap().to_string_lossy().to_string(),
            error: e.to_string(),
        })?;

        // Create snapshot
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let snapshot = Snapshot {
            id: snapshot_id,
            container_id: container_id.to_string(),
            snapshot_type,
            parent_id: parent_id.map(|s| s.to_string()),
            path: snapshot_path.to_string_lossy().to_string(),
            size_bytes: 0,
            created_at: now,
            options,
            labels: HashMap::new(),
            custom: HashMap::new(),
        };

        // Add snapshot to container filesystem
        container_fs.add_snapshot(snapshot.clone())?;

        // Update container filesystem
        self.update_container_fs(container_fs)?;

        Ok(snapshot)
    }

    /// Remove a snapshot
    pub fn remove_snapshot(&self, container_id: &str, snapshot_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_snapshot",
            common::identity::IdentityContext::system(),
        );

        // Get container filesystem
        let mut container_fs = self.get_container_fs(container_id)?;

        // Get snapshot
        let snapshot = container_fs.get_snapshot(snapshot_id)?.clone();

        // Remove snapshot file
        std::fs::remove_file(&snapshot.path).map_err(|e| ForgeError::IOError {
            operation: "remove_file".to_string(),
            path: snapshot.path.clone(),
            error: e.to_string(),
        })?;

        // Remove snapshot
        container_fs.remove_snapshot(snapshot_id)?;

        // Update container filesystem
        self.update_container_fs(container_fs)?;

        Ok(())
    }

    /// List container filesystems
    pub fn list_container_fs(&self) -> Result<Vec<ContainerFS>> {
        let span = ExecutionSpan::new(
            "list_container_fs",
            common::identity::IdentityContext::system(),
        );

        let container_fs_map = self.container_fs.read().map_err(|_| ForgeError::LockError {
            resource: "container_fs".to_string(),
        })?;

        Ok(container_fs_map.values().cloned().collect())
    }
}

/// Global filesystem manager instance
static mut FS_MANAGER: Option<FSManager> = None;

/// Initialize the filesystem manager
pub fn init(base_path: &Path) -> Result<()> {
    let span = ExecutionSpan::new(
        "init_fs_manager",
        common::identity::IdentityContext::system(),
    );

    // Create base directory
    std::fs::create_dir_all(base_path).map_err(|e| ForgeError::IOError {
        operation: "create_dir".to_string(),
        path: base_path.to_string_lossy().to_string(),
        error: e.to_string(),
    })?;

    // Create filesystem manager
    let fs_manager = FSManager::new(base_path);

    // Store the filesystem manager
    unsafe {
        if FS_MANAGER.is_none() {
            FS_MANAGER = Some(fs_manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "fs_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the filesystem manager
pub fn get_fs_manager() -> Result<&'static FSManager> {
    unsafe {
        match &FS_MANAGER {
            Some(fs_manager) => Ok(fs_manager),
            None => Err(ForgeError::UninitializedError {
                component: "fs_manager".to_string(),
            }),
        }
    }
}

/// Create a container filesystem
pub fn create_container_fs(container_id: &str, dna: &ContainerDNA) -> Result<PathBuf> {
    let fs_manager = get_fs_manager()?;
    fs_manager.create_container_fs(container_id, dna)
}

/// Remove a container filesystem
pub fn remove_container_fs(container_id: &str) -> Result<()> {
    let fs_manager = get_fs_manager()?;
    fs_manager.remove_container_fs(container_id)
}

/// Get a container filesystem
pub fn get_container_fs(container_id: &str) -> Result<ContainerFS> {
    let fs_manager = get_fs_manager()?;
    fs_manager.get_container_fs(container_id)
}

/// Create a mount
pub fn create_mount(
    container_id: &str,
    source: &str,
    destination: &str,
    driver_type: FSDriverType,
    options: MountOptions,
) -> Result<Mount> {
    let fs_manager = get_fs_manager()?;
    fs_manager.create_mount(container_id, source, destination, driver_type, options)
}

/// Remove a mount
pub fn remove_mount(container_id: &str, mount_id: &str) -> Result<()> {
    let fs_manager = get_fs_manager()?;
    fs_manager.remove_mount(container_id, mount_id)
}

/// Create a volume
pub fn create_volume(
    container_id: &str,
    name: &str,
    volume_type: VolumeType,
    source: Option<&str>,
    destination: &str,
    mount_options: MountOptions,
    encryption: Option<VolumeEncryption>,
) -> Result<Volume> {
    let fs_manager = get_fs_manager()?;
    fs_manager.create_volume(
        container_id,
        name,
        volume_type,
        source,
        destination,
        mount_options,
        encryption,
    )
}

/// Remove a volume
pub fn remove_volume(container_id: &str, volume_id: &str) -> Result<()> {
    let fs_manager = get_fs_manager()?;
    fs_manager.remove_volume(container_id, volume_id)
}

/// Create a snapshot
pub fn create_snapshot(
    container_id: &str,
    snapshot_type: SnapshotType,
    parent_id: Option<&str>,
    options: SnapshotOptions,
) -> Result<Snapshot> {
    let fs_manager = get_fs_manager()?;
    fs_manager.create_snapshot(container_id, snapshot_type, parent_id, options)
}

/// Remove a snapshot
pub fn remove_snapshot(container_id: &str, snapshot_id: &str) -> Result<()> {
    let fs_manager = get_fs_manager()?;
    fs_manager.remove_snapshot(container_id, snapshot_id)
}

/// List container filesystems
pub fn list_container_fs() -> Result<Vec<ContainerFS>> {
    let fs_manager = get_fs_manager()?;
    fs_manager.list_container_fs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs_manager() {
        // Create temporary directory
        let temp_dir = tempfile::tempdir().unwrap();
        let base_path = temp_dir.path();

        // Initialize filesystem manager
        init(base_path).unwrap();
        let fs_manager = get_fs_manager().unwrap();

        // Create container DNA
        let dna = ContainerDNA {
            id: "test-container".to_string(),
            fingerprint: "test-fingerprint".to_string(),
            resource_limits: crate::dna::ResourceLimits::default(),
        };

        // Create container filesystem
        let rootfs_path = fs_manager.create_container_fs("test-container", &dna).unwrap();
        assert!(rootfs_path.exists());

        // Get container filesystem
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.container_id, "test-container");
        assert_eq!(container_fs.rootfs_path, rootfs_path.to_string_lossy());

        // Create mount
        let mount_options = MountOptions::default();
        let mount = fs_manager
            .create_mount(
                "test-container",
                "/host/path",
                "/container/path",
                FSDriverType::Bind,
                mount_options,
            )
            .unwrap();

        // Get container filesystem with mount
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.mounts.len(), 1);
        assert_eq!(container_fs.mounts[0].id, mount.id);

        // Create volume
        let volume_options = MountOptions::default();
        let volume = fs_manager
            .create_volume(
                "test-container",
                "test-volume",
                VolumeType::Named,
                Some("/host/volume"),
                "/container/volume",
                volume_options,
                None,
            )
            .unwrap();

        // Get container filesystem with volume
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.volumes.len(), 1);
        assert_eq!(container_fs.volumes[0].id, volume.id);

        // Create snapshot
        let snapshot_options = SnapshotOptions::default();
        let snapshot = fs_manager
            .create_snapshot(
                "test-container",
                SnapshotType::Full,
                None,
                snapshot_options,
            )
            .unwrap();

        // Get container filesystem with snapshot
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.snapshots.len(), 1);
        assert_eq!(container_fs.snapshots[0].id, snapshot.id);

        // Remove snapshot
        fs_manager
            .remove_snapshot("test-container", &snapshot.id)
            .unwrap();

        // Get container filesystem without snapshot
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.snapshots.len(), 0);

        // Remove volume
        fs_manager
            .remove_volume("test-container", &volume.id)
            .unwrap();

        // Get container filesystem without volume
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.volumes.len(), 0);

        // Remove mount
        fs_manager.remove_mount("test-container", &mount.id).unwrap();

        // Get container filesystem without mount
        let container_fs = fs_manager.get_container_fs("test-container").unwrap();
        assert_eq!(container_fs.mounts.len(), 0);

        // Remove container filesystem
        fs_manager.remove_container_fs("test-container").unwrap();

        // Check container filesystem is removed
        let result = fs_manager.get_container_fs("test-container");
        assert!(result.is_err());
    }
}