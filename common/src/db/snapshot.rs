//! # Database snapshot module for ForgeOne
//!
//! This module provides functionality for creating and managing database snapshots,
//! enabling point-in-time recovery and backup capabilities.

use crate::db::DbOptions;
use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Snapshot manager
pub struct SnapshotManager {
    /// Base directory for snapshots
    base_dir: PathBuf,

    /// Snapshot metadata
    snapshots: RwLock<HashMap<String, SnapshotMetadata>>,

    /// Automatic snapshot schedule
    schedule: RwLock<Option<SnapshotSchedule>>,

    /// Last automatic snapshot time
    last_auto_snapshot: Mutex<Option<SystemTime>>,
}

/// Global snapshot manager
static SNAPSHOT_MANAGER: RwLock<Option<Arc<SnapshotManager>>> = RwLock::new(None);

/// Initialize snapshot manager
pub fn init_snapshot_manager(base_dir: &Path) -> Result<()> {
    // Create snapshots directory
    let snapshots_dir = base_dir.join("snapshots");
    fs::create_dir_all(&snapshots_dir).map_err(|e| ForgeError::IoError(e.to_string()))?;

    // Create manager
    let manager = SnapshotManager {
        base_dir: snapshots_dir,
        snapshots: RwLock::new(HashMap::new()),
        schedule: RwLock::new(None),
        last_auto_snapshot: Mutex::new(None),
    };

    // Load existing snapshots
    load_snapshots(&manager)?;

    // Store manager
    *SNAPSHOT_MANAGER.write().unwrap() = Some(Arc::new(manager));

    Ok(())
}

/// Get snapshot manager
pub fn get_snapshot_manager() -> Result<Arc<SnapshotManager>> {
    match SNAPSHOT_MANAGER.read().unwrap().as_ref() {
        Some(manager) => Ok(manager.clone()),
        None => Err(ForgeError::ConfigError(
            "Snapshot manager not initialized".to_string(),
        )),
    }
}

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Snapshot ID
    pub id: String,

    /// Snapshot name
    pub name: String,

    /// Snapshot description
    pub description: Option<String>,

    /// Creation timestamp
    pub created_at: String,

    /// Creator identity
    pub created_by: IdentityContext,

    /// Snapshot type
    pub snapshot_type: SnapshotType,

    /// Database size in bytes
    pub size_bytes: u64,

    /// Checksum
    pub checksum: String,

    /// Tags
    pub tags: Vec<String>,

    /// Retention policy
    pub retention: Option<RetentionPolicy>,
}

/// Snapshot type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// Full snapshot
    Full,

    /// Incremental snapshot
    Incremental,

    /// Differential snapshot
    Differential,
}

/// Retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Expiration date
    pub expires_at: Option<String>,

    /// Keep forever
    pub keep_forever: bool,

    /// Minimum snapshots to keep
    pub min_snapshots: Option<usize>,
}

/// Snapshot schedule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSchedule {
    /// Schedule enabled
    pub enabled: bool,

    /// Interval in minutes
    pub interval_minutes: u64,

    /// Retention policy
    pub retention: RetentionPolicy,

    /// Snapshot type
    pub snapshot_type: SnapshotType,

    /// Tags
    pub tags: Vec<String>,
}

/// Load existing snapshots
fn load_snapshots(manager: &SnapshotManager) -> Result<()> {
    let metadata_dir = manager.base_dir.join("metadata");

    // Create metadata directory if it doesn't exist
    if !metadata_dir.exists() {
        fs::create_dir_all(&metadata_dir).map_err(|e| ForgeError::IoError(e.to_string()))?;
        return Ok(());
    }

    // Read metadata files
    let entries = fs::read_dir(&metadata_dir).map_err(|e| ForgeError::IoError(e.to_string()))?;

    let mut snapshots = HashMap::new();

    for entry in entries {
        let entry = entry.map_err(|e| ForgeError::IoError(e.to_string()))?;
        let path = entry.path();

        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            // Read metadata file
            let metadata_json =
                fs::read_to_string(&path).map_err(|e| ForgeError::IoError(e.to_string()))?;

            // Parse metadata
            let metadata: SnapshotMetadata = serde_json::from_str(&metadata_json).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to parse snapshot metadata: {}", e))
            })?;

            // Add to map
            snapshots.insert(metadata.id.clone(), metadata);
        }
    }

    // Store snapshots
    *manager.snapshots.write().unwrap() = snapshots;

    // Load schedule
    let schedule_path = manager.base_dir.join("schedule.json");
    if schedule_path.exists() {
        let schedule_json =
            fs::read_to_string(&schedule_path).map_err(|e| ForgeError::IoError(e.to_string()))?;

        let schedule: SnapshotSchedule = serde_json::from_str(&schedule_json).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to parse snapshot schedule: {}", e))
        })?;

        *manager.schedule.write().unwrap() = Some(schedule);
    }

    Ok(())
}

impl SnapshotManager {
    /// Create a new snapshot
    pub fn create_snapshot(
        &self,
        name: &str,
        description: Option<&str>,
        snapshot_type: SnapshotType,
        identity: &IdentityContext,
        tags: Vec<String>,
        retention: Option<RetentionPolicy>,
    ) -> Result<SnapshotMetadata> {
        // Generate snapshot ID
        let snapshot_id = Uuid::new_v4().to_string();

        // Create snapshot directory
        let snapshot_dir = self.base_dir.join("data").join(&snapshot_id);
        fs::create_dir_all(&snapshot_dir).map_err(|e| ForgeError::IoError(e.to_string()))?;

        // Database snapshot code removed - sqlite and rocksdb dependencies have been removed

        // Calculate size
        let size_bytes = calculate_directory_size(&snapshot_dir)
            .map_err(|e| ForgeError::IoError(e.to_string()))?;

        // Calculate checksum
        let checksum = calculate_directory_checksum(&snapshot_dir)
            .map_err(|e| ForgeError::IoError(e.to_string()))?;

        // Create metadata
        let is_automatic = tags.contains(&"automatic".to_string());
        let mut final_tags = tags.clone();
        if is_automatic {
            final_tags.push("automatic".to_string());
        }

        let metadata = SnapshotMetadata {
            id: snapshot_id.clone(),
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
            created_at: Utc::now().to_rfc3339(),
            created_by: identity.clone(),
            snapshot_type,
            size_bytes,
            checksum,
            tags: final_tags,
            retention,
        };

        // Save metadata
        self.save_snapshot_metadata(&metadata)?;

        // Add to map
        self.snapshots
            .write()
            .unwrap()
            .insert(snapshot_id, metadata.clone());

        // Update last auto snapshot time if this is an automatic snapshot
        if is_automatic {
            *self.last_auto_snapshot.lock().unwrap() = Some(SystemTime::now());
        }

        // Apply retention policies
        self.apply_retention_policies()?;

        Ok(metadata)
    }

    /// Restore from a snapshot
    pub fn restore_from_snapshot(
        &self,
        snapshot_id: &str,
        identity: &IdentityContext,
    ) -> Result<()> {
        // Get snapshot metadata
        let metadata = self.get_snapshot(snapshot_id)?.ok_or_else(|| {
            ForgeError::DatabaseQueryError(format!("Snapshot {} not found", snapshot_id))
        })?;

        // Create restore snapshot before restoring
        self.create_snapshot(
            "pre-restore-backup",
            Some(&format!(
                "Automatic backup before restoring snapshot {}",
                snapshot_id
            )),
            SnapshotType::Full,
            identity,
            vec!["pre-restore".to_string()],
            None,
        )?;

        // Get snapshot directory
        let snapshot_dir = self.base_dir.join("data").join(snapshot_id);

        // Database restoration code removed - sqlite and rocksdb dependencies have been removed

        // Create post-restore snapshot
        self.create_snapshot(
            "post-restore-verification",
            Some(&format!(
                "Verification snapshot after restoring {}",
                snapshot_id
            )),
            SnapshotType::Full,
            identity,
            vec!["post-restore".to_string()],
            None,
        )?;

        Ok(())
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        // Get snapshot metadata
        let metadata = self.get_snapshot(snapshot_id)?.ok_or_else(|| {
            ForgeError::DatabaseQueryError(format!("Snapshot {} not found", snapshot_id))
        })?;

        // Remove from map
        self.snapshots.write().unwrap().remove(snapshot_id);

        // Delete metadata file
        let metadata_path = self
            .base_dir
            .join("metadata")
            .join(format!("{}.json", snapshot_id));
        if metadata_path.exists() {
            fs::remove_file(&metadata_path).map_err(|e| ForgeError::IoError(e.to_string()))?;
        }

        // Delete snapshot directory
        let snapshot_dir = self.base_dir.join("data").join(snapshot_id);
        if snapshot_dir.exists() {
            fs::remove_dir_all(&snapshot_dir).map_err(|e| ForgeError::IoError(e.to_string()))?;
        }

        Ok(())
    }

    /// Get a snapshot by ID
    pub fn get_snapshot(&self, snapshot_id: &str) -> Result<Option<SnapshotMetadata>> {
        let snapshots = self.snapshots.read().unwrap();
        Ok(snapshots.get(snapshot_id).cloned())
    }

    /// List all snapshots
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>> {
        let snapshots = self.snapshots.read().unwrap();
        let mut snapshot_list: Vec<SnapshotMetadata> = snapshots.values().cloned().collect();

        // Sort by creation time (newest first)
        snapshot_list.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(snapshot_list)
    }

    /// Set snapshot schedule
    pub fn set_schedule(&self, schedule: SnapshotSchedule) -> Result<()> {
        // Save schedule
        let schedule_path = self.base_dir.join("schedule.json");
        let schedule_json = serde_json::to_string_pretty(&schedule)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        fs::write(&schedule_path, schedule_json).map_err(|e| ForgeError::IoError(e.to_string()))?;

        // Update schedule
        *self.schedule.write().unwrap() = Some(schedule);

        Ok(())
    }

    /// Get snapshot schedule
    pub fn get_schedule(&self) -> Option<SnapshotSchedule> {
        self.schedule.read().unwrap().clone()
    }

    /// Check if automatic snapshot is due
    pub fn check_auto_snapshot(&self, identity: &IdentityContext) -> Result<bool> {
        // Get schedule
        let schedule = match self.schedule.read().unwrap().as_ref() {
            Some(schedule) if schedule.enabled => schedule.clone(),
            _ => return Ok(false),
        };

        // Get last auto snapshot time
        let last_auto = *self.last_auto_snapshot.lock().unwrap();

        // Check if it's time for a new snapshot
        let should_snapshot = match last_auto {
            Some(time) => {
                let elapsed = time.elapsed().map_err(|_| {
                    ForgeError::DatabaseError(crate::error::DatabaseErrorKind::DatabaseQueryError)
                })?;
                elapsed > Duration::from_secs(schedule.interval_minutes * 60)
            }
            None => true, // No previous snapshot, so take one now
        };

        if should_snapshot {
            // Create automatic snapshot
            let mut tags = schedule.tags.clone();
            tags.push("automatic".to_string());

            self.create_snapshot(
                &format!("auto-{}", Utc::now().format("%Y-%m-%d-%H-%M-%S")),
                Some("Automatic scheduled snapshot"),
                schedule.snapshot_type,
                identity,
                tags,
                Some(schedule.retention),
            )?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Save snapshot metadata
    fn save_snapshot_metadata(&self, metadata: &SnapshotMetadata) -> Result<()> {
        // Create metadata directory
        let metadata_dir = self.base_dir.join("metadata");
        fs::create_dir_all(&metadata_dir).map_err(|e| ForgeError::IoError(e.to_string()))?;

        // Save metadata
        let metadata_path = metadata_dir.join(format!("{}.json", metadata.id));
        let metadata_json = serde_json::to_string_pretty(metadata)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        fs::write(&metadata_path, metadata_json).map_err(|e| ForgeError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Apply retention policies
    fn apply_retention_policies(&self) -> Result<()> {
        let snapshots = self.snapshots.read().unwrap();
        let now = Utc::now();

        // Collect snapshots to delete
        let mut to_delete = Vec::new();

        for (id, metadata) in snapshots.iter() {
            if let Some(retention) = &metadata.retention {
                // Skip if keep_forever is true
                if retention.keep_forever {
                    continue;
                }

                // Check expiration
                if let Some(expires_at) = &retention.expires_at {
                    let expiration = DateTime::parse_from_rfc3339(expires_at).map_err(|_| {
                        ForgeError::DatabaseError(
                            crate::error::DatabaseErrorKind::DatabaseQueryError,
                        )
                    })?;

                    if expiration.with_timezone(&Utc) < now {
                        to_delete.push(id.clone());
                    }
                }
            }
        }

        // Delete expired snapshots
        for id in to_delete {
            self.delete_snapshot(&id)?;
        }

        let snapshots = self.snapshots.read().unwrap(); // reacquire after deletion

        // Apply minimum snapshots policy
        let mut tag_groups: HashMap<String, Vec<(String, DateTime<Utc>)>> = HashMap::new();

        // Group snapshots by tag
        for (id, metadata) in snapshots.iter() {
            if let Some(retention) = &metadata.retention {
                if retention.min_snapshots.is_some() {
                    // Skip if keep_forever is true
                    if retention.keep_forever {
                        continue;
                    }

                    // Group by tags
                    for tag in &metadata.tags {
                        let created_at = chrono::DateTime::parse_from_rfc3339(&metadata.created_at)
                            .map_err(|_| {
                                ForgeError::DatabaseError(
                                    crate::error::DatabaseErrorKind::DatabaseQueryError,
                                )
                            })?;

                        tag_groups
                            .entry(tag.clone())
                            .or_insert_with(Vec::new)
                            .push((id.clone(), created_at.with_timezone(&chrono::Utc)));
                    }
                }
            }
        }

        // Apply minimum snapshots policy for each tag group
        for (tag, mut snapshots) in tag_groups {
            // Sort by creation time (oldest first)
            snapshots.sort_by(|a, b| a.1.cmp(&b.1));

            // Get minimum snapshots to keep for this tag
            let min_to_keep = snapshots
                .iter()
                .filter_map(|(id, _)| {
                    self.snapshots
                        .read()
                        .unwrap()
                        .get(id)
                        .and_then(|m| m.retention.as_ref())
                        .and_then(|r| r.min_snapshots)
                })
                .max()
                .unwrap_or(1);

            // Delete excess snapshots
            if snapshots.len() > min_to_keep {
                let to_delete = snapshots.len() - min_to_keep;

                for i in 0..to_delete {
                    let (id, _) = &snapshots[i];
                    // Use a separate call to delete_snapshot to avoid borrowing issues
                    self.delete_snapshot(id)?;
                }
            }
        }

        Ok(())
    }
}

/// Calculate directory size
fn calculate_directory_size(dir: &Path) -> std::io::Result<u64> {
    let mut size = 0;

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                size += calculate_directory_size(&path)?;
            } else {
                size += entry.metadata()?.len();
            }
        }
    }

    Ok(size)
}

/// Calculate directory checksum
fn calculate_directory_checksum(dir: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    let mut paths = Vec::new();

    // Collect all file paths
    collect_file_paths(dir, &mut paths)?;

    // Sort paths for deterministic order
    paths.sort();

    // Hash each file
    for path in paths {
        // Add path to hash
        hasher.update(path.to_string_lossy().as_bytes());

        // Add file content to hash
        let content = fs::read(&path)?;
        hasher.update(&content);
    }

    // Finalize hash
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Collect file paths recursively
fn collect_file_paths(dir: &Path, paths: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                collect_file_paths(&path, paths)?;
            } else {
                paths.push(path);
            }
        }
    }

    Ok(())
}

/// Check if automatic snapshot is due
pub fn check_auto_snapshot(identity: &IdentityContext) -> Result<bool> {
    let manager = get_snapshot_manager()?;
    manager.check_auto_snapshot(identity)
}

/// Create a new snapshot
pub fn create_snapshot(
    name: &str,
    description: Option<&str>,
    snapshot_type: SnapshotType,
    identity: &IdentityContext,
    tags: Vec<String>,
    retention: Option<RetentionPolicy>,
) -> Result<SnapshotMetadata> {
    let manager = get_snapshot_manager()?;
    manager.create_snapshot(name, description, snapshot_type, identity, tags, retention)
}

/// Restore from a snapshot
pub fn restore_from_snapshot(snapshot_id: &str, identity: &IdentityContext) -> Result<()> {
    let manager = get_snapshot_manager()?;
    manager.restore_from_snapshot(snapshot_id, identity)
}

/// List all snapshots
pub fn list_snapshots() -> Result<Vec<SnapshotMetadata>> {
    let manager = get_snapshot_manager()?;
    manager.list_snapshots()
}

/// Delete a snapshot
pub fn delete_snapshot(snapshot_id: &str) -> Result<()> {
    let manager = get_snapshot_manager()?;
    manager.delete_snapshot(snapshot_id)
}

/// Set snapshot schedule
pub fn set_schedule(schedule: SnapshotSchedule) -> Result<()> {
    let manager = get_snapshot_manager()?;
    manager.set_schedule(schedule)
}

/// Get snapshot schedule
pub fn get_schedule() -> Result<Option<SnapshotSchedule>> {
    let manager = get_snapshot_manager()?;
    Ok(manager.get_schedule())
}

pub fn init_snapshot_system(options: &DbOptions) -> Result<()> {
    // Determine the snapshot base directory from DbOptions
    let base_dir = &options.base_dir;
    let snapshots_dir = base_dir.join("snapshots");

    // Ensure the snapshots directory exists
    if let Err(e) = fs::create_dir_all(&snapshots_dir) {
        log::error!("Failed to create snapshots directory: {}", e);
        return Err(ForgeError::IoError(e.to_string()));
    }

    // Initialize the snapshot manager
    if let Err(e) = init_snapshot_manager(base_dir) {
        log::error!("Failed to initialize snapshot manager: {}", e);
        return Err(e);
    }

    log::info!("Snapshot system initialized at {:?}", snapshots_dir);
    Ok(())
}
