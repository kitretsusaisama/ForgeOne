//! # Database module for ForgeOne
//!
//! This module provides secure, distributed, and resilient database services for ForgeOne.
//! It includes support for IndxDb (metadata, user access control), Redb (logs, blobs, events, snapshots),
//! sharded local storage, immutable audit trails, stateful recovery, and more.

mod access;
mod crypto;
mod integrity;
mod metrics;
pub mod model;
mod recovery;
pub mod redb;
mod schema;
mod snapshot;

pub use self::access::*;
pub use self::crypto::*;
pub use self::integrity::*;
pub use self::metrics::*;
pub use self::model::*;
pub use self::recovery::*;
pub use self::redb::*;
pub use self::schema::*;
pub use self::snapshot::*;

/// Database initialization options
pub struct DbOptions {
    /// The base directory for database files
    pub base_dir: std::path::PathBuf,
    /// Whether to encrypt the database
    pub encrypt: bool,
    /// The encryption key for the database (if encryption is enabled)
    pub encryption_key: Option<String>,
    /// Whether to use sharding
    pub use_sharding: bool,
    /// The number of shards to use (if sharding is enabled)
    pub shard_count: Option<usize>,
    /// The checkpoint interval in minutes
    pub checkpoint_interval_minutes: u64,
    /// Whether to verify checksums on startup
    pub verify_checksums: bool,
    /// Whether to enable automatic recovery
    pub auto_recovery: bool,
    /// Compression level (0-22, where 0 is no compression and 22 is max compression)
    pub compression_level: u32,
    /// Whether to enable field-level encryption
    pub field_level_encryption: bool,
    /// Whether to enable change history tracking
    pub track_changes: bool,
    /// TTL (Time-to-live) for ephemeral data in seconds
    pub ephemeral_ttl_seconds: Option<u64>,
    /// Whether to enable schema validation
    pub schema_validation: bool,
    /// Whether to enable event subscriptions
    pub enable_subscriptions: bool,
    /// Whether to enable real-time metrics
    pub enable_metrics: bool,
    /// Whether to enable scheduled database maintenance (compaction, backups, etc.)
    pub enable_scheduled_maintenance: Option<bool>,
}

impl Default for DbOptions {
    fn default() -> Self {
        Self {
            base_dir: std::path::PathBuf::from(".forgeone/db"),
            encrypt: true,
            encryption_key: None,
            use_sharding: true,
            shard_count: Some(2),
            checkpoint_interval_minutes: 15,
            verify_checksums: true,
            auto_recovery: true,
            compression_level: 3, // Default Zstd compression level
            field_level_encryption: true,
            track_changes: true,
            ephemeral_ttl_seconds: Some(86400), // 24 hours
            schema_validation: true,
            enable_subscriptions: true,
            enable_metrics: true,
            enable_scheduled_maintenance: Some(true), // Enable scheduled maintenance by default
        }
    }
}

/// Initialize the database system
pub fn init(options: DbOptions) -> crate::error::Result<()> {
    // Create base directory if it doesn't exist
    std::fs::create_dir_all(&options.base_dir)
        .map_err(|e| crate::error::ForgeError::IoError(e.to_string()))?;
    let redb_options = RedbOptions {
        base_dir: options.base_dir.clone(),
        encryption_enabled: options.encrypt,
        compression_level: options.compression_level as i32, // or as needed
        sharding_enabled: options.use_sharding,
        shard_count: options.shard_count.unwrap_or(1),
        checksum_verification: options.verify_checksums,
        auto_recovery: options.auto_recovery,
        chunk_size: 4096,            // or set a default/constant as needed
        log_rotation_size: 10485760, // or set a default/constant as needed
        checkpoint_interval: options.checkpoint_interval_minutes,
        deduplication_enabled: true, // or map from options if available
        dedup_cache_size: 10000,     // or map from options if available
    };
    redb::init_redb(redb_options)?;
    snapshot::init_snapshot_system(&options)?; // TODO: Implement snapshot system initialization

    // Initialize metrics system if enabled
    if options.enable_metrics {
        metrics::init_metrics_system(&options)?; // TODO: Implement metrics system initialization
    }

    // Initialize integrity checking system
    integrity::init_integrity_system(&options)?; // TODO: Implement integrity system initialization

    // Initialize recovery system if auto-recovery is enabled
    if options.auto_recovery {
        recovery::init_recovery_system(&options)?; // TODO: Implement recovery system initialization
    }

    Ok(())
}

/// Shutdown the database system
pub fn shutdown() -> crate::error::Result<()> {
    // Shutdown IndxDb
    // indxdb::shutdown_indxdb()?; // TODO: Implement IndxDb shutdown
    // Shutdown Redb
    // redb::shutdown_redb()?; // TODO: Implement Redb shutdown
    // Create final checkpoint
    // snapshot::create_checkpoint("shutdown")?; // TODO: Implement checkpoint creation
    Ok(())
}

/// Check database health
pub fn check_health() -> crate::error::Result<HealthStatus> {
    // Check IndxDb health
    // let indxdb_health = indxdb::check_health()?; // TODO: Implement IndxDb health check
    // Check Redb health
    // let redb_health = redb::check_health()?; // TODO: Implement Redb health check
    // Return the worst health status
    // TODO: Implement health status comparison
    Ok(HealthStatus::Healthy)
}

/// Repair database if needed
pub fn repair_if_needed() -> crate::error::Result<bool> {
    // Check health first
    let health = check_health()?;

    match health {
        HealthStatus::Healthy => Ok(false), // No repair needed
        HealthStatus::Degraded | HealthStatus::Corrupted => {
            // Attempt repair
            // let indxdb_repaired = indxdb::repair()?; // TODO: Implement IndxDb repair
            // let redb_repaired = redb::repair()?; // TODO: Implement Redb repair

            Ok(false)
        }
        HealthStatus::Unrepairable => {
            // Cannot repair, restore from snapshot
            // recovery::restore_from_latest_snapshot()?; // TODO: Implement restore from latest snapshot
            Ok(true)
        }
    }
}
