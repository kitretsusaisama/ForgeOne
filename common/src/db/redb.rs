//! # Redb Database Implementation
//!
//! This module provides an implementation of the Redb database for ForgeOne.
//! Redb is used for logs, blobs, events, and snapshots, with features like:
//! - Stream-based chunk writes and appends
//! - Rotating encrypted logs (.zlog) with index snapshots
//! - Compression pipeline: Zstd + deduplication using BLAKE3 hash keys
//! - Log topics and substreams (e.g. container_logs, audit_logs)
//! - Checkpoint markers inside logs (for quick seek & replay)
//! - Event subscriptions with async hooks (e.g., write triggers)

use crate::db::LogLevel;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use warp::filters::log::Log;

use blake3::Hash;
use redb::{Database, ReadableTable, TableDefinition, TypeName};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;
use zstd::DEFAULT_COMPRESSION_LEVEL;

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::crypto::{decrypt_aes_gcm, encrypt_aes_gcm, generate_key};
use crate::db::model::{EventPriority, Persistable, StorageBackend, StreamableEvent};
use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;
use once_cell::sync::OnceCell;

/// Default compression level for Zstd
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Maximum compression level for Zstd
pub const MAX_ZSTD_LEVEL: i32 = 19;

/// Maximum number of shards
pub const MAX_SHARDS: usize = 16;

/// Default chunk size for blob storage (1MB)
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Default log rotation size (100MB)
pub const DEFAULT_LOG_ROTATION_SIZE: u64 = 100 * 1024 * 1024;

/// Default checkpoint interval (1000 entries)
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 1000;

/// Redb database manager
pub struct RedbManager {
    /// Base directory for Redb databases
    pub base_dir: PathBuf,
    /// Database instances
    pub databases: RwLock<HashMap<String, Arc<Database>>>,
    /// Encryption enabled flag
    pub encryption_enabled: bool,
    /// Encryption key
    pub encryption_key: Option<Vec<u8>>,
    /// Compression level
    pub compression_level: i32,
    /// Sharding enabled flag
    pub sharding_enabled: bool,
    /// Number of shards
    pub shard_count: usize,
    /// Checksum verification enabled flag
    pub checksum_verification: bool,
    /// Auto-recovery enabled flag
    pub auto_recovery: bool,
    /// Chunk size for blob storage
    pub chunk_size: usize,
    /// Log rotation size
    pub log_rotation_size: u64,
    /// Checkpoint interval
    pub checkpoint_interval: u64,
    /// Event subscribers
    pub event_subscribers: RwLock<HashMap<String, broadcast::Sender<EventMessage>>>,
    /// Deduplication cache
    pub dedup_cache: Mutex<HashMap<Hash, String>>,
    /// Deduplication enabled flag
    pub deduplication_enabled: bool,
    /// Deduplication cache size
    pub dedup_cache_size: usize,
}

/// Singleton instance of the Redb manager
pub static REDB_MANAGER: OnceCell<Arc<RedbManager>> = OnceCell::new();

/// Redb options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedbOptions {
    /// Base directory for Redb databases
    pub base_dir: PathBuf,
    /// Encryption enabled flag
    pub encryption_enabled: bool,
    /// Compression level (-1 to 19, where -1 is default)
    pub compression_level: i32,
    /// Sharding enabled flag
    pub sharding_enabled: bool,
    /// Number of shards
    pub shard_count: usize,
    /// Checksum verification enabled flag
    pub checksum_verification: bool,
    /// Auto-recovery enabled flag
    pub auto_recovery: bool,
    /// Chunk size for blob storage
    pub chunk_size: usize,
    /// Log rotation size
    pub log_rotation_size: u64,
    /// Checkpoint interval
    pub checkpoint_interval: u64,
    /// Deduplication enabled flag
    pub deduplication_enabled: bool,
    /// Deduplication cache size
    pub dedup_cache_size: usize,
}

impl Default for RedbOptions {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./data/redb"),
            encryption_enabled: true,
            compression_level: DEFAULT_ZSTD_LEVEL,
            sharding_enabled: true,
            shard_count: 4,
            checksum_verification: true,
            auto_recovery: true,
            chunk_size: DEFAULT_CHUNK_SIZE,
            log_rotation_size: DEFAULT_LOG_ROTATION_SIZE,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            deduplication_enabled: true,
            dedup_cache_size: 10000,
        }
    }
}

/// Event message for subscribers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMessage {
    /// Event ID
    pub id: String,
    /// Event topic
    pub topic: String,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Event priority
    pub priority: EventPriority,
    /// Event payload
    pub payload: String,
    /// Event metadata
    pub metadata: HashMap<String, String>,
    /// Checkpoint marker
    pub checkpoint_marker: Option<String>,
}

/// Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Entry ID
    pub id: String,
    /// Log topic
    pub topic: String,
    /// Entry timestamp
    pub timestamp: DateTime<Utc>,
    /// Entry severity
    pub severity: EventPriority,
    /// Entry message
    pub message: String,
    /// Entry metadata
    pub metadata: HashMap<String, String>,
    /// Checkpoint marker
    pub checkpoint_marker: Option<String>,
    /// Content hash
    pub content_hash: Option<String>,
}

/// Blob metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobMetadata {
    /// Blob ID
    pub id: String,
    /// Blob name
    pub name: String,
    /// Blob content type
    pub content_type: String,
    /// Blob size
    pub size: u64,
    /// Blob creation timestamp
    pub created_at: DateTime<Utc>,
    /// Blob creator
    pub created_by: String,
    /// Blob checksum
    pub checksum: String,
    /// Blob encryption flag
    pub encrypted: bool,
    /// Blob compression flag
    pub compressed: bool,
    /// Blob chunk count
    pub chunk_count: u32,
    /// Blob metadata
    pub metadata: HashMap<String, String>,
}

/// Blob chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobChunk {
    /// Blob ID
    pub blob_id: String,
    /// Chunk index
    pub chunk_index: u32,
    /// Chunk data
    pub data: Vec<u8>,
    /// Chunk checksum
    pub checksum: String,
}

/// Initialize the Redb database system
pub fn init_redb(options: RedbOptions) -> Result<()> {
    // Validate options
    if options.shard_count > MAX_SHARDS {
        return Err(ForgeError::ConfigError(format!(
            "Shard count {} exceeds maximum of {}",
            options.shard_count, MAX_SHARDS
        )));
    }

    let encryption_key = if options.encryption_enabled {
        Some(generate_key(32))
    } else {
        None
    };

    let manager = RedbManager {
        base_dir: options.base_dir,
        databases: RwLock::new(HashMap::new()),
        encryption_enabled: options.encryption_enabled,
        encryption_key,
        compression_level: options.compression_level,
        sharding_enabled: options.sharding_enabled,
        shard_count: options.shard_count,
        checksum_verification: options.checksum_verification,
        auto_recovery: options.auto_recovery,
        chunk_size: options.chunk_size,
        log_rotation_size: options.log_rotation_size,
        checkpoint_interval: options.checkpoint_interval,
        event_subscribers: RwLock::new(HashMap::new()),
        dedup_cache: Mutex::new(HashMap::with_capacity(options.dedup_cache_size)),
        deduplication_enabled: options.deduplication_enabled,
        dedup_cache_size: options.dedup_cache_size,
    };

    let manager_arc = Arc::new(manager);

    // Set the global instance
    REDB_MANAGER.set(manager_arc.clone()).map_err(|_| {
        ForgeError::DatabaseConnectionError("Redb manager already initialized".to_string())
    })?;

    // Initialize the system database
    init_system_database(manager_arc.clone())?;

    // Initialize the log database
    init_log_database(manager_arc.clone())?;

    // Initialize the blob database
    init_blob_database(manager_arc.clone())?;

    // Initialize the event database
    init_event_database(manager_arc)?;

    Ok(())
}

/// Initialize the system database
fn init_system_database(manager: Arc<RedbManager>) -> Result<()> {
    let db_path = manager.base_dir.join("system.redb");

    // Create the parent directory if it doesn't exist
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ForgeError::IoError(format!("Failed to create database directory: {}", e))
        })?;
    }

    // Open the database
    let db = Database::create(db_path).map_err(|e| {
        ForgeError::DatabaseConnectionError(format!("Failed to create system database: {}", e))
    })?;

    // Define tables
    let tables = [
        ("metadata", TableDefinition::<&str, &str>::new("metadata")),
        ("snapshots", TableDefinition::<&str, &str>::new("snapshots")),
        ("metrics", TableDefinition::<&str, &str>::new("metrics")),
        ("settings", TableDefinition::<&str, &str>::new("settings")),
    ];

    // Create tables
    let write_txn = db.begin_write().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to begin write transaction: {}", e))
    })?;

    {
        let mut metadata_table = write_txn.open_table(tables[0].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[0].0, e))
        })?;
    }

    {
        let mut snapshots_table = write_txn.open_table(tables[1].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[1].0, e))
        })?;
    }

    {
        let mut metrics_table = write_txn.open_table(tables[2].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[2].0, e))
        })?;
    }

    {
        let mut settings_table = write_txn.open_table(tables[3].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[3].0, e))
        })?;
    }

    write_txn.commit().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
    })?;

    // Store the database instance
    let mut databases = manager.databases.write().unwrap();
    databases.insert("system".to_string(), Arc::new(db));

    Ok(())
}

/// Initialize the log database
fn init_log_database(manager: Arc<RedbManager>) -> Result<()> {
    // If sharding is enabled, initialize each shard
    if manager.sharding_enabled {
        for shard in 0..manager.shard_count {
            let db_path = manager.base_dir.join(format!("logs_shard_{}.redb", shard));
            init_log_shard(&manager, db_path, shard)?;
        }
    } else {
        // Initialize a single log database
        let db_path = manager.base_dir.join("logs.redb");
        init_log_shard(&manager, db_path, 0)?;
    }

    Ok(())
}

/// Initialize a log database shard
fn init_log_shard(manager: &RedbManager, db_path: PathBuf, shard: usize) -> Result<()> {
    // Create the parent directory if it doesn't exist
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ForgeError::IoError(format!("Failed to create database directory: {}", e))
        })?;
    }

    // Open the database
    let db = Database::create(&db_path).map_err(|e| {
        ForgeError::DatabaseConnectionError(format!(
            "Failed to create log database shard {}: {}",
            shard, e
        ))
    })?;

    // Define tables
    let tables = [
        ("logs", TableDefinition::<&str, &str>::new("logs")),
        ("log_index", TableDefinition::<&str, &str>::new("log_index")),
        (
            "checkpoints",
            TableDefinition::<&str, &str>::new("checkpoints"),
        ),
    ];

    // Create tables
    let write_txn = db.begin_write().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to begin write transaction: {}", e))
    })?;

    {
        let mut logs_table = write_txn.open_table(tables[0].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[0].0, e))
        })?;
    }

    {
        let mut log_index_table = write_txn.open_table(tables[1].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[1].0, e))
        })?;
    }

    {
        let mut checkpoints_table = write_txn.open_table(tables[2].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[2].0, e))
        })?;
    }

    write_txn.commit().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
    })?;

    // Store the database instance
    let mut databases = manager.databases.write().unwrap();
    let db_name = if manager.sharding_enabled {
        format!("logs_shard_{}", shard)
    } else {
        "logs".to_string()
    };

    databases.insert(db_name, Arc::new(db));

    Ok(())
}

/// Initialize the blob database
fn init_blob_database(manager: Arc<RedbManager>) -> Result<()> {
    // If sharding is enabled, initialize each shard
    if manager.sharding_enabled {
        for shard in 0..manager.shard_count {
            let db_path = manager.base_dir.join(format!("blobs_shard_{}.redb", shard));
            init_blob_shard(&manager, db_path, shard)?;
        }
    } else {
        // Initialize a single blob database
        let db_path = manager.base_dir.join("blobs.redb");
        init_blob_shard(&manager, db_path, 0)?;
    }

    Ok(())
}

/// Initialize a blob database shard
fn init_blob_shard(manager: &RedbManager, db_path: PathBuf, shard: usize) -> Result<()> {
    // Create the parent directory if it doesn't exist
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ForgeError::IoError(format!("Failed to create database directory: {}", e))
        })?;
    }

    // Open the database
    let db = Database::create(&db_path).map_err(|e| {
        ForgeError::DatabaseConnectionError(format!(
            "Failed to create blob database shard {}: {}",
            shard, e
        ))
    })?;

    // Define tables
    let tables = [
        (
            "blob_metadata",
            TableDefinition::<&str, &str>::new("blob_metadata"),
        ),
        (
            "blob_chunks",
            TableDefinition::<&str, &str>::new("blob_chunks"),
        ),
        (
            "blob_index",
            TableDefinition::<&str, &str>::new("blob_index"),
        ),
    ];

    // Create tables
    let write_txn = db.begin_write().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to begin write transaction: {}", e))
    })?;

    {
        let mut blob_metadata_table = write_txn.open_table(tables[0].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[0].0, e))
        })?;
    }

    {
        let mut blob_chunks_table = write_txn.open_table(tables[1].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[1].0, e))
        })?;
    }

    {
        let mut blob_index_table = write_txn.open_table(tables[2].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[2].0, e))
        })?;
    }

    write_txn.commit().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
    })?;

    // Store the database instance
    let mut databases = manager.databases.write().unwrap();
    let db_name = if manager.sharding_enabled {
        format!("blobs_shard_{}", shard)
    } else {
        "blobs".to_string()
    };

    databases.insert(db_name, Arc::new(db));

    Ok(())
}

/// Initialize the event database
fn init_event_database(manager: Arc<RedbManager>) -> Result<()> {
    // If sharding is enabled, initialize each shard
    if manager.sharding_enabled {
        for shard in 0..manager.shard_count {
            let db_path = manager
                .base_dir
                .join(format!("events_shard_{}.redb", shard));
            init_event_shard(&manager, db_path, shard)?;
        }
    } else {
        // Initialize a single event database
        let db_path = manager.base_dir.join("events.redb");
        init_event_shard(&manager, db_path, 0)?;
    }

    Ok(())
}

/// Initialize an event database shard
fn init_event_shard(manager: &RedbManager, db_path: PathBuf, shard: usize) -> Result<()> {
    // Create the parent directory if it doesn't exist
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ForgeError::IoError(format!("Failed to create database directory: {}", e))
        })?;
    }

    // Open the database
    let db = Database::create(&db_path).map_err(|e| {
        ForgeError::DatabaseConnectionError(format!(
            "Failed to create event database shard {}: {}",
            shard, e
        ))
    })?;

    // Define tables
    let tables = [
        ("events", TableDefinition::<&str, &str>::new("events")),
        (
            "event_index",
            TableDefinition::<&str, &str>::new("event_index"),
        ),
        ("topics", TableDefinition::<&str, &str>::new("topics")),
    ];

    // Create tables
    let write_txn = db.begin_write().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to begin write transaction: {}", e))
    })?;

    {
        let mut events_table = write_txn.open_table(tables[0].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[0].0, e))
        })?;
    }

    {
        let mut event_index_table = write_txn.open_table(tables[1].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[1].0, e))
        })?;
    }

    {
        let mut topics_table = write_txn.open_table(tables[2].1).map_err(|e| {
            ForgeError::DatabaseQueryError(format!("Failed to create table {}: {}", tables[2].0, e))
        })?;
    }

    write_txn.commit().map_err(|e| {
        ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
    })?;

    // Store the database instance
    let mut databases = manager.databases.write().unwrap();
    let db_name = if manager.sharding_enabled {
        format!("events_shard_{}", shard)
    } else {
        "events".to_string()
    };

    databases.insert(db_name, Arc::new(db));

    Ok(())
}

impl RedbManager {
    /// Get the Redb manager instance
    pub fn get_instance() -> Result<Arc<RedbManager>> {
        REDB_MANAGER.get().cloned().ok_or_else(|| {
            ForgeError::DatabaseConnectionError("Redb manager not initialized".to_string())
        })
    }

    /// Get a database by name
    pub fn get_database(&self, name: &str) -> Result<Arc<Database>> {
        let databases = self.databases.read().unwrap();

        databases.get(name).map(Arc::clone).ok_or_else(|| {
            ForgeError::DatabaseConnectionError(format!("Database '{}' not found", name))
        })
    }

    /// Calculate the shard ID for a key
    pub fn calculate_shard_id(&self, key: &str) -> usize {
        if !self.sharding_enabled || self.shard_count <= 1 {
            return 0;
        }

        // Use a simple hash function to determine the shard
        let mut hasher = blake3::Hasher::new();
        hasher.update(key.as_bytes());
        let hash = hasher.finalize();

        // Use the first 4 bytes of the hash as a u32 and mod by shard count
        let bytes = hash.as_bytes();
        let value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        (value as usize) % self.shard_count
    }

    /// Get the log database for a key
    pub fn get_log_database(&self, key: &str) -> Result<Arc<Database>> {
        if self.sharding_enabled {
            let shard = self.calculate_shard_id(key);
            self.get_database(&format!("logs_shard_{}", shard))
        } else {
            self.get_database("logs")
        }
    }

    /// Get the blob database for a key
    pub fn get_blob_database(&self, key: &str) -> Result<Arc<Database>> {
        if self.sharding_enabled {
            let shard = self.calculate_shard_id(key);
            self.get_database(&format!("blobs_shard_{}", shard))
        } else {
            self.get_database("blobs")
        }
    }

    /// Get the event database for a key
    pub fn get_event_database(&self, key: &str) -> Result<Arc<Database>> {
        if self.sharding_enabled {
            let shard = self.calculate_shard_id(key);
            self.get_database(&format!("events_shard_{}", shard))
        } else {
            self.get_database("events")
        }
    }

    /// Get the encryption key
    pub fn encryption_key(&self) -> Result<&[u8]> {
        if !self.encryption_enabled {
            return Err(ForgeError::DatabaseEncryptionError(
                "Encryption is not enabled".to_string(),
            ));
        }

        self.encryption_key
            .as_ref()
            .map(|k| k.as_slice())
            .ok_or_else(|| {
                ForgeError::DatabaseEncryptionError("Encryption key not available".to_string())
            })
    }

    /// Check if encryption is enabled
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }

    /// Get the compression level
    pub fn compression_level(&self) -> i32 {
        self.compression_level
    }

    /// Check if checksum verification is enabled
    pub fn is_checksum_verification_enabled(&self) -> bool {
        self.checksum_verification
    }

    /// Check if deduplication is enabled
    pub fn is_deduplication_enabled(&self) -> bool {
        self.deduplication_enabled
    }

    /// Get the chunk size for blob storage
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Get the log rotation size
    pub fn log_rotation_size(&self) -> u64 {
        self.log_rotation_size
    }

    /// Get the checkpoint interval
    pub fn checkpoint_interval(&self) -> u64 {
        self.checkpoint_interval
    }

    /// Subscribe to events on a topic
    pub fn subscribe_to_events(&self, topic: &str) -> Result<broadcast::Receiver<EventMessage>> {
        let mut subscribers = self.event_subscribers.write().unwrap();

        // Create a new channel if one doesn't exist for this topic
        if !subscribers.contains_key(topic) {
            let (tx, _) = broadcast::channel(100); // Buffer size of 100 events
            subscribers.insert(topic.to_string(), tx);
        }

        let tx = subscribers.get(topic).unwrap().clone();
        Ok(tx.subscribe())
    }

    pub fn get_all_events<T: for<'de> serde::Deserialize<'de>>(
        &self,
        topic: &str,
    ) -> crate::error::Result<Vec<T>> {
        let db = self.get_event_database(topic)?;
        let read_txn = db.begin_read().map_err(|e| {
            crate::error::ForgeError::DatabaseTransactionError(format!(
                "Failed to begin read transaction: {}",
                e
            ))
        })?;
        let events_table = read_txn
            .open_table(redb::TableDefinition::<&str, &str>::new("events"))
            .map_err(|e| {
                crate::error::ForgeError::DatabaseQueryError(format!(
                    "Failed to open events table: {}",
                    e
                ))
            })?;
        let mut events = Vec::new();
        for entry in events_table.iter().map_err(|e| {
            crate::error::ForgeError::DatabaseQueryError(format!("Failed to iterate events: {}", e))
        })? {
            let (_, value) = entry.map_err(|e| {
                crate::error::ForgeError::DatabaseQueryError(format!("Failed to read event: {}", e))
            })?;
            // Decode, decrypt, decompress as needed (see get_event for logic)
            let data = base64::decode(value.value()).map_err(|e| {
                crate::error::ForgeError::SerializationError(format!(
                    "Failed to decode base64: {}",
                    e
                ))
            })?;
            let decrypted_data = if self.is_encryption_enabled() {
                let nonce = [0u8; 12];
                crate::crypto::decrypt_aes_gcm(&data, self.encryption_key()?, &nonce)?
            } else {
                data
            };
            let decompressed_data = if self.compression_level() != 0 {
                zstd::decode_all(std::io::Cursor::new(&decrypted_data))
                    .map_err(|e| crate::error::ForgeError::SerializationError(e.to_string()))?
            } else {
                decrypted_data
            };
            let event: T = serde_json::from_slice(&decompressed_data)
                .map_err(|e| crate::error::ForgeError::SerializationError(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }

    /// Publish an event to subscribers
    pub fn publish_event(&self, event: EventMessage) -> Result<()> {
        let subscribers = self.event_subscribers.read().unwrap();

        if let Some(tx) = subscribers.get(&event.topic) {
            // Ignore send errors (no subscribers)
            let _ = tx.send(event.clone());
        }

        // Also publish to the "*" topic if it exists
        if let Some(tx) = subscribers.get("*") {
            let _ = tx.send(event);
        }

        Ok(())
    }

    /// Add a value to the deduplication cache
    pub fn add_to_dedup_cache(&self, data: &[u8], reference: &str) -> Result<Hash> {
        if !self.deduplication_enabled {
            return Err(ForgeError::ConfigError(
                "Deduplication is not enabled".to_string(),
            ));
        }

        let hash = blake3::hash(data);

        let mut cache = self.dedup_cache.lock().unwrap();

        // If the cache is full, remove the oldest entries
        if cache.len() >= self.dedup_cache_size {
            // This is inefficient but simple; in production we'd use an LRU cache
            let keys: Vec<Hash> = cache.keys().cloned().collect();
            for key in keys.iter().take(self.dedup_cache_size / 10) {
                cache.remove(key);
            }
        }

        cache.insert(hash, reference.to_string());

        Ok(hash)
    }

    /// Check if a value exists in the deduplication cache
    pub fn check_dedup_cache(&self, data: &[u8]) -> Option<String> {
        if !self.deduplication_enabled {
            return None;
        }

        let hash = blake3::hash(data);
        let cache = self.dedup_cache.lock().unwrap();

        cache.get(&hash).cloned()
    }

    /// Check database health
    pub fn check_health(&self, db_name: &str) -> Result<bool> {
        let db = self.get_database(db_name)?;

        // Try to open a read transaction
        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseConnectionError(format!("Failed to begin read transaction: {}", e))
        })?;

        // TODO: Add more health checks

        Ok(true)
    }

    /// Repair a database if needed
    pub fn repair_if_needed(&self, db_name: &str) -> Result<bool> {
        if !self.auto_recovery {
            return Ok(false);
        }

        // Check if the database is healthy
        if self.check_health(db_name)? {
            return Ok(false); // No repair needed
        }

        // TODO: Implement repair logic

        Ok(true) // Repair attempted
    }
}

/// Repair the Redb database
pub fn repair() -> crate::error::Result<bool> {
    let manager = RedbManager::get_instance()?;

    // Get all database names
    let databases = manager.databases.read().unwrap();
    let db_names: Vec<String> = databases.keys().cloned().collect();
    drop(databases); // Release the read lock

    let mut repaired = false;

    // Try to repair each database
    for db_name in db_names {
        if manager.repair_if_needed(&db_name)? {
            repaired = true;
        }
    }

    Ok(repaired)
}

/// Shutdown the Redb database system
pub fn shutdown_redb() -> Result<()> {
    let manager = RedbManager::get_instance()?;

    // Close all databases (Redb doesn't have an explicit close method, so we just drop the references)
    let mut databases = manager.databases.write().unwrap();
    databases.clear();

    // Clear the global instance
    // REDB_MANAGER.set(None).map_err(|_| ForgeError::DatabaseConnectionError("Redb manager already cleared".to_string()))?;

    Ok(())
}

/// Log manager for Redb
pub struct LogManager {
    /// Current log file
    current_log: String,
    /// Current log size
    current_log_size: u64,
    /// Current entry count
    current_entry_count: u64,
    /// Last checkpoint
    last_checkpoint: u64,
}

impl LogManager {
    /// Create a new log manager
    pub fn new() -> Self {
        Self {
            current_log: format!("log_{}", Utc::now().timestamp()),
            current_log_size: 0,
            current_entry_count: 0,
            last_checkpoint: 0,
        }
    }

    /// Write a log entry
    pub fn write_log(&mut self, entry: LogEntry) -> Result<String> {
        let manager = RedbManager::get_instance()?;

        // Check if we need to rotate the log
        if self.current_log_size >= manager.log_rotation_size() {
            self.rotate_log()?;
        }

        // Check if we need to create a checkpoint
        let checkpoint_marker = if manager.checkpoint_interval() > 0
            && self.current_entry_count % manager.checkpoint_interval() == 0
        {
            let checkpoint_id = format!("cp_{}_{}", self.current_log, self.current_entry_count);
            Some(checkpoint_id)
        } else {
            None
        };

        // Create a log entry with checkpoint if needed
        let mut entry = entry;
        entry.checkpoint_marker = checkpoint_marker.clone();

        // Calculate content hash if checksum verification is enabled
        if manager.is_checksum_verification_enabled() {
            let mut hasher = blake3::Hasher::new();
            hasher.update(entry.message.as_bytes());
            entry.content_hash = Some(hasher.finalize().to_hex().to_string());
        }

        // Serialize the entry
        let entry_json = serde_json::to_string(&entry)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Compress if enabled
        let compressed_data = if manager.compression_level() != 0 {
            let level = if manager.compression_level() < 0 {
                DEFAULT_COMPRESSION_LEVEL
            } else {
                manager.compression_level()
            };

            zstd::encode_all(entry_json.as_bytes(), level)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?
        } else {
            entry_json.as_bytes().to_vec()
        };

        let final_data = if manager.is_encryption_enabled() {
            let nonce = [0u8; 12]; // Replace with a secure random nonce in production!
            let encrypted = encrypt_aes_gcm(&compressed_data, manager.encryption_key()?, &nonce)?;
            STANDARD.encode(&encrypted)
        } else {
            STANDARD.encode(&compressed_data)
        };

        // Get the log database
        let db = manager.get_log_database(&entry.id)?;

        let write_txn = db.begin_write().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!(
                "Failed to begin write transaction: {}",
                e
            ))
        })?;

        {
            let mut logs_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("logs"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open logs table: {}", e))
                })?;

            logs_table
                .insert(entry.id.as_str(), final_data.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert log entry: {}", e))
                })?;
        } // logs_table borrow ends here

        {
            let mut log_index_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("log_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open log_index table: {}", e))
                })?;

            // Create an index entry with topic and timestamp
            let index_key = format!("{}:{}", entry.topic, entry.timestamp.timestamp_nanos());
            log_index_table
                .insert(index_key.as_str(), entry.id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert log index: {}", e))
                })?;
        } // log_index_table borrow ends here

        if let Some(checkpoint) = &checkpoint_marker {
            let mut checkpoints_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("checkpoints"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open checkpoints table: {}",
                        e
                    ))
                })?;

            checkpoints_table
                .insert(checkpoint.as_str(), entry.id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert checkpoint: {}", e))
                })?;

            self.last_checkpoint = self.current_entry_count;
        } // checkpoints_table borrow ends here

        write_txn.commit().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
        })?;

        // Update log size and entry count
        self.current_log_size += final_data.len() as u64;
        self.current_entry_count += 1;

        // Publish the event if it's a streamable event
        let event_message = EventMessage {
            id: entry.id.clone(),
            topic: entry.topic.clone(),
            timestamp: entry.timestamp,
            priority: entry.severity,
            payload: entry.message,
            metadata: entry.metadata,
            checkpoint_marker,
        };

        manager.publish_event(event_message)?;

        Ok(entry.id)
    }

    /// Rotate the log
    fn rotate_log(&mut self) -> Result<()> {
        // Create a new log file
        self.current_log = format!("log_{}", Utc::now().timestamp());
        self.current_log_size = 0;
        self.current_entry_count = 0;
        self.last_checkpoint = 0;

        Ok(())
    }

    /// Read logs by topic
    pub fn read_logs_by_topic(
        &self,
        topic: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<LogEntry>> {
        let manager = RedbManager::get_instance()?;

        // If sharding is enabled, we need to query all shards
        let mut all_entries = Vec::new();

        if manager.sharding_enabled {
            for shard in 0..manager.shard_count {
                let db_name = format!("logs_shard_{}", shard);
                let entries =
                    self.read_logs_from_db(&db_name, topic, start_time, end_time, limit)?;
                all_entries.extend(entries);
            }
        } else {
            let entries = self.read_logs_from_db("logs", topic, start_time, end_time, limit)?;
            all_entries.extend(entries);
        }

        // Sort by timestamp
        all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Apply limit
        if limit > 0 && all_entries.len() > limit {
            all_entries.truncate(limit);
        }

        Ok(all_entries)
    }

    /// Read logs from a specific database
    fn read_logs_from_db(
        &self,
        db_name: &str,
        topic: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<LogEntry>> {
        let manager = RedbManager::get_instance()?;
        let db = manager.get_database(db_name)?;

        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        let log_index_table = read_txn
            .open_table(TableDefinition::<&str, &str>::new("log_index"))
            .map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to open log_index table: {}", e))
            })?;

        let logs_table = read_txn
            .open_table(TableDefinition::<&str, &str>::new("logs"))
            .map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to open logs table: {}", e))
            })?;

        let mut entries = Vec::new();
        let mut count = 0;

        // Create range bounds for the query
        let start_key = if let Some(start) = start_time {
            format!("{}:{}", topic, start.timestamp_nanos())
        } else {
            format!("{}:", topic)
        };

        let end_key = if let Some(end) = end_time {
            format!("{}:{}", topic, end.timestamp_nanos() + 1) // Add 1 to make it inclusive
        } else {
            format!("{}:~", topic) // ~ is after all ASCII characters
        };

        // Query the index
        for result in log_index_table
            .range(start_key.as_str()..end_key.as_str())
            .map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to query log index: {}", e))
            })?
        {
            let (_, log_id) = result.map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to read log index entry: {}", e))
            })?;

            // Get the log entry
            if let Some(entry_data) = logs_table.get(log_id.value()).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to get log entry: {}", e))
            })? {
                // Decode from base64
                let data = base64::decode(entry_data.value()).map_err(|e| {
                    ForgeError::SerializationError(format!("Failed to decode base64: {}", e))
                })?;

                // Decrypt if needed
                let decrypted_data = if manager.is_encryption_enabled() {
                    let nonce = [0u8; 12];
                    decrypt_aes_gcm(&data, manager.encryption_key()?, &nonce)?
                } else {
                    data
                };

                // Decompress if needed
                let decompressed_data = if manager.compression_level() != 0 {
                    zstd::decode_all(std::io::Cursor::new(&decrypted_data))
                        .map_err(|e| ForgeError::SerializationError(e.to_string()))?
                } else {
                    decrypted_data
                };

                // Deserialize
                let entry: LogEntry = serde_json::from_slice(&decompressed_data)
                    .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

                // Verify checksum if enabled
                if manager.is_checksum_verification_enabled() {
                    if let Some(stored_hash) = &entry.content_hash {
                        let mut hasher = blake3::Hasher::new();
                        hasher.update(entry.message.as_bytes());
                        let computed_hash = hasher.finalize().to_hex().to_string();

                        if computed_hash != *stored_hash {
                            return Err(ForgeError::IntegrityBreach(format!(
                                "Log entry {} has invalid checksum",
                                entry.id
                            )));
                        }
                    }
                }

                entries.push(entry);
                count += 1;

                if limit > 0 && count >= limit {
                    break;
                }
            }
        }

        Ok(entries)
    }

    /// Read logs from a checkpoint
    pub fn read_logs_from_checkpoint(
        &self,
        checkpoint: &str,
        limit: usize,
    ) -> Result<Vec<LogEntry>> {
        let manager = RedbManager::get_instance()?;

        // Find the checkpoint
        let mut checkpoint_entry_id = None;

        if manager.sharding_enabled {
            for shard in 0..manager.shard_count {
                let db_name = format!("logs_shard_{}", shard);
                let db = manager.get_database(&db_name)?;

                let read_txn = db.begin_read().map_err(|e| {
                    ForgeError::DatabaseTransactionError(format!(
                        "Failed to begin read transaction: {}",
                        e
                    ))
                })?;

                let checkpoints_table = read_txn
                    .open_table(TableDefinition::<&str, &str>::new("checkpoints"))
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to open checkpoints table: {}",
                            e
                        ))
                    })?;

                let found = {
                    let entry_id = checkpoints_table.get(checkpoint).map_err(|e| {
                        ForgeError::DatabaseQueryError(format!("Failed to get checkpoint: {}", e))
                    })?;

                    if let Some(entry_id) = entry_id {
                        checkpoint_entry_id = Some((db_name.clone(), entry_id.value().to_string()));
                        true
                    } else {
                        false
                    }
                };

                if found {
                    break;
                }
            }
        } else {
            let db = manager.get_database("logs")?;

            let read_txn = db.begin_read().map_err(|e| {
                ForgeError::DatabaseTransactionError(format!(
                    "Failed to begin read transaction: {}",
                    e
                ))
            })?;

            let checkpoints_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("checkpoints"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open checkpoints table: {}",
                        e
                    ))
                })?;

            // Contain the borrow to avoid drop conflicts
            {
                let entry = checkpoints_table.get(checkpoint).map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to get checkpoint: {}", e))
                })?;

                if let Some(entry_id) = entry {
                    checkpoint_entry_id = Some(("logs".to_string(), entry_id.value().to_string()));
                }
            }
        }

        // If checkpoint not found, return empty list
        let (db_name, entry_id) = match checkpoint_entry_id {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        // Get the checkpoint entry
        let db = manager.get_database(&db_name)?;

        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        let logs_table = read_txn
            .open_table(TableDefinition::<&str, &str>::new("logs"))
            .map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to open logs table: {}", e))
            })?;

        // Get the checkpoint entry
        let entry_data = logs_table
            .get(entry_id.as_str())
            .map_err(|e| ForgeError::DatabaseQueryError(format!("Failed to get log entry: {}", e)))?
            .ok_or_else(|| {
                ForgeError::DatabaseQueryError(format!("Log entry {} not found", entry_id))
            })?;

        // Decode from base64
        let data = base64::decode(entry_data.value()).map_err(|e| {
            ForgeError::SerializationError(format!("Failed to decode base64: {}", e))
        })?;

        // Decrypt if needed
        let decrypted_data = if manager.is_encryption_enabled() {
            let nonce = [0u8; 12]; // TODO: Use a secure random nonce in production!
            decrypt_aes_gcm(&data, manager.encryption_key()?, &nonce)?
        } else {
            data
        };

        // Decompress if needed
        let decompressed_data = if manager.compression_level() != 0 {
            zstd::decode_all(std::io::Cursor::new(&decrypted_data))
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?
        } else {
            decrypted_data
        };

        // Deserialize
        let checkpoint_entry: LogEntry = serde_json::from_slice(&decompressed_data)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Now get all logs after this checkpoint
        self.read_logs_by_topic(
            &checkpoint_entry.topic,
            Some(checkpoint_entry.timestamp),
            None,
            limit,
        )
    }
}

/// Blob manager for Redb
pub struct BlobManager;

impl BlobManager {
    /// Create a new blob manager
    pub fn new() -> Self {
        Self
    }

    /// Store a blob
    pub fn store_blob(
        &self,
        name: &str,
        content_type: &str,
        data: &[u8],
        metadata: HashMap<String, String>,
        identity: &IdentityContext,
    ) -> Result<String> {
        let manager = RedbManager::get_instance()?;

        // Generate a blob ID
        let blob_id = Uuid::new_v4().to_string();

        // Calculate checksum
        let mut hasher = blake3::Hasher::new();
        hasher.update(data);
        let checksum = hasher.finalize().to_hex().to_string();

        // Check for deduplication
        if manager.is_deduplication_enabled() {
            if let Some(existing_id) = manager.check_dedup_cache(data) {
                // Return the existing blob ID
                return Ok(existing_id);
            }
        }

        // Create blob metadata
        let blob_metadata = BlobMetadata {
            id: blob_id.clone(),
            name: name.to_string(),
            content_type: content_type.to_string(),
            size: data.len() as u64,
            created_at: Utc::now(),
            created_by: identity.user_id.clone(),
            checksum: checksum.clone(),
            encrypted: manager.is_encryption_enabled(),
            compressed: manager.compression_level() != 0,
            chunk_count: ((data.len() as f64) / (manager.chunk_size() as f64)).ceil() as u32,
            metadata,
        };

        // Serialize metadata
        let metadata_json = serde_json::to_string(&blob_metadata)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Get the blob database
        let db = manager.get_blob_database(&blob_id)?;

        let write_txn = db.begin_write().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!(
                "Failed to begin write transaction: {}",
                e
            ))
        })?;

        {
            let mut metadata_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_metadata"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_metadata table: {}",
                        e
                    ))
                })?;

            metadata_table
                .insert(blob_id.as_str(), metadata_json.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert blob metadata: {}", e))
                })?;
        } // metadata_table borrow ends here

        {
            let mut chunks_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_chunks"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_chunks table: {}",
                        e
                    ))
                })?;

            // Split data into chunks
            let chunk_size = manager.chunk_size();
            for (i, chunk) in data.chunks(chunk_size).enumerate() {
                // Calculate chunk checksum
                let mut chunk_hasher = blake3::Hasher::new();
                chunk_hasher.update(chunk);
                let chunk_checksum = chunk_hasher.finalize().to_hex().to_string();

                // Compress if enabled
                let compressed_chunk = if manager.compression_level() != 0 {
                    let level = if manager.compression_level() < 0 {
                        DEFAULT_COMPRESSION_LEVEL
                    } else {
                        manager.compression_level()
                    };

                    zstd::encode_all(chunk, level)
                        .map_err(|e| ForgeError::SerializationError(e.to_string()))?
                } else {
                    chunk.to_vec()
                };

                // Encrypt if enabled
                let final_chunk = if manager.is_encryption_enabled() {
                    let nonce = [0u8; 12]; // TODO: Use a secure random nonce in production!
                    let encrypted =
                        encrypt_aes_gcm(&compressed_chunk, manager.encryption_key()?, &nonce)?;
                    STANDARD.encode(&encrypted)
                } else {
                    STANDARD.encode(&compressed_chunk)
                };

                // Create chunk
                let blob_chunk = BlobChunk {
                    blob_id: blob_id.clone(),
                    chunk_index: i as u32,
                    data: final_chunk.into_bytes(),
                    checksum: chunk_checksum,
                };

                // Serialize chunk
                let chunk_data = bincode::serialize(&blob_chunk)
                    .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

                // Store chunk
                let chunk_key = format!("{}:{}", blob_id, i);
                chunks_table
                    .insert(chunk_key.as_str(), base64::encode(&chunk_data).as_str())
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to insert blob chunk: {}",
                            e
                        ))
                    })?;
            }
        } // chunks_table borrow ends here

        {
            let mut index_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_index table: {}",
                        e
                    ))
                })?;

            // Index by name
            index_table
                .insert(format!("name:{}", name).as_str(), blob_id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to insert blob name index: {}",
                        e
                    ))
                })?;

            // Index by checksum
            index_table
                .insert(format!("checksum:{}", checksum).as_str(), blob_id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to insert blob checksum index: {}",
                        e
                    ))
                })?;

            // Index by content type
            index_table
                .insert(
                    format!("content_type:{}", content_type).as_str(),
                    blob_id.as_str(),
                )
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to insert blob content type index: {}",
                        e
                    ))
                })?;
        } // index_table borrow ends here

        write_txn.commit().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
        })?;
        if manager.is_deduplication_enabled() {
            manager.add_to_dedup_cache(data, &blob_id)?;
        }
        Ok(blob_id)
    }

    /// Get a blob
    pub fn get_blob(&self, blob_id: &str) -> Result<(BlobMetadata, Vec<u8>)> {
        let manager = RedbManager::get_instance()?;
        let db = manager.get_blob_database(blob_id)?;
        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        {
            let metadata_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_metadata"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_metadata table: {}",
                        e
                    ))
                })?;

            let metadata_json = metadata_table
                .get(blob_id)
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to get blob metadata: {}", e))
                })?
                .ok_or_else(|| {
                    ForgeError::DatabaseQueryError(format!("Blob {} not found", blob_id))
                })?;

            let metadata: BlobMetadata = serde_json::from_str(metadata_json.value())
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

            // Get chunks
            let chunks_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_chunks"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_chunks table: {}",
                        e
                    ))
                })?;

            // Collect all chunks
            let mut chunks = Vec::with_capacity(metadata.chunk_count as usize);

            for i in 0..metadata.chunk_count {
                let chunk_key = format!("{}:{}", blob_id, i);
                let chunk_data = chunks_table
                    .get(chunk_key.as_str())
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to get blob chunk {}: {}",
                            i, e
                        ))
                    })?
                    .ok_or_else(|| {
                        ForgeError::DatabaseQueryError(format!(
                            "Blob chunk {}:{} not found",
                            blob_id, i
                        ))
                    })?;

                // Decode from base64
                let encoded_chunk = chunk_data.value();
                let chunk_bytes = base64::decode(encoded_chunk).map_err(|e| {
                    ForgeError::SerializationError(format!("Failed to decode base64: {}", e))
                })?;

                // Deserialize chunk
                let chunk: BlobChunk = bincode::deserialize(&chunk_bytes)
                    .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

                chunks.push(chunk);
            }

            // Sort chunks by index
            chunks.sort_by_key(|c| c.chunk_index);

            // Combine chunks
            let mut combined_data = Vec::with_capacity(metadata.size as usize);

            for chunk in chunks {
                // Verify checksum if enabled
                if manager.is_checksum_verification_enabled() {
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&chunk.data);
                    let computed_checksum = hasher.finalize().to_hex().to_string();

                    if computed_checksum != chunk.checksum {
                        return Err(ForgeError::IntegrityBreach(format!(
                            "Blob chunk {}:{} has invalid checksum",
                            blob_id, chunk.chunk_index
                        )));
                    }
                }

                // Decrypt if needed
                let decrypted_chunk = if metadata.encrypted {
                    let nonce = [0u8; 12];
                    decrypt_aes_gcm(&chunk.data, manager.encryption_key()?, &nonce)?
                } else {
                    chunk.data
                };

                // Decompress if needed
                let decompressed_chunk = if metadata.compressed {
                    zstd::decode_all(std::io::Cursor::new(&decrypted_chunk))
                        .map_err(|e| ForgeError::SerializationError(e.to_string()))?
                } else {
                    decrypted_chunk
                };

                combined_data.extend_from_slice(&decompressed_chunk);
            }

            // Verify overall checksum
            if manager.is_checksum_verification_enabled() {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&combined_data);
                let computed_checksum = hasher.finalize().to_hex().to_string();

                if computed_checksum != metadata.checksum {
                    return Err(ForgeError::IntegrityBreach(format!(
                        "Blob {} has invalid checksum",
                        blob_id
                    )));
                }
            }

            Ok((metadata, combined_data))
        } // metadata_table and chunks_table borrows end here
    }

    /// Delete a blob
    pub fn delete_blob(&self, blob_id: &str) -> Result<()> {
        let manager = RedbManager::get_instance()?;

        // Get the blob database
        let db = manager.get_blob_database(blob_id)?;

        // Get metadata first to check if blob exists
        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        {
            let metadata_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_metadata"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_metadata table: {}",
                        e
                    ))
                })?;

            let metadata_json = metadata_table
                .get(blob_id)
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to get blob metadata: {}", e))
                })?
                .ok_or_else(|| {
                    ForgeError::DatabaseQueryError(format!("Blob {} not found", blob_id))
                })?;

            let metadata: BlobMetadata = serde_json::from_str(metadata_json.value())
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

            // Begin write transaction
            let write_txn = db.begin_write().map_err(|e| {
                ForgeError::DatabaseTransactionError(format!(
                    "Failed to begin write transaction: {}",
                    e
                ))
            })?;

            {
                let mut metadata_table = write_txn
                    .open_table(TableDefinition::<&str, &str>::new("blob_metadata"))
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to open blob_metadata table: {}",
                            e
                        ))
                    })?;

                metadata_table.remove(blob_id).map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to delete blob metadata: {}", e))
                })?;
            } // metadata_table borrow ends here

            {
                let mut chunks_table = write_txn
                    .open_table(TableDefinition::<&str, &str>::new("blob_chunks"))
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to open blob_chunks table: {}",
                            e
                        ))
                    })?;

                for i in 0..metadata.chunk_count {
                    let chunk_key = format!("{}:{}", blob_id, i);
                    chunks_table.remove(chunk_key.as_str()).map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to delete blob chunk {}: {}",
                            i, e
                        ))
                    })?;
                }
            } // chunks_table borrow ends here

            {
                let mut index_table = write_txn
                    .open_table(TableDefinition::<&str, &str>::new("blob_index"))
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to open blob_index table: {}",
                            e
                        ))
                    })?;

                // Remove name index
                index_table
                    .remove(format!("name:{}", metadata.name).as_str())
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to delete blob name index: {}",
                            e
                        ))
                    })?;

                // Remove checksum index
                index_table
                    .remove(format!("checksum:{}", metadata.checksum).as_str())
                    .map_err(|e| {
                        ForgeError::DatabaseQueryError(format!(
                            "Failed to delete blob checksum index: {}",
                            e
                        ))
                    })?;
            } // index_table borrow ends here

            write_txn.commit().map_err(|e| {
                ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
            })?;
        } // read_txn borrow ends here

        Ok(())
    }

    /// List blobs by content type
    pub fn list_blobs_by_content_type(&self, content_type: &str) -> Result<Vec<BlobMetadata>> {
        let manager = RedbManager::get_instance()?;

        // If sharding is enabled, we need to query all shards
        let mut all_blobs = Vec::new();

        if manager.sharding_enabled {
            for shard in 0..manager.shard_count {
                let db_name = format!("blobs_shard_{}", shard);
                let blobs = self.list_blobs_from_db(&db_name, content_type)?;
                all_blobs.extend(blobs);
            }
        } else {
            let blobs = self.list_blobs_from_db("blobs", content_type)?;
            all_blobs.extend(blobs);
        }

        Ok(all_blobs)
    }

    /// List blobs from a specific database
    fn list_blobs_from_db(&self, db_name: &str, content_type: &str) -> Result<Vec<BlobMetadata>> {
        let manager = RedbManager::get_instance()?;
        let db = manager.get_database(db_name)?;

        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        {
            let index_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_index table: {}",
                        e
                    ))
                })?;

            let metadata_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("blob_metadata"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open blob_metadata table: {}",
                        e
                    ))
                })?;

            let mut blobs = Vec::new();

            // Query the index for the content type
            let index_key = format!("content_type:{}", content_type);

            if let Some(blob_id) = index_table.get(index_key.as_str()).map_err(|e| {
                ForgeError::DatabaseQueryError(format!("Failed to query blob index: {}", e))
            })? {
                // Get the blob metadata
                if let Some(metadata_json) = metadata_table.get(blob_id.value()).map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to get blob metadata: {}", e))
                })? {
                    let metadata: BlobMetadata = serde_json::from_str(metadata_json.value())
                        .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

                    blobs.push(metadata);
                }
            }

            Ok(blobs)
        } // index_table and metadata_table borrows end here
    }
}

/// Event manager for Redb
pub struct EventManager {
    /// Current topic
    current_topic: String,
    /// Event count
    event_count: u64,
    /// Last checkpoint
    last_checkpoint: u64,
}

impl EventManager {
    /// Create a new event manager
    pub fn new(topic: &str) -> Self {
        Self {
            current_topic: topic.to_string(),
            event_count: 0,
            last_checkpoint: 0,
        }
    }

    /// Publish an event
    pub fn publish_event<T: StreamableEvent>(&mut self, event: &T) -> Result<String> {
        let manager = RedbManager::get_instance()?;

        // Generate event ID
        let event_id = format!(
            "{}_{}_{}",
            self.current_topic,
            Utc::now().timestamp_nanos(),
            Uuid::new_v4()
        );

        // Checkpoint marker
        let checkpoint_marker = if manager.checkpoint_interval() > 0
            && self.event_count % manager.checkpoint_interval() == 0
        {
            let checkpoint_id = format!("cp_{}_{}", self.current_topic, self.event_count);
            Some(checkpoint_id)
        } else {
            None
        };

        // Serialize event
        let event_json = serde_json::to_string(event)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Compress
        let compressed_data = if manager.compression_level() != 0 {
            let level = if manager.compression_level() < 0 {
                DEFAULT_COMPRESSION_LEVEL
            } else {
                manager.compression_level()
            };
            zstd::encode_all(event_json.as_bytes(), level)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?
        } else {
            event_json.as_bytes().to_vec()
        };

        // Encrypt
        let final_data = if manager.is_encryption_enabled() {
            let nonce = [0u8; 12]; // ⚠️ Replace with secure nonce in production
            let encrypted = encrypt_aes_gcm(&compressed_data, manager.encryption_key()?, &nonce)?;
            STANDARD.encode(&encrypted)
        } else {
            STANDARD.encode(&compressed_data)
        };

        // Database operations
        let db = manager.get_event_database(&event_id)?;

        let write_txn = db.begin_write().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!(
                "Failed to begin write transaction: {}",
                e
            ))
        })?;

        {
            let mut events_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("events"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open events table: {}", e))
                })?;

            events_table
                .insert(event_id.as_str(), final_data.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert event: {}", e))
                })?;
        }

        {
            let mut index_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("event_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open event_index table: {}",
                        e
                    ))
                })?;

            let index_key = format!("{}:{}", self.current_topic, Utc::now().timestamp_nanos());

            index_table
                .insert(index_key.as_str(), event_id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert event index: {}", e))
                })?;
        }

        if let Some(checkpoint) = &checkpoint_marker {
            let mut checkpoints_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("topics"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open topics table: {}", e))
                })?;

            checkpoints_table
                .insert(checkpoint.as_str(), event_id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert checkpoint: {}", e))
                })?;

            self.last_checkpoint = self.event_count;
        }

        write_txn.commit().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
        })?;

        self.event_count += 1;

        // Construct event message
        let event_message = EventMessage {
            id: event_id.clone(),
            topic: self.current_topic.clone(),
            timestamp: Utc::now(),
            priority: event.priority(),
            payload: event_json,
            metadata: event.metadata(),
            checkpoint_marker,
        };

        manager.publish_event(event_message)?;

        Ok(event_id)
    }

    /// Subscribe to events
    pub fn subscribe(&self) -> Result<broadcast::Receiver<EventMessage>> {
        let manager = RedbManager::get_instance()?;
        manager.subscribe_to_events(&self.current_topic)
    }

    /// Query events by time range
    pub fn query_events(
        &self,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<String>> {
        let manager = RedbManager::get_instance()?;

        // If sharding is enabled, we need to query all shards
        let mut all_events = Vec::new();

        if manager.sharding_enabled {
            for shard in 0..manager.shard_count {
                let db_name = format!("events_shard_{}", shard);
                let events = self.query_events_from_db(&db_name, start_time, end_time, limit)?;
                all_events.extend(events);
            }
        } else {
            let events = self.query_events_from_db("events", start_time, end_time, limit)?;
            all_events.extend(events);
        }

        // Sort by timestamp (which is embedded in the event ID)
        all_events.sort();

        // Apply limit
        if limit > 0 && all_events.len() > limit {
            all_events.truncate(limit);
        }

        Ok(all_events)
    }

    /// Query events from a specific database
    fn query_events_from_db(
        &self,
        db_name: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<String>> {
        let manager = RedbManager::get_instance()?;
        let db = manager.get_database(db_name)?;

        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        {
            let event_index_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("event_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open event_index table: {}",
                        e
                    ))
                })?;

            let mut events = Vec::new();
            let mut count = 0;

            // Create range bounds for the query
            let start_key = if let Some(start) = start_time {
                format!("{}:{}", self.current_topic, start.timestamp_nanos())
            } else {
                format!("{}:", self.current_topic)
            };

            let end_key = if let Some(end) = end_time {
                format!("{}:{}", self.current_topic, end.timestamp_nanos() + 1) // Add 1 to make it inclusive
            } else {
                format!("{}:~", self.current_topic) // ~ is after all ASCII characters
            };

            // Query the index
            for result in event_index_table
                .range(start_key.as_str()..end_key.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to query event index: {}", e))
                })?
            {
                let (_, event_id) = result.map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to read event index entry: {}",
                        e
                    ))
                })?;

                events.push(event_id.value().to_string());
                count += 1;

                if limit > 0 && count >= limit {
                    break;
                }
            }

            Ok(events)
        } // event_index_table borrow ends here
    }

    /// Get an event by ID
    pub fn get_event(&self, event_id: &str) -> Result<String> {
        let manager = RedbManager::get_instance()?;

        // Get the event database
        let db = manager.get_event_database(event_id)?;

        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        {
            let events_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("events"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open events table: {}", e))
                })?;

            let event_data = events_table
                .get(event_id)
                .map_err(|e| ForgeError::DatabaseQueryError(format!("Failed to get event: {}", e)))?
                .ok_or_else(|| {
                    ForgeError::DatabaseQueryError(format!("Event {} not found", event_id))
                })?;

            // Decode from base64
            let data = base64::decode(event_data.value()).map_err(|e| {
                ForgeError::SerializationError(format!("Failed to decode base64: {}", e))
            })?;

            // Decrypt if needed
            let decrypted_data = if manager.is_encryption_enabled() {
                let nonce = [0u8; 12]; // TODO: Use a secure random nonce in production!
                decrypt_aes_gcm(&data, manager.encryption_key()?, &nonce)?
            } else {
                data
            };

            // Decompress if needed
            let decompressed_data = if manager.compression_level() != 0 {
                zstd::decode_all(std::io::Cursor::new(&decrypted_data))
                    .map_err(|e| ForgeError::SerializationError(e.to_string()))?
            } else {
                decrypted_data
            };

            // Convert to string
            let event_json = String::from_utf8(decompressed_data)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
            Ok(event_json)
        }
    }
}

pub struct TopicLogManager {
    current_topic: String,
    entry_count: u64,
    /// Last rotation timestamp
    last_rotation: DateTime<Utc>,
    /// Rotation interval in seconds
    rotation_interval: u64,
    /// Maximum log file size in bytes
    max_log_size: u64,
    /// Current log file size
    current_log_size: u64,
}
impl From<LogLevel> for EventPriority {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Info => EventPriority::Low,
            LogLevel::Warning => EventPriority::Medium,
            LogLevel::Error => EventPriority::High,
            LogLevel::Critical => EventPriority::Critical,
            LogLevel::Debug => EventPriority::Debug,
        }
    }
}
impl TopicLogManager {
    /// Create a new topic-based log manager
    pub fn new(topic: &str, rotation_interval: u64, max_log_size: u64) -> Self {
        Self {
            current_topic: topic.to_string(),
            entry_count: 0,
            last_rotation: Utc::now(),
            rotation_interval,
            max_log_size,
            current_log_size: 0,
        }
    }

    /// Write a log entry
    pub fn write_log(
        &mut self,
        level: LogLevel,
        message: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<String> {
        let manager = RedbManager::get_instance()?;
        self.check_rotation()?;
        let level_clone = level.clone();
        let entry_id = format!(
            "{}_{}_{}",
            self.current_topic,
            Utc::now().timestamp_nanos(),
            Uuid::new_v4()
        );
        let log_entry = LogEntry {
            id: entry_id.clone(),
            topic: self.current_topic.clone(),
            timestamp: Utc::now(),
            severity: level_clone.into(),
            message: message.to_string(),
            metadata: metadata.unwrap_or_default(),
            checkpoint_marker: None,
            content_hash: None,
        };
        // Serialize the log entry
        let entry_json = serde_json::to_string(&log_entry)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        // Compress if enabled
        let compressed_data = if manager.compression_level() != 0 {
            let level = if manager.compression_level() < 0 {
                DEFAULT_COMPRESSION_LEVEL
            } else {
                manager.compression_level()
            };
            zstd::encode_all(entry_json.as_bytes(), level)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?
        } else {
            entry_json.as_bytes().to_vec()
        };
        let final_data = if manager.is_encryption_enabled() {
            let nonce = [0u8; 12];
            let encrypted = encrypt_aes_gcm(&compressed_data, manager.encryption_key()?, &nonce)?;
            STANDARD.encode(&encrypted)
        } else {
            STANDARD.encode(&compressed_data)
        };
        // Get the log database
        let db = manager.get_log_database(&self.current_topic)?;
        // Write the log entry
        let write_txn = db.begin_write().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!(
                "Failed to begin write transaction: {}",
                e
            ))
        })?;
        {
            let mut logs_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("logs"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open logs table: {}", e))
                })?;
            logs_table
                .insert(entry_id.as_str(), final_data.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert log entry: {}", e))
                })?;
        } // logs_table borrow ends here
        {
            let mut log_index_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("log_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open log_index table: {}", e))
                })?;
            // Create an index entry with topic, level, and timestamp
            let index_key = format!(
                "{}:{:?}:{}",
                self.current_topic,
                level,
                Utc::now().timestamp_nanos()
            );
            log_index_table
                .insert(index_key.as_str(), entry_id.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to insert log index: {}", e))
                })?;
        } // log_index_table borrow ends here
        {
            let mut metadata_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("log_metadata"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open log_metadata table: {}",
                        e
                    ))
                })?;
            // Update entry count and log size
            let metadata_key = format!("{}:stats", self.current_topic);
            let metadata_value = format!(
                "{},{},{}",
                self.entry_count + 1,
                self.current_log_size + final_data.len() as u64,
                Utc::now().timestamp()
            );
            metadata_table
                .insert(metadata_key.as_str(), metadata_value.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to update log metadata: {}", e))
                })?;
        } // metadata_table borrow ends here
        write_txn.commit().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
        })?;
        // Update entry count and log size
        self.entry_count += 1;
        self.current_log_size += final_data.len() as u64;
        Ok(entry_id)
    }

    fn check_rotation(&mut self) -> Result<bool> {
        let now = Utc::now();
        let time_since_rotation =
            now.signed_duration_since(self.last_rotation).num_seconds() as u64;

        // Check if we need to rotate based on time or size
        if (self.rotation_interval > 0 && time_since_rotation >= self.rotation_interval)
            || (self.max_log_size > 0 && self.current_log_size >= self.max_log_size)
        {
            self.rotate_log()?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Rotate the log
    fn rotate_log(&mut self) -> Result<()> {
        let manager = RedbManager::get_instance()?;

        // Create a snapshot of the current log
        let snapshot_id = format!(
            "{}_{}_{}",
            self.current_topic,
            self.last_rotation.format("%Y%m%d%H%M%S"),
            self.entry_count
        );

        // Get the log database
        let db = manager.get_log_database(&self.current_topic)?;

        // Create a snapshot
        let write_txn = db.begin_write().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!(
                "Failed to begin write transaction: {}",
                e
            ))
        })?;

        {
            let mut snapshots_table = write_txn
                .open_table(TableDefinition::<&str, &str>::new("log_snapshots"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to open log_snapshots table: {}",
                        e
                    ))
                })?;

            // Store snapshot metadata
            let snapshot_metadata = format!(
                "{},{},{},{}",
                self.current_topic,
                self.last_rotation.timestamp(),
                Utc::now().timestamp(),
                self.entry_count
            );
            snapshots_table
                .insert(snapshot_id.as_str(), snapshot_metadata.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!(
                        "Failed to insert snapshot metadata: {}",
                        e
                    ))
                })?;
        }
        write_txn.commit().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to commit transaction: {}", e))
        })?;

        // Reset log stats
        self.last_rotation = Utc::now();
        self.current_log_size = 0;

        Ok(())
    }

    /// Query logs by level and time range
    pub fn query_logs(
        &self,
        level: Option<LogLevel>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<LogEntry>> {
        let manager = RedbManager::get_instance()?;

        // If sharding is enabled, we need to query all shards
        let mut all_logs = Vec::new();

        if manager.sharding_enabled {
            let level_clone = level.clone();
            for shard in 0..manager.shard_count {
                let db_name = format!("logs_shard_{}", shard);
                let logs = self.query_logs_from_db(
                    &db_name,
                    level_clone.clone(),
                    start_time,
                    end_time,
                    limit,
                )?;
                all_logs.extend(logs);
            }
        } else {
            let logs = self.query_logs_from_db("logs", level, start_time, end_time, limit)?;
            all_logs.extend(logs);
        }

        // Sort by timestamp
        all_logs.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Apply limit
        if limit > 0 && all_logs.len() > limit {
            all_logs.truncate(limit);
        }

        Ok(all_logs)
    }

    /// Query logs from a specific database
    fn query_logs_from_db(
        &self,
        db_name: &str,
        level: Option<LogLevel>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<LogEntry>> {
        let manager = RedbManager::get_instance()?;
        let db = manager.get_database(db_name)?;

        let read_txn = db.begin_read().map_err(|e| {
            ForgeError::DatabaseTransactionError(format!("Failed to begin read transaction: {}", e))
        })?;

        {
            let log_index_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("log_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open log_index table: {}", e))
                })?;

            let logs_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("logs"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open logs table: {}", e))
                })?;

            let mut logs: Vec<LogEntry> = Vec::new();
            let mut count = 0;

            // Create range bounds for the query
            let level_str = if let Some(ref l) = level {
                l.to_string()
            } else {
                "*".to_string() // Match any level
            };

            let log_index_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("log_index"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open log_index table: {}", e))
                })?;

            let logs_table = read_txn
                .open_table(TableDefinition::<&str, &str>::new("logs"))
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to open logs table: {}", e))
                })?;

            let mut logs = Vec::new();
            let mut count = 0;

            // Create range bounds for the query
            let level_str = if let Some(ref l) = level {
                l.to_string()
            } else {
                "*".to_string() // Match any level
            };

            let start_key = if let Some(start) = start_time {
                format!(
                    "{}:{}:{}",
                    self.current_topic,
                    level_str,
                    start.timestamp_nanos()
                )
            } else {
                format!("{}:{}:", self.current_topic, level_str)
            };

            let end_key = if let Some(end) = end_time {
                format!(
                    "{}:{}:{}",
                    self.current_topic,
                    level_str,
                    end.timestamp_nanos() + 1
                ) // Add 1 to make it inclusive
            } else {
                format!("{}:{}:~", self.current_topic, level_str) // ~ is after all ASCII characters
            };

            // Query the index
            for result in log_index_table
                .range(start_key.as_str()..end_key.as_str())
                .map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to query log index: {}", e))
                })?
            {
                let (_, entry_id) = result.map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to read log index entry: {}", e))
                })?;

                // Get the log entry
                if let Some(entry_data) = logs_table.get(entry_id.value()).map_err(|e| {
                    ForgeError::DatabaseQueryError(format!("Failed to get log entry: {}", e))
                })? {
                    // Decode from base64
                    let data = base64::decode(entry_data.value()).map_err(|e| {
                        ForgeError::SerializationError(format!("Failed to decode base64: {}", e))
                    })?;

                    // Decrypt if needed
                    let decrypted_data = if manager.is_encryption_enabled() {
                        let nonce = [0u8; 12];
                        decrypt_aes_gcm(&data, manager.encryption_key()?, &nonce)?
                    } else {
                        data
                    };

                    // Decompress if needed
                    let decompressed_data = if manager.compression_level() != 0 {
                        zstd::decode_all(std::io::Cursor::new(&decrypted_data))
                            .map_err(|e| ForgeError::SerializationError(e.to_string()))?
                    } else {
                        decrypted_data
                    };

                    // Convert to string and deserialize
                    let entry_json = String::from_utf8(decompressed_data)
                        .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

                    let log_entry: LogEntry = serde_json::from_str(&entry_json)
                        .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

                    logs.push(log_entry);
                    count += 1;

                    if limit > 0 && count >= limit {
                        break;
                    }
                }
            }

            Ok(logs)
        }
    }   
}
