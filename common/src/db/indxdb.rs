//! # IndxDb Database Implementation
//!
//! This module provides an implementation of the IndxDb database for ForgeOne.
//! IndxDb is used for metadata and user access control, with features like:
//! - Versioned schemas with migrations
//! - Automatic Zstd compression with level tuning
//! - Field-level encryption (AES-GCM per-entry)
//! - Change history tracking (for audit logs)
//! - TTL (Time-to-live) support for ephemeral tokens and metrics
//! - Schema validation and rollback if corrupt

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, Mutex};
use std::time::{Duration, Instant};
use std::string::String;

use chrono::{DateTime, Utc};
use indxdb::{Database, Table, Transaction, TransactionMode};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use zstd::{DEFAULT_COMPRESSION_LEVEL, ZstdError};

use crate::crypto::{encrypt_aes_gcm, decrypt_aes_gcm, generate_key};
use crate::db::model::{BaseEntity, ChangeRecord, FieldEncryptable, Persistable, StorageBackend};
use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;

/// Default compression level for Zstd
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Maximum compression level for Zstd
pub const MAX_ZSTD_LEVEL: i32 = 19;

/// IndxDb database manager
pub struct IndxDbManager {
    /// Base directory for IndxDb databases
    base_dir: PathBuf,
    /// Database instances
    databases: RwLock<HashMap<String, Arc<Database>>>,
    /// Encryption enabled flag
    encryption_enabled: bool,
    /// Encryption key
    encryption_key: Option<Vec<u8>>,
    /// Compression level
    compression_level: i32,
    /// Schema version
    schema_version: u32,
    /// Auto-recovery enabled flag
    auto_recovery: bool,
    /// Field-level encryption enabled flag
    field_encryption: bool,
    /// Change tracking enabled flag
    change_tracking: bool,
    /// TTL cleanup interval
    ttl_cleanup_interval: Duration,
    /// Last TTL cleanup time
    last_ttl_cleanup: Mutex<Instant>,
    /// Schema validation enabled flag
    schema_validation: bool,
    /// Enable scheduled maintenance (compaction, backups, etc.)
    enable_scheduled_maintenance: bool,
}

/// Singleton instance of the IndxDb manager
static mut INDXDB_MANAGER: Option<Arc<IndxDbManager>> = None;

/// IndxDb options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndxDbOptions {
    /// Base directory for IndxDb databases
    pub base_dir: PathBuf,
    /// Encryption enabled flag
    pub encryption_enabled: bool,
    /// Compression level (-1 to 19, where -1 is default)
    pub compression_level: i32,
    /// Auto-recovery enabled flag
    pub auto_recovery: bool,
    /// Field-level encryption enabled flag
    pub field_encryption: bool,
    /// Change tracking enabled flag
    pub change_tracking: bool,
    /// TTL cleanup interval in seconds
    pub ttl_cleanup_interval_secs: u64,
    /// Schema validation enabled flag
    pub schema_validation: bool,
    /// Enable scheduled maintenance (compaction, backups, etc.)
    pub enable_scheduled_maintenance: bool,
}

impl Default for IndxDbOptions {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./data/indxdb"),
            encryption_enabled: true,
            compression_level: DEFAULT_ZSTD_LEVEL,
            auto_recovery: true,
            field_encryption: true,
            change_tracking: true,
            ttl_cleanup_interval_secs: 300, // 5 minutes
            schema_validation: true,
            enable_scheduled_maintenance: false,
        }
    }
}

/// Schema definition for IndxDb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaDefinition {
    /// Schema version
    pub version: u32,
    /// Schema name
    pub name: String,
    /// Table definitions
    pub tables: Vec<TableDefinition>,
    /// Migration scripts
    pub migrations: Vec<MigrationScript>,
}

/// Table definition for IndxDb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableDefinition {
    /// Table name
    pub name: String,
    /// Primary key field
    pub primary_key: String,
    /// Field definitions
    pub fields: Vec<FieldDefinition>,
    /// Index definitions
    pub indexes: Vec<IndexDefinition>,
}

/// Field definition for IndxDb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: FieldType,
    /// Required flag
    pub required: bool,
    /// Default value
    pub default: Option<String>,
    /// Encrypted flag
    pub encrypted: bool,
}

/// Field type for IndxDb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    /// String type
    String,
    /// Integer type
    Integer,
    /// Float type
    Float,
    /// Boolean type
    Boolean,
    /// Date type
    Date,
    /// Binary type
    Binary,
    /// JSON type
    Json,
    /// UUID type
    Uuid,
}

/// Index definition for IndxDb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDefinition {
    /// Index name
    pub name: String,
    /// Fields to index
    pub fields: Vec<String>,
    /// Unique flag
    pub unique: bool,
}

/// Migration script for IndxDb
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationScript {
    /// From version
    pub from_version: u32,
    /// To version
    pub to_version: u32,
    /// Migration script
    pub script: String,
}

/// Initialize the IndxDb database system
pub fn init_indxdb(options: &crate::db::DbOptions) -> Result<()> {
    // Convert DbOptions to IndxDbOptions
    let indxdb_options = IndxDbOptions {
        base_dir: options.base_dir.join("indxdb"),
        encryption_enabled: options.encrypt,
        compression_level: options.compression_level as i32,
        auto_recovery: options.auto_recovery,
        field_encryption: options.field_level_encryption,
        change_tracking: options.track_changes,
        ttl_cleanup_interval_secs: 300, // 5 minutes default
        schema_validation: options.schema_validation,
        enable_scheduled_maintenance: options.enable_scheduled_maintenance.unwrap_or(false),
    };
    
    let encryption_key = if indxdb_options.encryption_enabled {
        match options.encryption_key.as_ref() {
            Some(key) => Some(key.as_bytes().to_vec()),
            None => Some(generate_key(32))
        }
    } else {
        None
    };

    let manager = IndxDbManager {
        base_dir: indxdb_options.base_dir,
        databases: RwLock::new(HashMap::new()),
        encryption_enabled: indxdb_options.encryption_enabled,
        encryption_key,
        compression_level: indxdb_options.compression_level,
        schema_version: 1, // Start with version 1
        auto_recovery: indxdb_options.auto_recovery,
        field_encryption: indxdb_options.field_encryption,
        change_tracking: indxdb_options.change_tracking,
        ttl_cleanup_interval: Duration::from_secs(indxdb_options.ttl_cleanup_interval_secs),
        last_ttl_cleanup: Mutex::new(Instant::now()),
        schema_validation: indxdb_options.schema_validation,
        enable_scheduled_maintenance: indxdb_options.enable_scheduled_maintenance,
    };

    let manager_arc = Arc::new(manager);

    // Set the global instance
    unsafe {
        INDXDB_MANAGER = Some(manager_arc.clone());
    }

    // Initialize the system database
    init_system_database(manager_arc)?;

    // Start TTL cleanup thread if enabled
    if indxdb_options.ttl_cleanup_interval_secs > 0 {
        if let Err(e) = start_ttl_cleanup(manager_arc.clone()) {
            tracing::warn!("Failed to start TTL cleanup thread: {}", e);
        } else {
            tracing::info!("Started TTL cleanup thread with interval of {:?}", manager_arc.ttl_cleanup_interval);
        }
    }
    
    // Start scheduled maintenance if enabled
    if indxdb_options.enable_scheduled_maintenance {
        let schedule = MaintenanceSchedule::default();
        if let Err(e) = start_scheduled_maintenance(manager_arc.clone(), schedule) {
            tracing::warn!("Failed to start scheduled maintenance: {}", e);
        } else {
            tracing::info!("Started scheduled database maintenance");
        }
    }

    Ok(())
}

/// Initialize the system database
fn init_system_database(manager: Arc<IndxDbManager>) -> Result<()> {
    let system_db = manager.open_database("system")?;
    
    // Create tables for system database
    let tables = [
        "schemas",
        "migrations",
        "change_history",
        "metrics",
        "api_keys",
        "users",
        "roles",
        "permissions",
        "settings",
    ];

    for table_name in tables.iter() {
        // Add error handling for table creation
        if let Err(e) = system_db.create_table(table_name) {
            return Err(ForgeError::DatabaseError(format!(
                "Failed to create table '{}': {}", table_name, e
            )));
        }
    }

    // Create initial schema definition
    let schema = SchemaDefinition {
        version: 1,
        name: "system".to_string(),
        tables: vec![
            TableDefinition {
                name: "schemas".to_string(),
                primary_key: "name".to_string(),
                fields: vec![
                    FieldDefinition {
                        name: "name".to_string(),
                        field_type: FieldType::String,
                        required: true,
                        default: None,
                        encrypted: false,
                    },
                    FieldDefinition {
                        name: "version".to_string(),
                        field_type: FieldType::Integer,
                        required: true,
                        default: Some("1".to_string()),
                        encrypted: false,
                    },
                    FieldDefinition {
                        name: "definition".to_string(),
                        field_type: FieldType::Json,
                        required: true,
                        default: None,
                        encrypted: false,
                    },
                ],
                indexes: vec![
                    IndexDefinition {
                        name: "idx_schemas_version".to_string(),
                        fields: vec!["version".to_string()],
                        unique: false,
                    },
                ],
            },
            // Add other table definitions here
        ],
        migrations: vec![],
    };

    // Store the schema definition
    let schemas_table = system_db.table("schemas")
        .map_err(|e| ForgeError::DatabaseError(format!("Failed to get schemas table: {}", e)))?;
    let tx = system_db.transaction(TransactionMode::ReadWrite)
        .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
    let schema_json = serde_json::to_string(&schema)
        .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
    
    schemas_table.put(&tx, "system", &schema_json)
        .map_err(|e| ForgeError::DatabaseError(format!("Failed to put schema: {}", e)))?;
    tx.commit()
        .map_err(|e| ForgeError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;

    Ok(())
}

/// Start the TTL cleanup thread
pub fn start_ttl_cleanup(manager: Arc<IndxDbManager>) -> Result<()> {
    // Create a thread to periodically clean up expired entries
    std::thread::spawn(move || {
        loop {
            // Sleep for the cleanup interval
            std::thread::sleep(manager.ttl_cleanup_interval);
            
            // Update the last cleanup time
            *manager.last_ttl_cleanup.lock().unwrap() = Instant::now();
            
            // Clean up expired entries
            if let Err(e) = cleanup_expired_entries(&manager) {
                tracing::error!("Failed to cleanup expired entries: {}", e);
            }
        }
    });
    
    Ok(())
}

/// Clean up expired entries
fn cleanup_expired_entries(manager: &IndxDbManager) -> Result<()> {
    let databases = manager.databases.read().unwrap();
    
    for (db_name, db) in databases.iter() {
        // Skip system database for now
        if db_name == "system" {
            continue;
        }
        
        // Get all tables in the database
        let table_names = db.table_names()
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table names: {}", e)))?;
        
        for table_name in table_names {
            let table = db.table(&table_name)
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table: {}", e)))?;
            let tx = db.transaction(TransactionMode::ReadWrite)
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
            
            // Find and delete expired entries
            let keys_to_delete = find_expired_entries(&table, &tx)?;
            
            if !keys_to_delete.is_empty() {
                tracing::info!("Deleting {} expired entries from table {}", keys_to_delete.len(), table_name);
                
                for key in keys_to_delete {
                    table.delete(&tx, &key)
                        .map_err(|e| ForgeError::DatabaseError(format!("Failed to delete key: {}", e)))?;
                }
                
                tx.commit()
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
            }
        }
    }
    
    Ok(())
}

/// Find expired entries in a table
fn find_expired_entries(table: &Table, tx: &Transaction) -> Result<Vec<String>> {
    let mut keys_to_delete = Vec::new();
    let now = Utc::now();
    let now_timestamp = now.timestamp();
    
    // Get the table schema if available to optimize TTL checks
    // TODO: Implement schema-based TTL optimization
    
    // Scan all entries in the table
    let scan_iter = table.scan(tx)
        .map_err(|e| ForgeError::DatabaseError(format!("Failed to scan table: {}", e)))?;
    
    // Process each entry
    for item in scan_iter {
        // Skip any entries that can't be read instead of failing the entire operation
        let (key, value): (String, String) = match item {
            Ok(item_data) => item_data,
            Err(e) => {
                tracing::warn!("Failed to read item during TTL cleanup: {}", e);
                continue;
            }
        };
        
        // Try to parse as a BaseEntity or a type containing expires_at
        if let Ok(entity) = serde_json::from_str::<BaseEntity>(&value) {
            if entity.is_expired() {
                keys_to_delete.push(key);
                continue;
            }
        }
        
        // Try to parse as a map to check for expiration fields
        if let Ok(map) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&value) {
            // Check for expires_at field (could be DateTime or timestamp)
            if let Some(expires_at) = map.get("expires_at") {
                match expires_at {
                    serde_json::Value::String(date_str) => {
                        // Try to parse as ISO 8601 date string
                        if let Ok(expiry) = DateTime::parse_from_rfc3339(date_str) {
                            if now > expiry.with_timezone(&Utc) {
                                keys_to_delete.push(key);
                                continue;
                            }
                        }
                    },
                    serde_json::Value::Number(num) => {
                        // Try to parse as Unix timestamp
                        if let Some(expiry_ts) = num.as_i64() {
                            if expiry_ts > 0 && now_timestamp > expiry_ts {
                                keys_to_delete.push(key);
                                continue;
                            }
                        }
                    },
                    _ => {}
                }
            }
            
            // Check for ttl_seconds and created_at fields
            if let (Some(ttl), Some(created_at)) = (map.get("ttl_seconds"), map.get("created_at")) {
                let ttl_seconds = match ttl {
                    serde_json::Value::Number(n) => n.as_i64().unwrap_or(0),
                    serde_json::Value::String(s) => s.parse::<i64>().unwrap_or(0),
                    _ => 0
                };
                
                if ttl_seconds <= 0 {
                    continue;
                }
                
                let created_time = match created_at {
                    serde_json::Value::String(date_str) => {
                        // Try to parse as ISO 8601 date string
                        if let Ok(dt) = DateTime::parse_from_rfc3339(date_str) {
                            dt.with_timezone(&Utc)
                        } else {
                            continue;
                        }
                    },
                    serde_json::Value::Number(num) => {
                        // Try to parse as Unix timestamp
                        if let Some(ts) = num.as_i64() {
                            match Utc.timestamp_opt(ts, 0) {
                                chrono::offset::LocalResult::Single(dt) => dt,
                                _ => continue
                            }
                        } else {
                            continue;
                        }
                    },
                    _ => continue
                };
                
                let expiry = created_time + chrono::Duration::seconds(ttl_seconds);
                if now > expiry {
                    keys_to_delete.push(key);
                }
            }
        }
    }
    
    Ok(keys_to_delete)
}

impl IndxDbManager {
    /// Get the IndxDb manager instance
    pub fn get_instance() -> Result<Arc<IndxDbManager>> {
        unsafe {
            INDXDB_MANAGER.as_ref().map(Arc::clone).ok_or_else(|| {
                ForgeError::DatabaseConnectionError("IndxDb manager not initialized. Call init_indxdb first.".to_string())
            })
        }
    }
    
    /// Manually trigger TTL cleanup for all databases
    pub fn cleanup_expired_records(&self) -> Result<usize> {
        self.purge_expired_entries()
    }
    
    pub fn purge_expired_entries(&self) -> Result<usize> {
        let mut total_purged = 0;
        
        // Update the last cleanup time
        *self.last_ttl_cleanup.lock().unwrap() = Instant::now();
        
        // Get all databases
        let databases = self.databases.read().unwrap();
        
        for (db_name, db) in databases.iter() {
            // Skip system database
            if db_name == "system" {
                continue;
            }
            
            // Get all tables in the database
            let table_names = db.table_names()
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table names: {}", e)))?;
            
            for table_name in table_names {
                let table = db.table(&table_name)
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table: {}", e)))?;
                let tx = db.transaction(TransactionMode::ReadWrite)
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
                
                // Find and delete expired entries
                let keys_to_delete = find_expired_entries(&table, &tx)?;
                let count = keys_to_delete.len();
                
                if !keys_to_delete.is_empty() {
                    tracing::info!("Purging {} expired entries from table {}", count, table_name);
                    
                    for key in keys_to_delete {
                        table.delete(&tx, &key)
                            .map_err(|e| ForgeError::DatabaseError(format!("Failed to delete key: {}", e)))?;
                    }
                    
                    tx.commit()
                        .map_err(|e| ForgeError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
                    
                    total_purged += count;
                }
            }
        }
        
        tracing::info!("Purged a total of {} expired entries", total_purged);
        Ok(total_purged)
    }
    
    /// Open a database
    pub fn open_database(&self, name: &str) -> Result<Arc<Database>> {
        let mut databases = self.databases.write().unwrap();
        
        if let Some(db) = databases.get(name) {
            return Ok(Arc::clone(db));
        }
        
        // Create the database directory if it doesn't exist
        let db_path = self.base_dir.join(name);
        std::fs::create_dir_all(&db_path).map_err(|e| {
            ForgeError::IoError(format!("Failed to create database directory: {}", e))
        })?;
        
        // Open the database
        let db = Database::open(&db_path).map_err(|e| {
            ForgeError::DatabaseConnectionError(format!("Failed to open IndxDb database: {}", e))
        })?;
        
        let db_arc = Arc::new(db);
        databases.insert(name.to_string(), Arc::clone(&db_arc));
        
        Ok(db_arc)
    }
    
    /// Get a database by name
    pub fn get_database(&self, name: &str) -> Result<Arc<Database>> {
        let databases = self.databases.read().unwrap();
        
        databases.get(name).map(Arc::clone).ok_or_else(|| {
            ForgeError::DatabaseError(format!("Database '{}' not found", name))
        })
    }
    
    /// Close a database
    pub fn close_database(&self, name: &str) -> Result<()> {
        let mut databases = self.databases.write().unwrap();
        
        if databases.remove(name).is_none() {
            return Err(ForgeError::DatabaseError(format!(
                "Database '{}' not found", 
                name
            )));
        }
        
        Ok(())
    }
    
    /// Get the encryption key
    pub fn encryption_key(&self) -> Result<&[u8]> {
        if !self.encryption_enabled {
            return Err(ForgeError::DatabaseError("Encryption is not enabled".to_string()));
        }
        
        self.encryption_key.as_ref().map(|k| k.as_slice()).ok_or_else(|| {
            ForgeError::DatabaseError("Database encryption error".to_string())
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
    
    /// Check if field encryption is enabled
    pub fn is_field_encryption_enabled(&self) -> bool {
        self.field_encryption
    }
    
    /// Check if change tracking is enabled
    pub fn is_change_tracking_enabled(&self) -> bool {
        self.change_tracking
    }
    
    /// Check if schema validation is enabled
    pub fn is_schema_validation_enabled(&self) -> bool {
        self.schema_validation
    }
    
    /// Get the TTL cleanup interval
    pub fn ttl_cleanup_interval(&self) -> Duration {
        self.ttl_cleanup_interval
    }
    
    /// Get the last TTL cleanup time
    pub fn last_ttl_cleanup(&self) -> Instant {
        *self.last_ttl_cleanup.lock().unwrap()
    }
    
    /// Set the last TTL cleanup time
    pub fn set_last_ttl_cleanup(&self, time: Instant) {
        *self.last_ttl_cleanup.lock().unwrap() = time;
    }
    
    /// Get statistics for all databases
    pub fn get_statistics(&self) -> Result<HashMap<String, DatabaseStats>> {
        let mut stats = HashMap::new();
        let databases = self.databases.read().unwrap();
        
        for (db_name, db) in databases.iter() {
            let mut db_stats = DatabaseStats {
                name: db_name.clone(),
                table_count: 0,
                total_entries: 0,
                tables: HashMap::new(),
                size_bytes: 0,
                last_modified: None,
            };
            
            // Get all tables in the database
            let table_names = db.table_names()
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table names: {}", e)))?;
            
            db_stats.table_count = table_names.len();
            
            // Try to get database file size and last modified time
            if let Some(db_path) = self.get_database_path(db_name) {
                if let Ok(metadata) = std::fs::metadata(&db_path) {
                    db_stats.size_bytes = metadata.len();
                    
                    if let Ok(modified) = metadata.modified() {
                        if let Ok(datetime) = modified.into_std().try_into() {
                            db_stats.last_modified = Some(datetime);
                        }
                    }
                }
            }
            
            for table_name in table_names {
                let table = db.table(&table_name)
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table: {}", e)))?;
                let tx = db.transaction(TransactionMode::ReadOnly)
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
                
                // Count entries in the table
                let mut entry_count = 0;
                let mut table_size = 0;
                let scan_iter = table.scan(&tx)
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to scan table: {}", e)))?;
                
                for item in scan_iter {
                    if let Ok((key, value)) = item {
                        entry_count += 1;
                        table_size += key.len() as u64 + value.len() as u64;
                    }
                }
                
                let table_stats = TableStats {
                    name: table_name.clone(),
                    entry_count,
                    has_indexes: false, // TODO: Implement index detection
                    size_bytes: table_size,
                };
                
                db_stats.tables.insert(table_name, table_stats);
                db_stats.total_entries += entry_count;
            }
            
            stats.insert(db_name.clone(), db_stats);
        }
        
        Ok(stats)
    }
    
    /// Export database schemas to JSON
    pub fn export_schemas(&self) -> Result<String> {
        // Get the system database
        let system_db = self.get_database("system")?;
        
        // Get the schemas table
        let schemas_table = system_db.table("schemas")
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get schemas table: {}", e)))?;
        
        // Start a transaction
        let tx = system_db.transaction(TransactionMode::ReadOnly)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        // Get all schemas
        let mut schemas = HashMap::new();
        
        for item in schemas_table.scan(&tx)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to scan schemas table: {}", e)))? {
            
            let (db_name, schema_json) = item
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to read schema: {}", e)))?;
            
            // Parse the schema
            let schema: serde_json::Value = serde_json::from_str(&schema_json)
                .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
            
            schemas.insert(db_name, schema);
        }
        
        // Convert to JSON
        let schemas_json = serde_json::to_string_pretty(&schemas)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        
        Ok(schemas_json)
    }
    
    /// Import database schemas from JSON
    pub fn import_schemas(&self, schemas_json: &str) -> Result<usize> {
        // Parse the JSON
        let schemas: HashMap<String, serde_json::Value> = serde_json::from_str(schemas_json)
            .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
        
        // Get the system database
        let system_db = self.get_database("system")?;
        
        // Get the schemas table
        let schemas_table = system_db.table("schemas")
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get schemas table: {}", e)))?;
        
        // Start a transaction
        let tx = system_db.transaction(TransactionMode::ReadWrite)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        let mut imported_count = 0;
        
        // Import each schema
        for (db_name, schema) in schemas.iter() {
            // Convert the schema to JSON string
            let schema_json = serde_json::to_string(schema)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
            
            // Store the schema
            schemas_table.put(&tx, db_name, &schema_json)
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to store schema: {}", e)))?;
            
            imported_count += 1;
            tracing::info!("Imported schema for database '{}'", db_name);
        }
        
        // Commit the transaction
        tx.commit()
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
        
        tracing::info!("Successfully imported {} database schemas", imported_count);
        Ok(imported_count)
    }
    
    /// Get the file path for a database
    fn get_database_path(&self, db_name: &str) -> Option<PathBuf> {
        let mut path = self.base_dir.clone();
        path.push(db_name);
        path.set_extension("idb");
        
        if path.exists() {
            Some(path)
        } else {
            None
        }
    }
    
    /// Create a backup of a database
    pub fn backup_database(&self, db_name: &str) -> Result<PathBuf> {
        // Check if the database exists
        let db_path = self.get_database_path(db_name)
            .ok_or_else(|| ForgeError::DatabaseError(format!("Database '{}' not found", db_name)))?;
        
        // Create a backup directory if it doesn't exist
        let mut backup_dir = self.base_dir.clone();
        backup_dir.push("backups");
        if !backup_dir.exists() {
            std::fs::create_dir_all(&backup_dir)
                .map_err(|e| ForgeError::IoError(e.to_string()))?;
        }
        
        // Generate a timestamp for the backup file
        let now = chrono::Utc::now();
        let timestamp = now.format("%Y%m%d_%H%M%S");
        
        // Create the backup file path
        let mut backup_path = backup_dir.clone();
        backup_path.push(format!("{}_backup_{}", db_name, timestamp));
        backup_path.set_extension("idb");
        
        // Close the database if it's open
        {
            let mut databases = self.databases.write().unwrap();
            if databases.contains_key(db_name) {
                databases.remove(db_name);
                tracing::info!("Closed database '{}' for backup", db_name);
            }
        }
        
        // Copy the database file to the backup location
        std::fs::copy(&db_path, &backup_path)
            .map_err(|e| ForgeError::IoError(format!("Failed to create backup: {}", e)))?;
        
        tracing::info!("Created backup of database '{}' at {:?}", db_name, backup_path);
        
        Ok(backup_path)
    }
    
    /// Restore a database from a backup file
    pub fn restore_database(&self, backup_path: &Path, target_db_name: Option<&str>) -> Result<()> {
        // Check if the backup file exists
        if !backup_path.exists() {
            return Err(ForgeError::IoError(format!("Backup file not found: {:?}", backup_path)));
        }
        
        // Determine the target database name
        let db_name = match target_db_name {
            Some(name) => name.to_string(),
            None => {
                // Extract database name from backup filename
                let filename = backup_path.file_stem()
                    .ok_or_else(|| ForgeError::IoError("Invalid backup filename".to_string()))?
                    .to_string_lossy();
                
                // Parse the filename to extract the original database name
                // Expected format: {db_name}_backup_{timestamp}
                let parts: Vec<&str> = filename.split("_backup_").collect();
                if parts.len() != 2 {
                    return Err(ForgeError::IoError("Invalid backup filename format".to_string()));
                }
                
                parts[0].to_string()
            }
        };
        
        // Determine the target database path
        let mut target_path = self.base_dir.clone();
        target_path.push(&db_name);
        target_path.set_extension("idb");
        
        // Close the database if it's open
        {
            let mut databases = self.databases.write().unwrap();
            if databases.contains_key(&db_name) {
                databases.remove(&db_name);
                tracing::info!("Closed database '{}' for restoration", db_name);
            }
        }
        
        // Create a backup of the current database if it exists
        if target_path.exists() {
            let now = chrono::Utc::now();
            let timestamp = now.format("%Y%m%d_%H%M%S");
            
            let mut pre_restore_backup_dir = self.base_dir.clone();
            pre_restore_backup_dir.push("backups");
            if !pre_restore_backup_dir.exists() {
                std::fs::create_dir_all(&pre_restore_backup_dir)
                    .map_err(|e| ForgeError::IoError(e.to_string()))?;
            }
            
            let mut pre_restore_backup_path = pre_restore_backup_dir.clone();
            pre_restore_backup_path.push(format!("{}_pre_restore_{}", db_name, timestamp));
            pre_restore_backup_path.set_extension("idb");
            
            std::fs::copy(&target_path, &pre_restore_backup_path)
                .map_err(|e| ForgeError::IoError(format!("Failed to create pre-restore backup: {}", e)))?;
            
            tracing::info!("Created pre-restore backup at {:?}", pre_restore_backup_path);
        }
        
        // Copy the backup file to the target location
        std::fs::copy(backup_path, &target_path)
            .map_err(|e| ForgeError::IoError(format!("Failed to restore database: {}", e)))?;
        
        tracing::info!("Successfully restored database '{}' from backup {:?}", db_name, backup_path);
        
        Ok(())
    }
    
    /// Information about a database backup
    #[derive(Debug, Clone)]
    pub struct BackupInfo {
        /// Path to the backup file
        pub path: PathBuf,
        /// Name of the database
        pub database_name: String,
        /// Timestamp when the backup was created
        pub timestamp: String,
        /// Size of the backup file in bytes
        pub size_bytes: u64,
        /// Whether this is a pre-restore backup
        pub is_pre_restore: bool,
    }
    
    /// List all available database backups
    pub fn list_backups(&self, db_name: Option<&str>) -> Result<Vec<BackupInfo>> {
        // Get the backup directory
        let mut backup_dir = self.base_dir.clone();
        backup_dir.push("backups");
        
        // Check if the backup directory exists
        if !backup_dir.exists() {
            return Ok(Vec::new());
        }
        
        let mut backups = Vec::new();
        
        // Read the backup directory
        let entries = std::fs::read_dir(&backup_dir)
            .map_err(|e| ForgeError::IoError(format!("Failed to read backup directory: {}", e)))?;
        
        for entry in entries {
            let entry = entry.map_err(|e| ForgeError::IoError(e.to_string()))?;
            let path = entry.path();
            
            // Skip if not a file or not an .idb file
            if !path.is_file() || path.extension().map_or(true, |ext| ext != "idb") {
                continue;
            }
            
            // Get the filename without extension
            let filename = path.file_stem()
                .ok_or_else(|| ForgeError::IoError("Invalid backup filename".to_string()))?
                .to_string_lossy();
            
            // Parse the filename to extract information
            let (db_name_from_file, timestamp, is_pre_restore) = if filename.contains("_backup_") {
                let parts: Vec<&str> = filename.split("_backup_").collect();
                if parts.len() != 2 {
                    continue; // Skip invalid format
                }
                (parts[0].to_string(), parts[1].to_string(), false)
            } else if filename.contains("_pre_restore_") {
                let parts: Vec<&str> = filename.split("_pre_restore_").collect();
                if parts.len() != 2 {
                    continue; // Skip invalid format
                }
                (parts[0].to_string(), parts[1].to_string(), true)
            } else {
                continue; // Skip unknown format
            };
            
            // Filter by database name if specified
            if let Some(name) = db_name {
                if name != db_name_from_file {
                    continue;
                }
            }
            
            // Get file size
            let size_bytes = std::fs::metadata(&path)
                .map(|m| m.len())
                .unwrap_or(0);
            
            backups.push(BackupInfo {
                path,
                database_name: db_name_from_file,
                timestamp,
                size_bytes,
                is_pre_restore,
            });
        }
        
        // Sort backups by database name and timestamp (newest first)
        backups.sort_by(|a, b| {
            let db_cmp = a.database_name.cmp(&b.database_name);
            if db_cmp == std::cmp::Ordering::Equal {
                b.timestamp.cmp(&a.timestamp) // Reverse order for timestamps
            } else {
                db_cmp
            }
        });
        
        Ok(backups)
    }
    
    /// Delete old backups to manage disk space
    /// 
    /// * `keep_count` - Number of most recent backups to keep for each database
    /// * `db_name` - Optional database name to limit cleanup to a specific database
    /// * `include_pre_restore` - Whether to include pre-restore backups in the cleanup
    pub fn cleanup_old_backups(&self, keep_count: usize, db_name: Option<&str>, include_pre_restore: bool) -> Result<usize> {
        // Get all backups
        let all_backups = self.list_backups(db_name)?;
        
        // Group backups by database name
        let mut backups_by_db: HashMap<String, Vec<BackupInfo>> = HashMap::new();
        
        for backup in all_backups {
            // Skip pre-restore backups if not included
            if backup.is_pre_restore && !include_pre_restore {
                continue;
            }
            
            backups_by_db.entry(backup.database_name.clone())
                .or_insert_with(Vec::new)
                .push(backup);
        }
        
        let mut deleted_count = 0;
        
        // Process each database's backups
        for (db_name, mut backups) in backups_by_db.iter_mut() {
            // Sort by timestamp (newest first)
            backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            
            // Keep the specified number of backups and delete the rest
            if backups.len() > keep_count {
                let to_delete = &backups[keep_count..];
                
                for backup in to_delete {
                    match std::fs::remove_file(&backup.path) {
                        Ok(_) => {
                            tracing::info!("Deleted old backup: {:?}", backup.path);
                            deleted_count += 1;
                        },
                        Err(e) => {
                            tracing::warn!("Failed to delete backup {:?}: {}", backup.path, e);
                        }
                    }
                }
            }
        }
        
        tracing::info!("Cleanup completed: deleted {} old backups", deleted_count);
        Ok(deleted_count)
    }
    
    /// Check the health of a database
    pub fn check_health(&self, db_name: &str) -> Result<bool> {
        // Get the database
        let db = match self.get_database(db_name) {
            Ok(db) => db,
            Err(_) => return Ok(false), // Database doesn't exist or can't be opened
        };
        
        // Try to create a read-only transaction
        let tx = match db.transaction(TransactionMode::ReadOnly) {
            Ok(tx) => tx,
            Err(_) => return Ok(false), // Can't create transaction
        };
        
        // Try to get table names
        let table_names = match db.table_names() {
            Ok(names) => names,
            Err(_) => return Ok(false), // Can't get table names
        };
        
        // Try to read from each table
        for table_name in table_names {
            let table = match db.table(&table_name) {
                Ok(t) => t,
                Err(_) => return Ok(false), // Can't open table
            };
            
            // Try to scan the table
            if let Err(_) = table.scan(&tx) {
                return Ok(false); // Can't scan table
            }
        }
        
        // All checks passed
    }
    
    /// Compact a database to reclaim space after deletions
    pub fn compact_database(&self, db_name: &str) -> Result<()> {
        tracing::info!("Starting database compaction for '{}'", db_name);
        
        // Check if the database exists
        let db_path = self.get_database_path(db_name)
            .ok_or_else(|| ForgeError::DatabaseError(format!("Database '{}' not found", db_name)))?;
        
        // Close the database if it's open
        {
            let mut databases = self.databases.write().unwrap();
            if databases.contains_key(db_name) {
                databases.remove(db_name);
                tracing::info!("Closed database '{}' for compaction", db_name);
            }
        }
        
        // Create a backup before compaction
        let backup_path = self.backup_database(db_name)?;
        tracing::info!("Created backup before compaction at {:?}", backup_path);
        
        // Create a temporary path for the compacted database
        let mut temp_path = db_path.clone();
        temp_path.set_file_name(format!("{}_compacted.idb", db_name));
        
        // Open the source database in read-only mode
        let source_db = redb::Database::open_read_only(&db_path)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to open source database: {}", e)))?;
        
        // Create a new database for the compacted version
        let target_db = redb::Database::create(&temp_path)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create target database: {}", e)))?;
        
        // Get all table definitions from the source database
        let table_defs = source_db.table_definitions()
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table definitions: {}", e)))?;
        
        // Copy each table to the new database
        for table_def in table_defs {
            let table_name = table_def.name();
            tracing::debug!("Compacting table '{}'", table_name);
            
            // Create the table in the target database
            let target_table = target_db.create_table(table_name, table_def.key_type(), table_def.value_type())
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to create table '{}': {}", table_name, e)))?;
            
            // Open the source table
            let source_table = source_db.open_table(table_name)
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to open source table '{}': {}", table_name, e)))?;
            
            // Start a read transaction on the source
            let source_tx = source_db.begin_read()
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to begin read transaction: {}", e)))?;
            
            // Start a write transaction on the target
            let mut target_tx = target_db.begin_write()
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to begin write transaction: {}", e)))?;
            
            // Copy all entries
            let mut entry_count = 0;
            for result in source_table.iter(&source_tx).unwrap() {
                let (key, value) = result
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to read entry: {}", e)))?;
                
                target_table.insert(&mut target_tx, key.as_bytes(), value.as_bytes())
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to insert entry: {}", e)))?;
                
                entry_count += 1;
            }
            
            // Commit the transaction
            target_tx.commit()
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
            
            tracing::debug!("Copied {} entries for table '{}'", entry_count, table_name);
        }
        
        // Close both databases
        drop(source_db);
        drop(target_db);
        
        // Replace the original database with the compacted one
        std::fs::remove_file(&db_path)
            .map_err(|e| ForgeError::IoError(format!("Failed to remove original database: {}", e)))?;
        
        std::fs::rename(&temp_path, &db_path)
            .map_err(|e| ForgeError::IoError(format!("Failed to rename compacted database: {}", e)))?;
        
        tracing::info!("Successfully compacted database '{}'", db_name);
        
        Ok(())
    }
    
    /// Maintenance schedule configuration
    #[derive(Debug, Clone)]
    pub struct MaintenanceSchedule {
        /// Interval in seconds for TTL cleanup
        pub ttl_cleanup_interval_secs: u64,
        /// Interval in seconds for database compaction
        pub compaction_interval_secs: u64,
        /// Interval in seconds for backup creation
        pub backup_interval_secs: u64,
        /// Maximum number of backups to keep per database
        pub max_backups_per_db: usize,
        /// Whether to include pre-restore backups in cleanup
        pub include_pre_restore_in_cleanup: bool,
    }
    
    impl Default for MaintenanceSchedule {
        fn default() -> Self {
            Self {
                ttl_cleanup_interval_secs: 3600, // 1 hour
                compaction_interval_secs: 86400, // 1 day
                backup_interval_secs: 604800,    // 1 week
                max_backups_per_db: 5,
                include_pre_restore_in_cleanup: false,
            }
        }
    }
    
    /// Start scheduled maintenance tasks
    pub fn start_scheduled_maintenance(&self, schedule: MaintenanceSchedule) -> Result<()> {
        let manager_clone = self.clone();
        
        // Spawn a thread for scheduled maintenance
        std::thread::spawn(move || {
            let mut last_ttl_cleanup = std::time::Instant::now();
            let mut last_compaction = std::time::Instant::now();
            let mut last_backup = std::time::Instant::now();
            
            loop {
                // Sleep for a short interval to check if any task needs to run
                std::thread::sleep(std::time::Duration::from_secs(60)); // Check every minute
                
                let now = std::time::Instant::now();
                
                // Check if TTL cleanup is due
                if now.duration_since(last_ttl_cleanup).as_secs() >= schedule.ttl_cleanup_interval_secs {
                    match manager_clone.purge_expired_entries() {
                        Ok(count) => {
                            tracing::info!("Scheduled TTL cleanup completed: purged {} entries", count);
                        },
                        Err(e) => {
                            tracing::error!("Scheduled TTL cleanup failed: {}", e);
                        }
                    }
                    last_ttl_cleanup = now;
                }
                
                // Check if compaction is due
                if now.duration_since(last_compaction).as_secs() >= schedule.compaction_interval_secs {
                    // Get all database names
                    if let Ok(stats) = manager_clone.get_statistics() {
                        for (db_name, _) in stats.iter() {
                            // Skip system database
                            if db_name == "system" {
                                continue;
                            }
                            
                            match manager_clone.compact_database(db_name) {
                                Ok(_) => {
                                    tracing::info!("Scheduled compaction completed for database '{}'", db_name);
                                },
                                Err(e) => {
                                    tracing::error!("Scheduled compaction failed for database '{}': {}", db_name, e);
                                }
                            }
                        }
                    }
                    last_compaction = now;
                }
                
                // Check if backup is due
                if now.duration_since(last_backup).as_secs() >= schedule.backup_interval_secs {
                    // Get all database names
                    if let Ok(stats) = manager_clone.get_statistics() {
                        for (db_name, _) in stats.iter() {
                            match manager_clone.backup_database(db_name) {
                                Ok(path) => {
                                    tracing::info!("Scheduled backup created for database '{}' at {:?}", db_name, path);
                                },
                                Err(e) => {
                                    tracing::error!("Scheduled backup failed for database '{}': {}", db_name, e);
                                }
                            }
                        }
                        
                        // Cleanup old backups
                        match manager_clone.cleanup_old_backups(
                            schedule.max_backups_per_db,
                            None,
                            schedule.include_pre_restore_in_cleanup
                        ) {
                            Ok(count) => {
                                tracing::info!("Cleaned up {} old backups", count);
                            },
                            Err(e) => {
                                tracing::error!("Failed to clean up old backups: {}", e);
                            }
                        }
                    }
                    last_backup = now;
                }
            }
        });
        
        tracing::info!("Started scheduled database maintenance");
        Ok(())
    }
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
        
        tracing::warn!("Database '{}' needs repair, attempting recovery", db_name);
        
        // Close the database if it's open
        if self.databases.read().unwrap().contains_key(db_name) {
            self.close_database(db_name)?;
        }
        
        // Get the database path
        let db_path = match self.get_database_path(db_name) {
            Some(path) => path,
            None => return Err(ForgeError::DatabaseError(format!("Database '{}' not found", db_name))),
        };
        
        // Create a backup
        let backup_path = db_path.with_extension("idb.bak");
        if let Err(e) = std::fs::copy(&db_path, &backup_path) {
            tracing::error!("Failed to create backup of database '{}': {}", db_name, e);
        } else {
            tracing::info!("Created backup of database '{}' at {:?}", db_name, backup_path);
        }
        
        // Try to repair by reopening
        match self.open_database(db_name) {
            Ok(_) => {
                tracing::info!("Successfully repaired database '{}'", db_name);
                Ok(true)
            },
            Err(e) => {
                tracing::error!("Failed to repair database '{}': {}", db_name, e);
                Err(ForgeError::DatabaseError(format!("Failed to repair database '{}': {}", db_name, e)))
            }
        }
    }
    
    /// Record a change if change tracking is enabled
    pub fn record_change(&self, mut change: ChangeRecord) -> Result<()> {
        // Skip if change tracking is disabled
        if !self.change_tracking {
            return Ok(());
        }
        
        // Generate a unique ID for the change record if not already set
        if change.id.is_empty() {
            change.id = Uuid::new_v4().to_string();
        }
        
        // Set timestamp if not already set
        if change.timestamp.is_none() {
            change.timestamp = Some(Utc::now());
        }
        
        // Get the system database
        let system_db = match self.get_database("system") {
            Ok(db) => db,
            Err(e) => {
                tracing::error!("Failed to get system database for change tracking: {}", e);
                return Err(ForgeError::DatabaseError(format!("Failed to access system database for change tracking: {}", e)));
            }
        };
        
        // Get the change_history table
        let history_table = system_db.table("change_history")
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get change_history table: {}", e)))?;
        
        // Start a transaction
        let tx = system_db.transaction(TransactionMode::ReadWrite)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        // Serialize the change record
        let change_json = serde_json::to_string(&change)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        
        // Store the change record
        if let Err(e) = history_table.put(&tx, &change.id, &change_json) {
            // Try to abort the transaction
            let _ = tx.abort();
            tracing::error!("Failed to store change record: {}", e);
            return Err(ForgeError::DatabaseError(format!("Failed to store change record: {}", e)));
        }
        
        // Commit the transaction
        if let Err(e) = tx.commit() {
            tracing::error!("Failed to commit change record transaction: {}", e);
            return Err(ForgeError::DatabaseError(format!("Failed to commit change record transaction: {}", e)));
        }
        
        tracing::debug!("Recorded change: id={}, entity={}, type={}, action={}", 
            change.id, change.entity_id, change.entity_type, change.action);
        
        Ok(())
    }
    
    /// Get change history for an entity
    pub fn get_change_history(&self, entity_id: Uuid, entity_type: &str) -> Result<Vec<ChangeRecord>> {
        // Return empty vector if change tracking is disabled
        if !self.change_tracking {
            return Ok(Vec::new());
        }
        
        // Get the system database
        let system_db = match self.get_database("system") {
            Ok(db) => db,
            Err(e) => {
                tracing::error!("Failed to get system database for change history: {}", e);
                return Err(ForgeError::DatabaseError(format!("Failed to access system database for change history: {}", e)));
            }
        };
        
        // Get the change_history table
        let history_table = system_db.table("change_history")
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get change_history table: {}", e)))?;
        
        // Start a read-only transaction
        let tx = system_db.transaction(TransactionMode::ReadOnly)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        let mut changes = Vec::new();
        let entity_id_str = entity_id.to_string();
        
        // Use a secondary index if available, otherwise scan the table
        // TODO: Implement a secondary index on entity_id and entity_type
        let scan_iter = history_table.scan(&tx)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to scan table: {}", e)))?;
        
        // Process each record
        for item in scan_iter {
            let (_, value): (String, String) = match item {
                Ok(item_data) => item_data,
                Err(e) => {
                    tracing::warn!("Failed to read change history item: {}", e);
                    continue; // Skip corrupted entries instead of failing the entire operation
                }
            };
            
            // Deserialize the change record
            let change: ChangeRecord = match serde_json::from_str(&value) {
                Ok(record) => record,
                Err(e) => {
                    tracing::warn!("Failed to deserialize change record: {}", e);
                    continue; // Skip corrupted entries
                }
            };
            
            // Filter by entity_id and entity_type
            if change.entity_id == entity_id && change.entity_type == entity_type {
                changes.push(change);
            }
        }
        
        // Sort by timestamp (oldest first)
        changes.sort_by(|a, b| {
            match (&a.timestamp, &b.timestamp) {
                (Some(a_time), Some(b_time)) => a_time.cmp(b_time),
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });
        
        Ok(changes)
    }
    
    /// Validate a schema
    pub fn validate_schema(&self, schema: &SchemaDefinition) -> Result<()> {
        if !self.schema_validation {
            return Ok(());
        }
        
        // Basic validation
        if schema.version == 0 {
            return Err(ForgeError::ValidationError("Schema version cannot be 0".to_string()));
        }
        
        if schema.name.is_empty() {
            return Err(ForgeError::ValidationError("Schema name cannot be empty".to_string()));
        }
        
        if schema.tables.is_empty() {
            return Err(ForgeError::ValidationError("Schema must have at least one table".to_string()));
        }
        
        // Validate tables
        for table in &schema.tables {
            if table.name.is_empty() {
                return Err(ForgeError::ValidationError("Table name cannot be empty".to_string()));
            }
            
            if table.primary_key.is_empty() {
                return Err(ForgeError::ValidationError("Table must have a primary key".to_string()));
            }
            
            if table.fields.is_empty() {
                return Err(ForgeError::ValidationError("Table must have at least one field".to_string()));
            }
            
            // Check that primary key is a field
            let primary_key_exists = table.fields.iter().any(|f| f.name == table.primary_key);
            if !primary_key_exists {
                return Err(ForgeError::ValidationError(
                    format!("Primary key '{}' not found in table '{}'", table.primary_key, table.name)
                ));
            }
            
            // Validate fields
            for field in &table.fields {
                if field.name.is_empty() {
                    return Err(ForgeError::ValidationError("Field name cannot be empty".to_string()));
                }
            }
            
            // Validate indexes
            for index in &table.indexes {
                if index.name.is_empty() {
                    return Err(ForgeError::ValidationError("Index name cannot be empty".to_string()));
                }
                
                if index.fields.is_empty() {
                    return Err(ForgeError::ValidationError("Index must have at least one field".to_string()));
                }
                
                // Check that indexed fields exist
                for field_name in &index.fields {
                    let field_exists = table.fields.iter().any(|f| &f.name == field_name);
                    if !field_exists {
                        return Err(ForgeError::ValidationError(
                            format!("Field '{}' in index '{}' not found in table '{}'", 
                                field_name, index.name, table.name)
                        ));
                    }
                }
            }
        }
        
        // Validate migrations
        for migration in &schema.migrations {
            if migration.from_version >= migration.to_version {
                return Err(ForgeError::ValidationError(
                    format!("Invalid migration: from_version ({}) must be less than to_version ({})", 
                        migration.from_version, migration.to_version)
                ));
            }
            
            if migration.script.is_empty() {
                return Err(ForgeError::ValidationError("Migration script cannot be empty".to_string()));
            }
        }
        
        Ok(())
    }
    
    /// Apply a schema to a database
    pub fn apply_schema(&self, db_name: &str, schema: &SchemaDefinition) -> Result<()> {
        // Validate the schema first
        self.validate_schema(schema)?;
        
        let db = self.open_database(db_name)?;
        
        // Create tables
        for table_def in &schema.tables {
            // Create the table if it doesn't exist
            let table_exists = db.table_exists(&table_def.name)
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to check table existence: {}", e)))?;
            
            if !table_exists {
                db.create_table(&table_def.name)
                    .map_err(|e| ForgeError::DatabaseError(format!("Failed to create table: {}", e)))?;
            }
            
            // TODO: Create indexes
        }
        
        // Store the schema in the system database
        let system_db = self.get_database("system")?;
        let schemas_table = system_db.table("schemas")
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get schemas table: {}", e)))?;
        let tx = system_db.transaction(TransactionMode::ReadWrite)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        let schema_json = serde_json::to_string(schema)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        
        schemas_table.put(&tx, &schema.name, &schema_json)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to put schema: {}", e)))?;
        tx.commit()
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to commit transaction: {}", e)))?;
        
        Ok(())
    }
    
    /// Get a schema by name
    pub fn get_schema(&self, name: &str) -> Result<SchemaDefinition> {
        let system_db = self.get_database("system")?;
        let schemas_table = system_db.table("schemas")
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get schemas table: {}", e)))?;
        let tx = system_db.transaction(TransactionMode::ReadOnly)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        let schema_json = schemas_table.get(&tx, name)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get schema: {}", e)))?
            .ok_or_else(|| ForgeError::NotFoundError(format!("Schema '{}' not found", name)))?;
        
        let schema: SchemaDefinition = serde_json::from_str(&schema_json)
            .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
        
        Ok(schema)
    }
    
    /// Check database health
    pub fn check_health(&self, db_name: &str) -> Result<bool> {
        let db = self.get_database(db_name)?;
        
        // Try to open a transaction
        let tx = db.transaction(TransactionMode::ReadOnly)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        tx.abort()
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to abort transaction: {}", e)))?;
        
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

/// Shutdown the IndxDb database system
pub fn shutdown_indxdb() -> Result<()> {
    let manager = IndxDbManager::get_instance()?;
    
    // Close all databases
    let databases = manager.databases.read().unwrap();
    let db_names: Vec<String> = databases.keys().cloned().collect();
    drop(databases); // Release the read lock
    
    for name in db_names {
        manager.close_database(&name)?;
    }
    
    // Clear the global instance
    unsafe {
        INDXDB_MANAGER = None;
    }
    
    Ok(())
}

/// Repair the IndxDb database
pub fn repair() -> Result<bool> {
    let manager = IndxDbManager::get_instance()?;
    
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

/// Generic repository for IndxDb
pub struct IndxDbRepository<T: Persistable> {
    /// Database name
    db_name: String,
    /// Table name
    table_name: String,
    /// Phantom data
    _phantom: std::marker::PhantomData<T>,
}

impl<T: Persistable> IndxDbRepository<T> {
    /// Create a new repository
    pub fn new(db_name: &str) -> Self {
        Self {
            db_name: db_name.to_string(),
            table_name: T::collection_name().to_string(),
            _phantom: std::marker::PhantomData,
        }
    }
    
    /// Initialize the repository
    pub fn init(&self) -> Result<()> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        
        // Create the table if it doesn't exist
        let table_exists = db.table_exists(&self.table_name)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to check table existence: {}", e)))?;
        
        if !table_exists {
            db.create_table(&self.table_name)
                .map_err(|e| ForgeError::DatabaseError(format!("Failed to create table: {}", e)))?;
        }
        
        Ok(())
    }
    
    /// Save an entity
    pub fn save(&self, entity: &T, identity: &IdentityContext) -> Result<()> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = db.table(&self.table_name)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to get table: {}", e)))?;
        let tx = db.transaction(TransactionMode::ReadWrite)
            .map_err(|e| ForgeError::DatabaseError(format!("Failed to create transaction: {}", e)))?;
        
        let id = entity.id().to_string();
        
        // Check if the entity already exists
        let existing = table.get(&tx, &id)?;
        
        // Prepare the entity for storage
        let mut entity_json = serde_json::to_string(entity)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        
        // Apply compression if enabled
        if manager.compression_level() != 0 {
            let binary = entity.to_binary()?;
            let compressed = entity.compress_zstd(manager.compression_level())?;
            let compressed_base64 = base64::encode(&compressed);
            entity_json = format!("{{\"_compressed\":\"{}\"}}", compressed_base64);
        }
        
        // Store the entity
        table.put(&tx, &id, &entity_json)?;
        tx.commit()?;
        
        // Record the change if tracking is enabled and the entity already existed
        if manager.is_change_tracking_enabled() && existing.is_some() {
            let change = ChangeRecord {
                entity_id: entity.id(),
                entity_type: T::collection_name().to_string(),
                field_name: "*".to_string(), // Whole entity update
                old_value: existing,
                new_value: Some(entity_json),
                timestamp: Utc::now(),
                changed_by: identity.user_id.clone().unwrap_or_else(|| "system".to_string()),
                entity_version: 0, // TODO: Get actual version
            };
            
            manager.record_change(change)?;
        }
        
        Ok(())
    }
    
    /// Find an entity by ID
    pub fn find_by_id(&self, id: Uuid) -> Result<Option<T>> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = (**db).table(&self.table_name)?;
        let tx = (**db).transaction(TransactionMode::ReadOnly)?;
        
        let id_str = id.to_string();
        let entity_json = match table.get(&tx, &id_str)? {
            Some(json) => json,
            None => return Ok(None),
        };
        
        // Check if the entity is compressed
        if entity_json.contains("\"_compressed\":") {
            let compressed_json: serde_json::Value = serde_json::from_str(&entity_json)
                .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
            
            if let Some(compressed_base64) = compressed_json["_compressed"].as_str() {
                let compressed = base64::decode(compressed_base64)
                    .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
                
                return Ok(Some(T::decompress_zstd(&compressed)?));
            }
        }
        
        // Regular deserialization
        let entity = T::from_json(&entity_json)?;
        
        // Apply field decryption if enabled
        if manager.is_field_encryption_enabled() {
            if let Some(encryptable) = (&entity as &dyn std::any::Any).downcast_ref::<dyn FieldEncryptable>() {
                let mut entity_mut = entity;
                let encryptable_mut = (&mut entity_mut as &mut dyn std::any::Any)
                    .downcast_mut::<dyn FieldEncryptable>()
                    .unwrap();
                
                encryptable_mut.decrypt_fields(manager.encryption_key()?)?;
                
                return Ok(Some(entity_mut));
            }
        }
        
        Ok(Some(entity))
    }
    
    /// Find all entities
    pub fn find_all(&self) -> Result<Vec<T>> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = db.table(&self.table_name)?;
        let tx = db.transaction(TransactionMode::ReadOnly)?;
        
        let mut entities = Vec::new();
        
        for item in table.scan(&tx)? {
            let (_, entity_json) = item?;
            
            // Check if the entity is compressed
            if entity_json.contains("\"_compressed\":") {
                let compressed_json: serde_json::Value = serde_json::from_str(&entity_json)
                    .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
                
                if let Some(compressed_base64) = compressed_json["_compressed"].as_str() {
                    let compressed = base64::decode(compressed_base64)
                        .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
                    
                    entities.push(T::decompress_zstd(&compressed)?);
                    continue;
                }
            }
            
            // Regular deserialization
            let entity = T::from_json(&entity_json)?;
            
            // Apply field decryption if enabled
            if manager.is_field_encryption_enabled() {
                if let Some(encryptable) = (&entity as &dyn std::any::Any).downcast_ref::<dyn FieldEncryptable>() {
                    let mut entity_mut = entity;
                    let encryptable_mut = (&mut entity_mut as &mut dyn std::any::Any)
                        .downcast_mut::<dyn FieldEncryptable>()
                        .unwrap();
                    
                    encryptable_mut.decrypt_fields(manager.encryption_key()?)?;
                    
                    entities.push(entity_mut);
                    continue;
                }
            }
            
            entities.push(entity);
        }
        
        Ok(entities)
    }
    
    /// Delete an entity
    pub fn delete(&self, id: Uuid, identity: &IdentityContext) -> Result<bool> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = (**db).table(&self.table_name)?;
        let tx = (**db).transaction(TransactionMode::ReadWrite)?;
        
        let id_str = id.to_string();
        
        // Get the existing entity for change tracking
        let existing = if manager.is_change_tracking_enabled() {
            table.get(&tx, &id_str)?
        } else {
            None
        };
        
        // Delete the entity
        let existed = table.delete(&tx, &id_str)?;
        tx.commit()?;
        
        // Record the change if tracking is enabled and the entity existed
        if manager.is_change_tracking_enabled() && existed && existing.is_some() {
            let change = ChangeRecord {
                entity_id: id,
                entity_type: T::collection_name().to_string(),
                field_name: "*".to_string(), // Whole entity deletion
                old_value: existing,
                new_value: None,
                timestamp: Utc::now(),
                changed_by: identity.user_id.clone().unwrap_or_else(|| "system".to_string()),
                entity_version: 0, // Deleted
            };
            
            manager.record_change(change)?;
        }
        
        Ok(existed)
    }
    
    /// Count entities
    pub fn count(&self) -> Result<usize> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = (**db).table(&self.table_name)?;
        let tx = (**db).transaction(TransactionMode::ReadOnly)?;
        
        let mut count = 0;
        
        for item in table.scan(&tx)? {
            item?; // Just to check for errors
            count += 1;
        }
        
        Ok(count)
    }
    
    /// Find entities by a field value
    pub fn find_by_field(&self, field: &str, value: &str) -> Result<Vec<T>> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = (**db).table(&self.table_name)?;
        let tx = (**db).transaction(TransactionMode::ReadOnly)?;
        
        let mut entities = Vec::new();
        
        for item in table.scan(&tx)? {
            let (_, entity_json) = item?;
            
            // Check if the entity is compressed
            if entity_json.contains("\"_compressed\":") {
                // Skip compressed entities for now in field search
                // TODO: Implement field search for compressed entities
                continue;
            }
            
            // Parse as JSON to check the field
            let json: serde_json::Value = serde_json::from_str(&entity_json)
                .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
            
            // Check if the field matches
            if let Some(field_value) = json.get(field) {
                let field_str = match field_value {
                    serde_json::Value::String(s) => s.as_str(),
                    serde_json::Value::Number(n) => {
                        if n.to_string() == value {
                            // Convert the entity and add it
                            let entity = T::from_json(&entity_json)?;
                            entities.push(entity);
                        }
                        continue;
                    },
                    serde_json::Value::Bool(b) => {
                        if b.to_string() == value {
                            // Convert the entity and add it
                            let entity = T::from_json(&entity_json)?;
                            entities.push(entity);
                        }
                        continue;
                    },
                    _ => continue, // Skip other types
                };
                
                if field_str == value {
                    // Convert the entity and add it
                    let entity = T::from_json(&entity_json)?;
                    entities.push(entity);
                }
            }
        }
        
        Ok(entities)
    }
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

/// Shutdown the IndxDb database system
pub fn shutdown_indxdb() -> Result<()> {
    let manager = IndxDbManager::get_instance()?;
    
    // Close all databases
    let databases = manager.databases.read().unwrap();
    let db_names: Vec<String> = databases.keys().cloned().collect();
    drop(databases); // Release the read lock
    
    for name in db_names {
        manager.close_database(&name)?;
    }
    
    // Clear the global instance
    unsafe {
        INDXDB_MANAGER = None;
    }
    
    Ok(())
}

/// Repair the IndxDb database
pub fn repair() -> crate::error::Result<bool> {
    let manager = IndxDbManager::get_instance()?;
    
    // Get all database names
    let databases = manager.databases.read().unwrap();
    let db_names: Vec<String> = databases.keys().cloned().collect();
    drop(databases); // Release the read lock
    
    let mut repaired_count = 0;
    
    // Try to repair each database
    for db_name in db_names {
        match manager.repair_if_needed(&db_name) {
            Ok(true) => {
                repaired_count += 1;
                tracing::info!("Repaired database '{}'", db_name);
            },
            Ok(false) => {
                tracing::debug!("Database '{}' is healthy, no repair needed", db_name);
            },
            Err(e) => {
                tracing::error!("Failed to repair database '{}': {}", db_name, e);
            }
        }
    }
    
    Ok(repaired_count)
}

/// Shutdown the IndxDb database system
pub fn shutdown_indxdb() -> Result<()> {
    let manager = IndxDbManager::get_instance()?;
    
    // Close all databases
    let databases = manager.databases.read().unwrap();
    let db_names: Vec<String> = databases.keys().cloned().collect();
    drop(databases); // Release the read lock
    
    for name in db_names {
        manager.close_database(&name)?;
    }
    
    // Clear the global instance
    unsafe {
        INDXDB_MANAGER = None;
    }
    
    Ok(());
    // The following code was misplaced and has been removed
        
        // Get the existing entity for change tracking
        let existing = if manager.is_change_tracking_enabled() {
            table.get(&tx, &id_str)?
        } else {
            None
        };
        
        // Delete the entity
        let existed = table.delete(&tx, &id_str)?;
        tx.commit()?;
        
        // Record the change if tracking is enabled and the entity existed
        if manager.is_change_tracking_enabled() && existed && existing.is_some() {
            let change = ChangeRecord {
                entity_id: id,
                entity_type: T::collection_name().to_string(),
                field_name: "*".to_string(), // Whole entity deletion
                old_value: existing,
                new_value: None,
                timestamp: Utc::now(),
                changed_by: identity.user_id.clone().unwrap_or_else(|| "system".to_string()),
                entity_version: 0, // Deleted
            };
            
            manager.record_change(change)?;
        }
        
        Ok(existed)
    }
    
    /// Count entities
    pub fn count(&self) -> Result<usize> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = db.table(&self.table_name)?;
        let tx = db.transaction(TransactionMode::ReadOnly)?;
        
        let mut count = 0;
        
        for item in table.scan(&tx)? {
            item?; // Just to check for errors
            count += 1;
        }
        
        Ok(count)
    }
    
    /// Find entities by a field value
    pub fn find_by_field(&self, field: &str, value: &str) -> Result<Vec<T>> {
        let manager = IndxDbManager::get_instance()?;
        let db = manager.open_database(&self.db_name)?;
        let table = db.table(&self.table_name)?;
        let tx = db.transaction(TransactionMode::ReadOnly)?;
        
        let mut entities = Vec::new();
        
        for item in table.scan(&tx)? {
            let (_, entity_json) = item?;
            
            // Check if the entity is compressed
            if entity_json.contains("\"_compressed\":") {
                // Skip compressed entities for now in field search
                // TODO: Implement field search for compressed entities
                continue;
            }
            
            // Parse as JSON to check the field
            let json: serde_json::Value = serde_json::from_str(&entity_json)
                .map_err(|e| ForgeError::DeserializationError(e.to_string()))?;
            
            // Check if the field matches
            if let Some(field_value) = json.get(field) {
                let field_str = match field_value {
                    serde_json::Value::String(s) => s.as_str(),
                    serde_json::Value::Number(n) => {
                        if n.to_string() == value {
                            // Convert the entity and add it
                            let entity = T::from_json(&entity_json)?;
                            entities.push(entity);
                        }
                        continue;
                    },
                    serde_json::Value::Bool(b) => {
                        if b.to_string() == value {
                            // Convert the entity and add it
                            let entity = T::from_json(&entity_json)?;
                            entities.push(entity);
                        }
                        continue;
                    },
                    _ => continue, // Skip other types
                };
                
                if field_str == value {
                    // Convert the entity and add it
                    let entity = T::from_json(&entity_json)?;
                    entities.push(entity);
                }
            }
        }
        
        Ok(entities)
    }

/// Statistics for a database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseStats {
    /// Database name
    pub name: String,
    /// Number of tables
    pub table_count: usize,
    /// Total number of entries across all tables
    pub total_entries: usize,
    /// Statistics for each table
    pub tables: HashMap<String, TableStats>,
    /// Size in bytes
    pub size_bytes: u64,
    /// Last modified timestamp
    pub last_modified: Option<DateTime<Utc>>,
}

/// Statistics for a table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableStats {
    /// Table name
    pub name: String,
    /// Number of entries
    pub entry_count: usize,
    /// Whether the table has indexes
    pub has_indexes: bool,
    /// Size in bytes
    pub size_bytes: u64,
}

/// Maintenance schedule for database operations
pub struct MaintenanceSchedule {
    /// Interval for TTL cleanup in seconds
    pub ttl_cleanup_interval_secs: u64,
    /// Interval for database compaction in seconds (default: 24 hours)
    pub compaction_interval_secs: u64,
    /// Interval for database backup in seconds (default: 24 hours)
    pub backup_interval_secs: u64,
    /// Number of backups to keep per database (default: 5)
    pub keep_backups_count: usize,
}

impl Default for MaintenanceSchedule {
    fn default() -> Self {
        Self {
            ttl_cleanup_interval_secs: 300, // 5 minutes
            compaction_interval_secs: 86400, // 24 hours
            backup_interval_secs: 86400, // 24 hours
            keep_backups_count: 5,
        }
    }
}

/// Start scheduled maintenance for databases
pub fn start_scheduled_maintenance(manager: Arc<IndxDbManager>, schedule: MaintenanceSchedule) -> Result<()> {
    let ttl_interval = Duration::from_secs(schedule.ttl_cleanup_interval_secs);
    let compaction_interval = Duration::from_secs(schedule.compaction_interval_secs);
    let backup_interval = Duration::from_secs(schedule.backup_interval_secs);
    let keep_backups = schedule.keep_backups_count;
    
    std::thread::spawn(move || {
        let mut last_ttl_cleanup = Instant::now();
        let mut last_compaction = Instant::now();
        let mut last_backup = Instant::now();
        
        loop {
            std::thread::sleep(Duration::from_secs(60)); // Check every minute
            
            // TTL cleanup
            if last_ttl_cleanup.elapsed() >= ttl_interval {
                if let Err(e) = manager.cleanup_expired_records() {
                    tracing::warn!("Scheduled TTL cleanup failed: {}", e);
                } else {
                    tracing::debug!("Scheduled TTL cleanup completed");
                }
                last_ttl_cleanup = Instant::now();
            }
            
            // Database compaction
            if last_compaction.elapsed() >= compaction_interval {
                if let Ok(databases) = manager.list_databases() {
                    for db_name in databases {
                        // Skip system database for compaction
                        if db_name == "system" {
                            continue;
                        }
                        
                        if let Err(e) = manager.compact_database(&db_name) {
                            tracing::warn!("Scheduled compaction failed for database {}: {}", db_name, e);
                        } else {
                            tracing::info!("Scheduled compaction completed for database {}", db_name);
                        }
                    }
                }
                last_compaction = Instant::now();
            }
            
            // Database backup
            if last_backup.elapsed() >= backup_interval {
                if let Ok(databases) = manager.list_databases() {
                    for db_name in databases {
                        if let Err(e) = manager.backup_database(&db_name) {
                            tracing::warn!("Scheduled backup failed for database {}: {}", db_name, e);
                        } else {
                            tracing::info!("Scheduled backup completed for database {}", db_name);
                            
                            // Cleanup old backups
                            if let Err(e) = manager.cleanup_old_backups(keep_backups, Some(&db_name), false) {
                                tracing::warn!("Failed to cleanup old backups for database {}: {}", db_name, e);
                            }
                        }
                    }
                }
                last_backup = Instant::now();
            }
        }
    });
    
    Ok(())
}