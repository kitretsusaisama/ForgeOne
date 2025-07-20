//! # Database models for ForgeOne
//!
//! This module provides traits and implementations for database-persisted models.
//! It includes the Persistable trait for types that can be stored in databases,
//! as well as serialization, versioning, and indexing support.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;

/// Storage backend type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageBackend {
    /// IndxDb storage backend (for metadata and user access control)
    IndxDb,
    /// Redb storage backend (for logs, blobs, events, and snapshots)
    Redb,
    /// Memory storage backend (for testing)
    Memory,
}

/// Trait for types that can be stored in a database
pub trait Persistable: Serialize + for<'de> Deserialize<'de> + Send + Sync + 'static {
    /// Get the unique ID for this entity
    fn id(&self) -> Uuid;
    
    /// Get the table or collection name for this entity
    fn collection_name() -> &'static str;
    
    /// Get the preferred storage backend for this entity
    fn preferred_backend() -> StorageBackend;
    
    /// Get the schema version for this entity
    fn schema_version() -> u32;
    
    /// Get the indexes for this entity
    fn indexes() -> Vec<IndexDefinition>;
    
    /// Convert this entity to a JSON string
    fn to_json(&self) -> Result<String> {
        serde_json::to_string(self)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))
    }
    
    /// Convert this entity to a binary representation
    fn to_binary(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))
    }
    
    /// Create an entity from a JSON string
    fn from_json(json: &str) -> Result<Self> where Self: Sized {
        serde_json::from_str(json)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))
    }
    
    /// Create an entity from a binary representation
    fn from_binary(binary: &[u8]) -> Result<Self> where Self: Sized {
        bincode::deserialize(binary)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))
    }
}

/// Index definition for a database entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexDefinition {
    /// The name of the index
    pub name: String,
    /// The fields to index
    pub fields: Vec<String>,
    /// Whether the index is unique
    pub unique: bool,
    /// Whether the index is sparse (only index documents that contain the indexed field)
    pub sparse: bool,
}

/// Trait for types that can be compressed
pub trait Compressible {
    /// Compress this entity using Zstd
    fn compress_zstd(&self, level: i32) -> Result<Vec<u8>>;
    
    /// Decompress a Zstd-compressed entity
    fn decompress_zstd(compressed: &[u8]) -> Result<Self> where Self: Sized;
    
    /// Compress this entity using xz
    fn compress_xz(&self) -> Result<Vec<u8>>;
    
    /// Decompress an xz-compressed entity
    fn decompress_xz(compressed: &[u8]) -> Result<Self> where Self: Sized;
    
    /// Compress this entity using snappy
    fn compress_snappy(&self) -> Result<Vec<u8>>;
    
    /// Decompress a snappy-compressed entity
    fn decompress_snappy(compressed: &[u8]) -> Result<Self> where Self: Sized;
}

/// Implement Compressible for any type that implements Persistable
impl<T: Persistable> Compressible for T {
    fn compress_zstd(&self, level: i32) -> Result<Vec<u8>> {
        let binary = self.to_binary()?;
        let compressed = zstd::encode_all(&binary[..], level)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        Ok(compressed)
    }
    
    fn decompress_zstd(compressed: &[u8]) -> Result<Self> where Self: Sized {
        let binary = zstd::decode_all(compressed)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        Self::from_binary(&binary)
    }
    
    fn compress_xz(&self) -> Result<Vec<u8>> {
        let binary = self.to_binary()?;
        let mut compressed = Vec::new();
        let mut encoder = xz2::write::XzEncoder::new(&mut compressed, 6);
        std::io::copy(&mut &binary[..], &mut encoder)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        encoder.finish()
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        Ok(compressed)
    }
    
    fn decompress_xz(compressed: &[u8]) -> Result<Self> where Self: Sized {
        let mut decoder = xz2::read::XzDecoder::new(compressed);
        let mut binary = Vec::new();
        std::io::copy(&mut decoder, &mut binary)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        Self::from_binary(&binary)
    }
    
    fn compress_snappy(&self) -> Result<Vec<u8>> {
        let binary = self.to_binary()?;
        Ok(snap::raw::Encoder::new().compress_vec(&binary)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?)
    }
    
    fn decompress_snappy(compressed: &[u8]) -> Result<Self> where Self: Sized {
        let binary = snap::raw::Decoder::new().decompress_vec(compressed)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        Self::from_binary(&binary)
    }
}

/// Trait for types that can be audited
pub trait Auditable {
    /// Get the audit context for this entity
    fn audit_context(&self) -> AuditContext;
    
    /// Create an audit event for this entity
    fn create_audit_event(&self, action: &str, outcome: crate::audit::AuditOutcome) -> crate::audit::AuditEvent;
}

/// Audit context for an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditContext {
    /// The entity type
    pub entity_type: String,
    /// The entity ID
    pub entity_id: String,
    /// The identity context
    pub identity: IdentityContext,
    /// The timestamp
    pub timestamp: DateTime<Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Trait for types that can be checkpointed
pub trait CheckPointable: Persistable {
    /// Create a checkpoint of this entity
    fn create_checkpoint(&self, checkpoint_name: &str) -> Result<()>;
    
    /// Restore this entity from a checkpoint
    fn restore_from_checkpoint(checkpoint_name: &str) -> Result<Self> where Self: Sized;
    
    /// List available checkpoints for this entity
    fn list_checkpoints() -> Result<Vec<String>>;
}

/// Trait for types that can heal themselves
pub trait SelfHealing {
    /// Check if this entity is corrupted
    fn is_corrupted(&self) -> bool;
    
    /// Attempt to repair this entity
    fn repair(&mut self) -> Result<bool>;
    
    /// Get the health status of this entity
    fn health_status(&self) -> HealthStatus;
}

/// Health status of an entity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// The entity is healthy
    Healthy,
    /// The entity is degraded but functional
    Degraded,
    /// The entity is corrupted but repairable
    Corrupted,
    /// The entity is corrupted and not repairable
    Unrepairable,
}

/// Trait for types that can be sharded
pub trait Shardable {
    /// Get the shard key for this entity
    fn shard_key(&self) -> String;
    
    /// Calculate the shard ID for this entity
    fn calculate_shard_id(&self, shard_count: usize) -> usize;
    
    /// Get the shard path for this entity
    fn shard_path(&self, base_path: &std::path::Path, shard_count: usize) -> std::path::PathBuf;
}

/// Trait for types that can be streamed as events
pub trait StreamableEvent: Persistable {
    /// Get the event type
    fn event_type(&self) -> &'static str;
    
    /// Get the event timestampf
    fn event_timestamp(&self) -> DateTime<Utc>;
    
    /// Convert this event to a JSON string for streaming
    fn to_stream_json(&self) -> Result<String>;
    
    /// Get the event priority
    fn priority(&self) -> EventPriority;
    
    /// Get the event topic
    fn topic(&self) -> &str;
    
    /// Get the event checkpoint marker (if any)
    fn checkpoint_marker(&self) -> Option<String>;

    fn metadata(&self) -> HashMap<String, String>;
}

/// Event priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EventPriority {
    /// Critical priority
    Critical = 0,
    /// High priority
    High = 1,
    /// Medium priority
    Medium = 2,
    /// Low priority
    Low = 3,
    /// Debug priority
    Debug = 4,
}

/// Base entity with common fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseEntity {
    /// The unique ID of this entity
    pub id: Uuid,
    /// The creation timestamp
    pub created_at: DateTime<Utc>,
    /// The last update timestamp
    pub updated_at: DateTime<Utc>,
    /// The version of this entity
    pub version: u32,
    /// The creator of this entity
    pub created_by: String,
    /// The last updater of this entity
    pub updated_by: String,
    /// Whether this entity is deleted
    pub is_deleted: bool,
    /// The deletion timestamp
    pub deleted_at: Option<DateTime<Utc>>,
    /// The deletion reason
    pub deletion_reason: Option<String>,
    /// Time-to-live in seconds (if applicable)
    pub ttl_seconds: Option<u64>,
    /// Expiration timestamp (if applicable)
    pub expires_at: Option<DateTime<Utc>>,
    /// BLAKE3 hash of the entity content for integrity verification
    pub content_hash: Option<String>,
}

impl BaseEntity {
    /// Create a new base entity
    pub fn new(created_by: String) -> Self {
        let created_by_clone = created_by.clone();
        Self {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            version: 1,
            created_by: created_by.clone(),
            updated_by: created_by_clone,
            is_deleted: false,
            deleted_at: None,
            deletion_reason: None,
            ttl_seconds: None,
            expires_at: None,
            content_hash: None,
        }
    }
    
    /// Mark this entity as updated
    pub fn mark_updated(&mut self, updated_by: String) {
        self.updated_at = Utc::now();
        self.version += 1;
        self.updated_by = updated_by;
    }
    
    /// Mark this entity as deleted
    pub fn mark_deleted(&mut self, deleted_by: String, reason: Option<String>) {
        self.is_deleted = true;
        self.deleted_at = Some(Utc::now());
        self.deletion_reason = reason;
        self.mark_updated(deleted_by);
    }
    
    /// Set TTL for this entity
    pub fn set_ttl(&mut self, ttl_seconds: u64) {
        self.ttl_seconds = Some(ttl_seconds);
        self.expires_at = Some(Utc::now() + chrono::Duration::seconds(ttl_seconds as i64));
    }
    
    /// Check if this entity has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
    
    /// Update the content hash for integrity verification
    pub fn update_content_hash<T: Serialize>(&mut self, content: &T) -> Result<()> {
        let json = serde_json::to_string(content)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        
        let mut hasher = blake3::Hasher::new();
        hasher.update(json.as_bytes());
        self.content_hash = Some(hasher.finalize().to_hex().to_string());
        
        Ok(())
    }
    
    /// Verify the content hash for integrity
    pub fn verify_content_hash<T: Serialize>(&self, content: &T) -> Result<bool> {
        if let Some(stored_hash) = &self.content_hash {
            let json = serde_json::to_string(content)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
            
            let mut hasher = blake3::Hasher::new();
            hasher.update(json.as_bytes());
            let computed_hash = hasher.finalize().to_hex().to_string();
            
            Ok(computed_hash == *stored_hash)
        } else {
            // No hash to verify against
            Ok(true)
        }
    }
}

/// Trait for types that support field-level encryption
pub trait FieldEncryptable {
    /// Encrypt sensitive fields
    fn encrypt_fields(&mut self, key: &[u8]) -> Result<()>;
    
    /// Decrypt sensitive fields
    fn decrypt_fields(&mut self, key: &[u8]) -> Result<()>;
    
    /// Get the names of fields that should be encrypted
    fn encrypted_field_names() -> Vec<&'static str>;
}

/// Trait for types that support change history tracking
pub trait ChangeTrackable: Persistable {
    /// Record a change to this entity
    fn record_change(&self, field_name: &str, old_value: Option<&str>, new_value: Option<&str>, changed_by: &str) -> Result<()>;
    
    /// Get the change history for this entity
    fn get_change_history(&self) -> Result<Vec<ChangeRecord>>;
}

/// A record of a change to an entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    /// The ID of the entity that was changed
    pub entity_id: Uuid,
    /// The type of entity that was changed
    pub entity_type: String,
    /// The field that was changed
    pub field_name: String,
    /// The old value of the field
    pub old_value: Option<String>,
    /// The new value of the field
    pub new_value: Option<String>,
    /// The timestamp of the change
    pub timestamp: DateTime<Utc>,
    /// The user who made the change
    pub changed_by: String,
    /// The version of the entity after the change
    pub entity_version: u32,
}