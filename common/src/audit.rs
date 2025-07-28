//! # Audit system for ForgeOne
//! /common/audit.rs
//! This module provides a comprehensive audit logging system for the ForgeOne platform, including:
//! - Immutable audit stream signing and verification
//! - Configurable audit policies and retention
//! - Multiple audit sink implementations (file, database, memory)
//! - Categorized and severity-based audit events
//! - Helper functions for common audit scenarios
//! - Query and export capabilities
//! - Compliance-oriented audit trail management

use crate::db::model::EventPriority;
use crate::db::model::StreamableEvent;
use crate::db::redb::{init_redb, EventManager, RedbManager, RedbOptions};
use crate::db::Persistable;
use crate::error::{ForgeError, Result};
use crate::identity::IdentityContext;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Mutex as StdMutex;
use std::sync::{Arc, Mutex, Once, RwLock};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

/// Audit event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditSeverity {
    /// Informational events
    Info,
    /// Warning events
    Warning,
    /// Error events
    Error,
    /// Critical events
    Critical,
}

/// Audit event categories
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditCategory {
    /// Authentication events (login, logout, etc.)
    Authentication,
    /// Authorization events (access granted/denied)
    Authorization,
    /// Data access events (read, write, delete)
    DataAccess,
    /// Configuration changes
    Configuration,
    /// System events (startup, shutdown, etc.)
    System,
    /// Security events (intrusion detection, etc.)
    Security,
    /// Compliance events
    Compliance,
    /// User management events
    UserManagement,
    /// Custom events
    Custom(String),
}

/// The outcome of an audit event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// The action succeeded
    Success,
    /// The action failed
    Failure(String),
    /// The action was denied
    Denied(String),
}

/// Audit event status (simplified version of outcome for filtering)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStatus {
    /// Event succeeded
    Success,
    /// Event failed
    Failure,
    /// Event is in progress
    InProgress,
    /// Event was attempted but blocked
    Blocked,
}

/// An audit event for the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// The ID of this event
    pub event_id: Uuid,
    /// The timestamp of this event
    pub timestamp: DateTime<Utc>,
    /// The identity context of this event
    pub identity: IdentityContext,
    /// The action performed
    pub action: String,
    /// The resource affected
    pub resource: String,
    /// The resource identifier (if applicable)
    pub resource_id: Option<String>,
    /// The outcome of the action
    pub outcome: AuditOutcome,
    /// The category of the event
    pub category: AuditCategory,
    /// The severity level of the event
    pub severity: AuditSeverity,
    /// Additional details about the event
    pub details: Option<serde_json::Value>,
    /// The signature of this event
    pub signature: Option<String>,
    /// Session identifier
    pub session_id: Option<String>,
    /// Request identifier
    pub request_id: Option<String>,
    /// Trace identifier for distributed tracing
    pub trace_id: Option<String>,
    /// Hash of the previous event (for tamper-evident chain)
    pub prev_hash: Option<String>,
}

/// Audit policy for controlling audit behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPolicy {
    /// Whether to enable audit logging
    pub enabled: bool,
    /// Minimum severity level to log
    pub min_severity: AuditSeverity,
    /// Categories to include
    pub include_categories: Vec<AuditCategory>,
    /// Categories to exclude
    pub exclude_categories: Vec<AuditCategory>,
    /// Whether to log successful events
    pub log_success: bool,
    /// Whether to log failed events
    pub log_failure: bool,
    /// Whether to include context information
    pub include_context: bool,
    /// Maximum retention period in days
    pub retention_days: u32,
    /// Whether to sign audit events
    pub sign_events: bool,
}

impl Default for AuditPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            min_severity: AuditSeverity::Info,
            include_categories: vec![], // Empty means include all
            exclude_categories: vec![],
            log_success: true,
            log_failure: true,
            include_context: true,
            retention_days: 90,
            sign_events: false,
        }
    }
}

/// Redaction rule for audit events
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedactionRule {
    /// Redact (remove) the field
    Redact,
    /// Mask the field (replace with fixed string)
    Mask(String),
}

/// Extended audit policy with redaction rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtendedAuditPolicy {
    pub base: AuditPolicy,
    /// Redaction rules: field name -> rule
    pub redaction: HashMap<String, RedactionRule>,
}

impl Default for ExtendedAuditPolicy {
    fn default() -> Self {
        Self {
            base: AuditPolicy::default(),
            redaction: HashMap::new(),
        }
    }
}

/// Trait for audit event sinks
pub trait AuditSink: Send + Sync {
    /// Write an audit event to the sink
    fn write(&self, event: &AuditEvent) -> Result<()>;

    /// Flush any buffered events
    fn flush(&self) -> Result<()>;

    /// Close the sink
    fn close(&self) -> Result<()>;
}
// Blanket implementation for downcasting
trait AsAny {
    fn as_any(&self) -> &dyn std::any::Any;
}
impl<T: 'static> AsAny for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Trait for real-time streaming audit sinks (webhook, message queue, gRPC, etc.)
pub trait StreamingAuditSink: AuditSink {
    /// Called when the sink should connect or initialize
    fn connect(&self) -> Result<()>;
    /// Called when the sink should disconnect or cleanup
    fn disconnect(&self) -> Result<()>;
}

/// Webhook audit sink stub
pub struct WebhookAuditSink {
    pub url: String,
}
impl AuditSink for WebhookAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        // Send event to webhook (stub)
        Ok(())
    }
    fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}
impl StreamingAuditSink for WebhookAuditSink {
    fn connect(&self) -> Result<()> {
        Ok(())
    }
    fn disconnect(&self) -> Result<()> {
        Ok(())
    }
}

/// Message queue audit sink stub
pub struct MessageQueueAuditSink {
    pub queue: String,
}
impl AuditSink for MessageQueueAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        // Send event to message queue (stub)
        Ok(())
    }
    fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}
impl StreamingAuditSink for MessageQueueAuditSink {
    fn connect(&self) -> Result<()> {
        Ok(())
    }
    fn disconnect(&self) -> Result<()> {
        Ok(())
    }
}

/// gRPC audit sink stub
pub struct GrpcAuditSink {
    pub endpoint: String,
}
impl AuditSink for GrpcAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        // Send event via gRPC (stub)
        Ok(())
    }
    fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}
impl StreamingAuditSink for GrpcAuditSink {
    fn connect(&self) -> Result<()> {
        Ok(())
    }
    fn disconnect(&self) -> Result<()> {
        Ok(())
    }
}

/// Replicated audit sink: replicates events to multiple sinks, with retry/failover
pub struct ReplicatedAuditSink {
    pub sinks: Vec<Box<dyn AuditSink>>,
    pub max_retries: usize,
    pub retry_delay: Duration,
}

impl AuditSink for ReplicatedAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        let mut last_err = None;
        for sink in &self.sinks {
            let mut attempts = 0;
            loop {
                match sink.write(event) {
                    Ok(_) => break,
                    Err(e) => {
                        attempts += 1;
                        last_err = Some(e);
                        if attempts >= self.max_retries {
                            break;
                        }
                        std::thread::sleep(self.retry_delay);
                    }
                }
            }
        }
        if let Some(e) = last_err {
            Err(e)
        } else {
            Ok(())
        }
    }
    fn flush(&self) -> Result<()> {
        for sink in &self.sinks {
            let _ = sink.flush();
        }
        Ok(())
    }
    fn close(&self) -> Result<()> {
        for sink in &self.sinks {
            let _ = sink.close();
        }
        Ok(())
    }
}

/// Write-ahead log (WAL) audit sink: persists events to file before forwarding
pub struct WriteAheadLogAuditSink {
    pub path: String,
    pub inner: Box<dyn AuditSink>,
}

impl AuditSink for WriteAheadLogAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| ForgeError::IoError(e.to_string()))?;
        let json = serde_json::to_string(event)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        writeln!(file, "{}", json).map_err(|e| ForgeError::IoError(e.to_string()))?;
        self.inner.write(event)
    }
    fn flush(&self) -> Result<()> {
        self.inner.flush()
    }
    fn close(&self) -> Result<()> {
        self.inner.close()
    }
}

impl WriteAheadLogAuditSink {
    /// Recover events from WAL file
    pub fn recover_events(&self) -> Result<Vec<AuditEvent>> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};
        let file = File::open(&self.path).map_err(|e| ForgeError::IoError(e.to_string()))?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line.map_err(|e| ForgeError::IoError(e.to_string()))?;
            let event: AuditEvent = serde_json::from_str(&line)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
            events.push(event);
        }
        Ok(events)
    }
}

/// Stub for network replication (future multi-node support)
pub struct NetworkReplicatedAuditSink {
    pub peers: Vec<String>, // peer addresses
}
impl AuditSink for NetworkReplicatedAuditSink {
    fn write(&self, _event: &AuditEvent) -> Result<()> {
        // TODO: send event to peers (future)
        Ok(())
    }
    fn flush(&self) -> Result<()> {
        Ok(())
    }
    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// An audit log for the system
pub struct AuditLog {
    /// The file to write audit events to
    file: Option<File>,
    /// Whether to sign audit events
    sign_events: bool,
    /// The private key to sign audit events with
    private_key: Option<Vec<u8>>,
    /// The audit policy
    policy: AuditPolicy,
    /// Last event hash for chain-linking
    last_hash: Option<String>,
}

impl AuditLog {
    /// Create a new audit log
    pub fn new() -> Self {
        Self {
            file: None,
            sign_events: false,
            private_key: None,
            policy: AuditPolicy::default(),
            last_hash: None,
        }
    }

    /// Create a new audit log with a policy
    pub fn with_policy(policy: AuditPolicy) -> Self {
        Self {
            file: None,
            sign_events: policy.sign_events,
            private_key: None,
            policy,
            last_hash: None,
        }
    }

    /// Set the file to write audit events to
    pub fn with_file(mut self, path: &str) -> Result<Self> {
        let path = Path::new(path);

        // Create the directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ForgeError::IoError(e.to_string()))?;
        }

        // Open the file for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| ForgeError::IoError(e.to_string()))?;

        self.file = Some(file);
        Ok(self)
    }

    /// Set whether to sign audit events
    pub fn with_signing(mut self, sign_events: bool) -> Self {
        self.sign_events = sign_events;
        self
    }

    /// Set the private key to sign audit events with
    pub fn with_private_key(mut self, private_key: Vec<u8>) -> Self {
        self.private_key = Some(private_key);
        self
    }

    /// Log an audit event (with chain hash)
    pub fn log_event(&mut self, mut event: AuditEvent) -> Result<()> {
        // Set prev_hash
        event.prev_hash = self.last_hash.clone();
        // Compute hash for this event (excluding signature and prev_hash)
        let hash = compute_event_hash(&event)?;
        self.last_hash = Some(hash.clone());
        // Sign the event if needed
        let event = if self.sign_events {
            self.sign_event(event)?
        } else {
            event
        };
        // Serialize the event
        let json = serde_json::to_string(&event)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        // Write the event to the file if available
        if let Some(file) = &mut self.file {
            writeln!(file, "{}", json).map_err(|e| ForgeError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    /// Sign an audit event
    fn sign_event(&self, mut event: AuditEvent) -> Result<AuditEvent> {
        if !self.sign_events || self.private_key.is_none() {
            return Ok(event);
        }

        // Clone the event without the signature
        let mut event_clone = event.clone();
        event_clone.signature = None;

        // Serialize the event
        let json = serde_json::to_string(&event_clone)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Sign the event
        let signature = self.sign_data(json.as_bytes())?;
        event.signature = Some(signature);

        Ok(event)
    }

    /// Sign data with the private key
    fn sign_data(&self, data: &[u8]) -> Result<String> {
        if let Some(private_key) = &self.private_key {
            use base64::{engine::general_purpose, Engine as _};
            use ed25519_dalek::{Signer, SigningKey};

            // Parse the private key - convert slice to fixed-size array
            let key_bytes: [u8; 32] = private_key[..32]
                .try_into()
                .map_err(|_| ForgeError::CryptoError("Invalid private key length".to_string()))?;
            let key = SigningKey::from_bytes(&key_bytes);

            // Sign the data
            let signature = key.sign(data);

            // Encode the signature using new base64 API
            Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
        } else {
            Err(ForgeError::CryptoError(
                "No private key available".to_string(),
            ))
        }
    }
}

/// Compute a hash for an audit event (excluding signature and prev_hash)
pub fn compute_event_hash(event: &AuditEvent) -> Result<String> {
    use sha2::{Digest, Sha256};
    // Clone and clear signature and prev_hash
    let mut event_clone = event.clone();
    event_clone.signature = None;
    event_clone.prev_hash = None;
    let json = serde_json::to_string(&event_clone)
        .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

/// Create a new audit event
pub fn create_audit_event(
    identity: IdentityContext,
    action: String,
    resource: String,
    outcome: AuditOutcome,
    category: AuditCategory,
    severity: AuditSeverity,
    details: Option<serde_json::Value>,
) -> AuditEvent {
    AuditEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        identity,
        action,
        resource,
        resource_id: None,
        outcome,
        category,
        severity,
        details,
        signature: None,
        session_id: None,
        request_id: None,
        trace_id: None,
        prev_hash: None,
    }
}

/// Create a new audit event with simplified parameters
pub fn create_simple_audit_event(
    identity: IdentityContext,
    action: String,
    resource: String,
    outcome: AuditOutcome,
    details: Option<serde_json::Value>,
) -> AuditEvent {
    AuditEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        identity,
        action,
        resource,
        resource_id: None,
        outcome,
        category: AuditCategory::System,
        severity: AuditSeverity::Info,
        details,
        signature: None,
        session_id: None,
        request_id: None,
        trace_id: None,
        prev_hash: None,
    }
}

/// Verify the signature of an audit event
pub fn verify_event_signature(event: &AuditEvent, public_key: &[u8]) -> Result<bool> {
    if let Some(signature) = &event.signature {
        // Clone the event without the signature
        let mut event_clone = event.clone();
        event_clone.signature = None;

        // Serialize the event
        let json = serde_json::to_string(&event_clone)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Verify the signature
        verify_signature(json.as_bytes(), signature, public_key)
    } else {
        Ok(false)
    }
}

/// Verify the integrity of a chain of audit events
pub fn verify_audit_chain(events: &[AuditEvent]) -> Result<bool> {
    if events.is_empty() {
        return Ok(true);
    }
    let mut prev_hash: Option<String> = None;
    for event in events {
        // Check prev_hash matches
        if event.prev_hash != prev_hash {
            return Err(ForgeError::IntegrityBreach(
                "Audit chain broken: prev_hash mismatch".to_string(),
            ));
        }
        // Compute this event's hash (excluding signature and prev_hash)
        let hash = compute_event_hash(event)?;
        prev_hash = Some(hash);
    }
    Ok(true)
}

// Database audit sink
pub struct DbAuditSink {
    // Implementation details would depend on the database module
}

impl Persistable for AuditEvent {
    fn id(&self) -> Uuid {
        self.event_id
    }
    fn collection_name() -> &'static str {
        "audit_events"
    }
    fn preferred_backend() -> crate::db::StorageBackend {
        crate::db::StorageBackend::IndxDb
    }
    fn schema_version() -> u32 {
        1
    }
    fn indexes() -> Vec<crate::db::IndexDefinition> {
        vec![]
    }
}

impl AuditSink for DbAuditSink {
    fn write(&self, _event: &AuditEvent) -> Result<()> {
        // Implementation would use the database module to store the event
        // This is a placeholder until the database module is fully implemented
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        // Implementation would flush any buffered events
        Ok(())
    }

    fn close(&self) -> Result<()> {
        // Implementation would close the sink
        Ok(())
    }
}

/// File audit sink
pub struct FileAuditSink {
    path: String,
    file: Mutex<File>,
    sign_events: bool,
    private_key: Option<Vec<u8>>,
}

impl FileAuditSink {
    /// Create a new file audit sink
    pub fn new(
        path: impl Into<String>,
        sign_events: bool,
        private_key: Option<Vec<u8>>,
    ) -> Result<Self> {
        let path_str = path.into();
        let path = Path::new(&path_str);

        // Create the directory if it doesn't exist
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ForgeError::IoError(e.to_string()))?;
        }

        // Open the file for appending
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| ForgeError::IoError(e.to_string()))?;

        Ok(Self {
            path: path_str,
            file: Mutex::new(file),
            sign_events,
            private_key,
        })
    }

    /// Sign an audit event
    fn sign_event(&self, mut event: AuditEvent) -> Result<AuditEvent> {
        if !self.sign_events || self.private_key.is_none() {
            return Ok(event);
        }

        // Clone the event without the signature
        let mut event_clone = event.clone();
        event_clone.signature = None;

        // Serialize the event
        let json = serde_json::to_string(&event_clone)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Sign the event
        let signature = self.sign_data(json.as_bytes())?;
        event.signature = Some(signature);

        Ok(event)
    }

    /// Sign data with the private key
    fn sign_data(&self, data: &[u8]) -> Result<String> {
        if let Some(private_key) = &self.private_key {
            use base64::{engine::general_purpose, Engine as _};
            use ed25519_dalek::{Signer, SigningKey};

            // Parse the private key - convert slice to fixed-size array
            let key_bytes: [u8; 32] = private_key[..32]
                .try_into()
                .map_err(|_| ForgeError::CryptoError("Invalid private key length".to_string()))?;
            let key = SigningKey::from_bytes(&key_bytes);

            // Sign the data
            let signature = key.sign(data);

            // Encode the signature using new base64 API
            Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
        } else {
            Err(ForgeError::CryptoError(
                "No private key available".to_string(),
            ))
        }
    }
}

impl AuditSink for FileAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        // Sign the event if needed
        let event = if self.sign_events {
            self.sign_event(event.clone())?
        } else {
            event.clone()
        };

        // Serialize the event
        let json = serde_json::to_string(&event)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        // Write the event to the file
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", json).map_err(|e| ForgeError::IoError(e.to_string()))?;

        Ok(())
    }

    fn flush(&self) -> Result<()> {
        let mut file = self.file.lock().unwrap();
        file.flush()
            .map_err(|e| ForgeError::IoError(e.to_string()))?;

        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.flush()
    }
}

/// Memory audit sink for testing
pub struct MemoryAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAuditSink {
    /// Create a new memory audit sink
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
    /// Get all events
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().unwrap().clone()
    }
    /// Clear all events
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
    /// Backup the sink's events to a file
    pub fn backup(&self, target_path: &str) -> Result<()> {
        let events = self.events.lock().unwrap();
        let json = serde_json::to_string(&*events)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        std::fs::write(target_path, json).map_err(|e| ForgeError::IoError(e.to_string()))?;
        Ok(())
    }
    /// Restore the sink's events from a file
    pub fn restore(&self, backup_path: &str) -> Result<()> {
        let json =
            std::fs::read_to_string(backup_path).map_err(|e| ForgeError::IoError(e.to_string()))?;
        let events: Vec<AuditEvent> = serde_json::from_str(&json)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        let mut store = self.events.lock().unwrap();
        *store = events;
        Ok(())
    }
}

impl AuditSink for MemoryAuditSink {
    fn write(&self, event: &AuditEvent) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Ok(())
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Audit manager for handling audit events
pub struct AuditManager {
    /// Audit policy
    policy: RwLock<AuditPolicy>,
    /// Audit sinks
    sinks: Arc<RwLock<Vec<Box<dyn AuditSink>>>>,
    /// Private key for signing
    private_key: Option<Vec<u8>>,
    /// Enable segment-based blockchain-style logging
    segmented_log: Option<std::sync::Mutex<SegmentedAuditLog>>,
    /// Asynchronous, non-blocking audit logger using a background thread
    async_logger: Option<AsyncAuditLogger>,
}

impl AuditManager {
    /// Create a new audit manager
    pub fn new(policy: AuditPolicy, private_key: Option<Vec<u8>>) -> Self {
        Self {
            policy: RwLock::new(policy),
            sinks: Arc::new(RwLock::new(Vec::new())),
            private_key,
            segmented_log: None,
            async_logger: None,
        }
    }

    /// Add an audit sink
    pub fn add_sink<S: AuditSink + 'static>(&self, sink: S) {
        self.sinks.write().unwrap().push(Box::new(sink));
    }

    /// Add a new audit sink at runtime (thread-safe)
    pub fn add_sink_dyn(&self, sink: Box<dyn AuditSink>) {
        self.sinks.write().unwrap().push(sink);
    }
    /// Remove an audit sink by type id (thread-safe, removes first match)
    pub fn remove_sink_by_type<T: 'static>(&self) {
        use std::any::Any;
        let mut sinks = self.sinks.write().unwrap();
        if let Some(pos) = sinks.iter().position(|s| s.as_any().is::<T>()) {
            sinks.remove(pos);
        }
    }
    /// Remove all sinks (for test/demo)
    pub fn clear_sinks(&self) {
        self.sinks.write().unwrap().clear();
    }

    /// Update the audit policy
    pub fn update_policy(&self, policy: AuditPolicy) {
        *self.policy.write().unwrap() = policy;
    }

    /// Get the current audit policy
    pub fn policy(&self) -> AuditPolicy {
        self.policy.read().unwrap().clone()
    }

    /// Log an audit event
    pub fn log(&self, event: AuditEvent) -> Result<()> {
        // Check if audit is enabled
        let policy = self.policy.read().unwrap();
        if !policy.enabled {
            return Ok(());
        }

        // Check severity
        if (event.severity as u8) < (policy.min_severity as u8) {
            return Ok(());
        }

        // Check status
        let status = match &event.outcome {
            AuditOutcome::Success => AuditStatus::Success,
            AuditOutcome::Failure(_) => AuditStatus::Failure,
            AuditOutcome::Denied(_) => AuditStatus::Blocked,
        };

        match status {
            AuditStatus::Success if !policy.log_success => return Ok(()),
            AuditStatus::Failure if !policy.log_failure => return Ok(()),
            _ => {}
        }

        // Check category
        if !policy.include_categories.is_empty() {
            let category_match = match &event.category {
                AuditCategory::Custom(name) => policy.include_categories.iter().any(|c| {
                    if let AuditCategory::Custom(pattern) = c {
                        pattern == name
                    } else {
                        false
                    }
                }),
                _ => policy.include_categories.contains(&event.category),
            };

            if !category_match {
                return Ok(());
            }
        }

        if !policy.exclude_categories.is_empty() {
            let category_match = match &event.category {
                AuditCategory::Custom(name) => policy.exclude_categories.iter().any(|c| {
                    if let AuditCategory::Custom(pattern) = c {
                        pattern == name
                    } else {
                        false
                    }
                }),
                _ => policy.exclude_categories.contains(&event.category),
            };

            if category_match {
                return Ok(());
            }
        }

        // Sign the event if needed
        let event = if policy.sign_events && self.private_key.is_some() {
            let mut event_clone = event.clone();
            event_clone.signature = None;

            // Serialize the event
            let json = serde_json::to_string(&event_clone)
                .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

            // Sign the event
            if let Some(private_key) = &self.private_key {
                use base64::{engine::general_purpose, Engine as _};
                use ed25519_dalek::{Signer, SigningKey};

                // Parse the private key
                let key_bytes: [u8; 32] = private_key[..32].try_into().map_err(|_| {
                    ForgeError::CryptoError("Invalid private key length".to_string())
                })?;
                let key = SigningKey::from_bytes(&key_bytes);

                // Sign the data
                let signature = key.sign(json.as_bytes());

                // Encode the signature
                let mut signed_event = event.clone();
                signed_event.signature =
                    Some(general_purpose::STANDARD.encode(signature.to_bytes()));
                signed_event
            } else {
                event
            }
        } else {
            event
        };

        // Write to all sinks
        let sinks = self.sinks.read().unwrap();
        for sink in sinks.iter() {
            sink.write(&event)?;
        }

        Ok(())
    }

    /// Flush all sinks
    pub fn flush(&self) -> Result<()> {
        let sinks = self.sinks.read().unwrap();
        for sink in sinks.iter() {
            sink.flush()?;
        }

        Ok(())
    }

    /// Close all sinks
    pub fn close(&self) -> Result<()> {
        let sinks = self.sinks.read().unwrap();
        for sink in sinks.iter() {
            sink.close()?;
        }

        Ok(())
    }

    /// Enable segment-based blockchain-style logging
    pub fn enable_segmented_logging(
        &mut self,
        segment_size: Option<usize>,
        signing_key: Option<Vec<u8>>,
    ) {
        self.segmented_log = Some(std::sync::Mutex::new(SegmentedAuditLog::new(
            segment_size,
            signing_key,
        )));
    }
    /// Log an event using segment-based logging if enabled, else fallback
    pub fn log_segmented(&self, event: AuditEvent) -> Result<()> {
        if let Some(seg_mutex) = &self.segmented_log {
            let mut seglog = seg_mutex.lock().unwrap();
            seglog.add_event(event)
        } else {
            self.log(event)
        }
    }
    /// Expose segment attestation API
    pub fn verify_segments(&self, public_key: &[u8]) -> Result<bool> {
        if let Some(seg_mutex) = &self.segmented_log {
            let seglog = seg_mutex.lock().unwrap();
            seglog.verify_all_segments(public_key)
        } else {
            Ok(true)
        }
    }

    /// Enable async logging mode (threaded)
    pub fn enable_async_logging(&mut self) {
        let sinks = Arc::clone(&self.sinks);
        let async_logger = AsyncAuditLogger::new(move |event| {
            let sinks = sinks.read().unwrap();
            for sink in sinks.iter() {
                let _ = sink.write(&event);
            }
        });
        self.async_logger = Some(async_logger);
    }
    /// Log an event using async logger if enabled, else fallback
    pub fn log_async(&self, event: AuditEvent) {
        if let Some(logger) = &self.async_logger {
            logger.log(event);
        } else {
            let _ = self.log(event);
        }
    }
    /// Shutdown async logger if enabled
    pub fn shutdown_async_logger(&mut self) {
        if let Some(logger) = self.async_logger.take() {
            logger.shutdown();
        }
    }
}

// Global audit manager
static mut AUDIT_MANAGER: Option<Arc<AuditManager>> = None;
static INIT: Once = Once::new();

/// Initialize the audit module
pub fn init_audit(policy: Option<AuditPolicy>, private_key: Option<Vec<u8>>) -> Result<()> {
    INIT.call_once(|| {
        let policy = policy.unwrap_or_default();
        let manager = AuditManager::new(policy, private_key);

        unsafe {
            AUDIT_MANAGER = Some(Arc::new(manager));
        }
    });

    Ok(())
}

/// Get the global audit manager
pub fn get_audit_manager() -> Result<Arc<AuditManager>> {
    unsafe {
        match &AUDIT_MANAGER {
            Some(manager) => Ok(manager.clone()),
            None => Err(ForgeError::DatabaseQueryError(
                "Audit module not initialized".to_string(),
            )),
        }
    }
}

/// Log an audit event
pub fn log_audit_event(event: AuditEvent) -> Result<()> {
    let manager = get_audit_manager()?;
    manager.log(event)
}

/// Helper function to log authentication events
pub fn log_authentication(
    identity: IdentityContext,
    action: impl Into<String>,
    outcome: AuditOutcome,
    details: Option<serde_json::Value>,
) -> Result<()> {
    let outcome_clone = outcome.clone();
    let severity = match outcome_clone {
        AuditOutcome::Success => AuditSeverity::Info,
        _ => AuditSeverity::Warning,
    };
    let event = create_audit_event(
        identity,
        action.into(),
        "user".to_string(),
        outcome,
        AuditCategory::Authentication,
        severity,
        details,
    );

    log_audit_event(event)
}

/// Helper function to log authorization events
pub fn log_authorization(
    identity: IdentityContext,
    resource: impl Into<String>,
    resource_id: Option<String>,
    action: impl Into<String>,
    outcome: AuditOutcome,
    details: Option<serde_json::Value>,
) -> Result<()> {
    let outcome_clone = outcome.clone();
    let severity = match outcome_clone {
        AuditOutcome::Success => AuditSeverity::Info,
        _ => AuditSeverity::Warning,
    };
    let mut event = create_audit_event(
        identity,
        action.into(),
        resource.into(),
        outcome,
        AuditCategory::Authorization,
        severity,
        details,
    );

    if let Some(id) = resource_id {
        event.resource_id = Some(id);
    }

    log_audit_event(event)
}

/// Helper function to log data access events
pub fn log_data_access(
    identity: IdentityContext,
    resource: impl Into<String>,
    resource_id: Option<String>,
    action: impl Into<String>,
    outcome: AuditOutcome,
    details: Option<serde_json::Value>,
) -> Result<()> {
    let mut event = create_audit_event(
        identity,
        action.into(),
        resource.into(),
        outcome,
        AuditCategory::DataAccess,
        AuditSeverity::Info,
        details,
    );

    if let Some(id) = resource_id {
        event.resource_id = Some(id);
    }

    log_audit_event(event)
}

/// Helper function to log configuration changes
pub fn log_configuration_change(
    identity: IdentityContext,
    component: impl Into<String>,
    action: impl Into<String>,
    outcome: AuditOutcome,
    details: Option<serde_json::Value>,
) -> Result<()> {
    let event = create_audit_event(
        identity,
        action.into(),
        component.into(),
        outcome,
        AuditCategory::Configuration,
        AuditSeverity::Info,
        details,
    );

    log_audit_event(event)
}

/// Helper function to log security events
pub fn log_security_event(
    identity: IdentityContext,
    action: impl Into<String>,
    resource: impl Into<String>,
    severity: AuditSeverity,
    outcome: AuditOutcome,
    details: Option<serde_json::Value>,
) -> Result<()> {
    let event = create_audit_event(
        identity,
        action.into(),
        resource.into(),
        outcome,
        AuditCategory::Security,
        severity,
        details,
    );

    log_audit_event(event)
}

/// Helper function to log system events
pub fn log_system_event(
    component: impl Into<String>,
    action: impl Into<String>,
    outcome: AuditOutcome,
    severity: AuditSeverity,
    details: Option<serde_json::Value>,
) -> Result<()> {
    // Create a system identity
    let identity = IdentityContext::system();
    let event = create_audit_event(
        identity,
        action.into(),
        component.into(),
        outcome,
        AuditCategory::System,
        severity,
        details,
    );

    log_audit_event(event)
}

/// Query audit events
pub async fn query_audit_events(
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    identity: Option<String>,
    category: Option<AuditCategory>,
    action: Option<String>,
    resource: Option<String>,
    status: Option<AuditStatus>,
    severity: Option<AuditSeverity>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<Vec<AuditEvent>> {
    // This is a placeholder until the database module is fully implemented
    // In a real implementation, this would query the database for matching events
    Ok(Vec::new())
}

/// Export audit events to a file
pub async fn export_audit_events(
    path: impl Into<String>,
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
    identity: Option<String>,
    category: Option<AuditCategory>,
    action: Option<String>,
    resource: Option<String>,
    status: Option<AuditStatus>,
    severity: Option<AuditSeverity>,
) -> Result<usize> {
    use std::fs::File;
    use std::io::Write;

    // Query matching events
    let events = query_audit_events(
        start_time, end_time, identity, category, action, resource, status, severity, None, None,
    )
    .await?;

    // Write events to file
    let path = path.into();
    let mut file = File::create(&path).map_err(|e| ForgeError::IoError(e.to_string()))?;

    for event in &events {
        let json = serde_json::to_string(event)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;

        writeln!(file, "{}", json).map_err(|e| ForgeError::IoError(e.to_string()))?;
    }

    Ok(events.len())
}

/// Purge old audit events
pub async fn purge_old_audit_events(retention_days: u32) -> Result<usize> {
    // This is a placeholder until the database module is fully implemented
    // In a real implementation, this would delete events older than the retention period
    Ok(0)
}

/// Verify a signature
fn verify_signature(data: &[u8], signature: &str, public_key: &[u8]) -> Result<bool> {
    use base64::{engine::general_purpose, Engine as _};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let key_bytes: [u8; 32] = public_key[..32]
        .try_into()
        .map_err(|_| ForgeError::CryptoError("Invalid public key length".to_string()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ForgeError::CryptoError(format!("Invalid public key: {}", e)))?;

    let sig_bytes = general_purpose::STANDARD
        .decode(signature)
        .map_err(|e| ForgeError::CryptoError(format!("Invalid signature: {}", e)))?;

    let sig_array: [u8; 64] = sig_bytes[..64]
        .try_into()
        .map_err(|_| ForgeError::CryptoError("Invalid signature length".to_string()))?;
    let sig = Signature::from_bytes(&sig_array);

    key.verify(data, &sig)
        .map(|_| true)
        .map_err(|_| ForgeError::IntegrityBreach("Signature verification failed".into()))
}

/// Represents a signed segment of audit events for blockchain-style attestation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSegment {
    /// Events in this segment
    pub events: Vec<AuditEvent>,
    /// Segment index (monotonic)
    pub segment_index: u64,
    /// Hash of the previous segment (for chain-linking)
    pub prev_segment_hash: Option<String>,
    /// Signature over this segment
    pub segment_signature: Option<String>,
    /// Public key used for signing
    pub public_key: Option<Vec<u8>>,
}

impl AuditSegment {
    /// Compute the hash of the segment (excluding signature)
    pub fn compute_segment_hash(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut segment_clone = self.clone();
        segment_clone.segment_signature = None;
        let json = serde_json::to_string(&segment_clone)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(json.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }
}

/// Audit log with segmenting for blockchain-style attestation
pub struct SegmentedAuditLog {
    /// Current segment of events
    pub current_segment: AuditSegment,
    /// All completed segments (optional, for in-memory use)
    pub completed_segments: Vec<AuditSegment>,
    /// Segment size (default 100, configurable)
    segment_size: usize,
    /// Signing key
    signing_key: Option<Vec<u8>>,
}

impl SegmentedAuditLog {
    pub fn new(segment_size: Option<usize>, signing_key: Option<Vec<u8>>) -> Self {
        let size = segment_size.unwrap_or(100);
        Self {
            current_segment: AuditSegment {
                events: Vec::new(),
                segment_index: 0,
                prev_segment_hash: None,
                segment_signature: None,
                public_key: None,
            },
            completed_segments: Vec::new(),
            segment_size: size,
            signing_key,
        }
    }

    /// Add an event to the current segment, sign and rotate if needed
    pub fn add_event(&mut self, event: AuditEvent) -> Result<()> {
        self.current_segment.events.push(event);
        if self.current_segment.events.len() >= self.segment_size {
            self.sign_and_rotate_segment()?;
        }
        Ok(())
    }

    /// Sign the current segment and start a new one
    pub fn sign_and_rotate_segment(&mut self) -> Result<()> {
        if self.current_segment.events.is_empty() {
            return Ok(());
        }
        // Compute segment hash
        let segment_hash = self.current_segment.compute_segment_hash()?;
        // Sign the segment hash
        let signature = if let Some(key) = &self.signing_key {
            use base64::{engine::general_purpose, Engine as _};
            use ed25519_dalek::{Signer, SigningKey};
            let key_bytes: [u8; 32] = key[..32]
                .try_into()
                .map_err(|_| ForgeError::CryptoError("Invalid private key length".to_string()))?;
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let sig = signing_key.sign(segment_hash.as_bytes());
            Some(general_purpose::STANDARD.encode(sig.to_bytes()))
        } else {
            None
        };
        self.current_segment.segment_signature = signature;
        // Optionally store public key
        // self.current_segment.public_key = ...
        // Store completed segment
        let prev_hash = self.current_segment.prev_segment_hash.clone();
        let mut completed = self.current_segment.clone();
        completed.prev_segment_hash = prev_hash;
        self.completed_segments.push(completed);
        // Start new segment
        let new_index = self.current_segment.segment_index + 1;
        self.current_segment = AuditSegment {
            events: Vec::new(),
            segment_index: new_index,
            prev_segment_hash: Some(segment_hash),
            segment_signature: None,
            public_key: None,
        };
        Ok(())
    }

    /// Attestation API: verify all segments
    pub fn verify_all_segments(&self, public_key: &[u8]) -> Result<bool> {
        for segment in &self.completed_segments {
            if !Self::verify_segment_signature(segment, public_key)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Verify a segment's signature
    pub fn verify_segment_signature(segment: &AuditSegment, public_key: &[u8]) -> Result<bool> {
        use base64::{engine::general_purpose, Engine as _};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let hash = segment.compute_segment_hash()?;
        let sig_b64 = segment
            .segment_signature
            .as_ref()
            .ok_or_else(|| ForgeError::CryptoError("No segment signature".to_string()))?;
        let sig_bytes = general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| ForgeError::CryptoError(format!("Invalid signature: {}", e)))?;
        let sig_array: [u8; 64] = sig_bytes[..64]
            .try_into()
            .map_err(|_| ForgeError::CryptoError("Invalid signature length".to_string()))?;
        let sig = Signature::from_bytes(&sig_array);
        let key_bytes: [u8; 32] = public_key[..32]
            .try_into()
            .map_err(|_| ForgeError::CryptoError("Invalid public key length".to_string()))?;
        let key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| ForgeError::CryptoError(format!("Invalid public key: {}", e)))?;
        key.verify(hash.as_bytes(), &sig)
            .map(|_| true)
            .map_err(|_| {
                ForgeError::IntegrityBreach("Segment signature verification failed".into())
            })
    }
}

/// Asynchronous, non-blocking audit logger using a background thread
pub struct AsyncAuditLogger {
    sender: Sender<AuditEvent>,
    handle: Option<thread::JoinHandle<()>>,
}

impl AsyncAuditLogger {
    /// Start a new async logger, consuming events and writing via the provided closure
    pub fn new<F>(mut event_writer: F) -> Self
    where
        F: FnMut(AuditEvent) + Send + 'static,
    {
        let (tx, rx): (Sender<AuditEvent>, Receiver<AuditEvent>) = mpsc::channel();
        let handle = thread::spawn(move || {
            while let Ok(event) = rx.recv() {
                event_writer(event);
            }
        });
        Self {
            sender: tx,
            handle: Some(handle),
        }
    }

    /// Enqueue an event for async logging
    pub fn log(&self, event: AuditEvent) {
        let _ = self.sender.send(event);
    }

    /// Shutdown the logger, waiting for the background thread to finish
    pub fn shutdown(mut self) {
        drop(self.sender.clone()); // Close channel
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// AuditManager with per-tenant policy and redaction
pub struct DynamicAuditManager {
    /// Per-tenant policies
    policies: RwLock<HashMap<String, ExtendedAuditPolicy>>,
    /// Default policy
    default_policy: ExtendedAuditPolicy,
    /// Sinks
    sinks: Arc<RwLock<Vec<Box<dyn AuditSink>>>>,
}

impl DynamicAuditManager {
    pub fn new(default_policy: ExtendedAuditPolicy) -> Self {
        Self {
            policies: RwLock::new(HashMap::new()),
            default_policy,
            sinks: Arc::new(RwLock::new(Vec::new())),
        }
    }
    /// Set or update a policy for a tenant
    pub fn set_policy(&self, tenant_id: String, policy: ExtendedAuditPolicy) {
        self.policies.write().unwrap().insert(tenant_id, policy);
    }
    /// Remove a policy for a tenant
    pub fn remove_policy(&self, tenant_id: &str) {
        self.policies.write().unwrap().remove(tenant_id);
    }
    /// Get the policy for a tenant (or default)
    pub fn policy_for(&self, tenant_id: &str) -> ExtendedAuditPolicy {
        self.policies
            .read()
            .unwrap()
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| self.default_policy.clone())
    }
    /// Add a sink
    pub fn add_sink_dyn(&self, sink: Box<dyn AuditSink>) {
        self.sinks.write().unwrap().push(sink);
    }
    /// Log an event, applying per-tenant policy and redaction
    pub fn log(&self, mut event: AuditEvent) -> Result<()> {
        let tenant_id = event.identity.tenant_id.clone();
        let policy = self.policy_for(&tenant_id);
        // Filtering (reuse base logic)
        if !policy.base.enabled {
            return Ok(());
        }
        if (event.severity as u8) < (policy.base.min_severity as u8) {
            return Ok(());
        }
        // Redaction
        for (field, rule) in &policy.redaction {
            match field.as_str() {
                "user_id" => match rule {
                    RedactionRule::Redact => event.identity.user_id.clear(),
                    RedactionRule::Mask(mask) => event.identity.user_id = mask.clone(),
                },
                "resource_id" => match rule {
                    RedactionRule::Redact => event.resource_id = None,
                    RedactionRule::Mask(mask) => event.resource_id = Some(mask.clone()),
                },
                "details" => match rule {
                    RedactionRule::Redact => event.details = None,
                    RedactionRule::Mask(mask) => event.details = Some(serde_json::json!(mask)),
                },
                _ => {}
            }
        }
        // Write to sinks
        let sinks = self.sinks.read().unwrap();
        for sink in sinks.iter() {
            sink.write(&event)?;
        }
        Ok(())
    }
}

/// Query struct for advanced audit search
#[derive(Debug, Clone, Default)]
pub struct AuditQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub tenant_id: Option<String>,
    pub category: Option<AuditCategory>,
    pub action: Option<String>,
    pub resource: Option<String>,
    pub status: Option<AuditStatus>,
    pub severity: Option<AuditSeverity>,
    pub hash: Option<String>,
    pub signature: Option<String>,
    pub resource_id: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub trace_id: Option<String>,
    pub prev_hash: Option<String>,
}

impl AuditQuery {
    /// Query a slice of events in memory (can be replaced with DB-backed)
    pub fn query_events<'a>(&self, events: &'a [AuditEvent]) -> Vec<&'a AuditEvent> {
        events
            .iter()
            .filter(|e| {
                if let Some(start) = self.start_time {
                    if e.timestamp < start {
                        return false;
                    }
                }
                if let Some(end) = self.end_time {
                    if e.timestamp > end {
                        return false;
                    }
                }
                if let Some(ref tenant) = self.tenant_id {
                    if &e.identity.tenant_id != tenant {
                        return false;
                    }
                }
                if let Some(ref cat) = self.category {
                    if &e.category != cat {
                        return false;
                    }
                }
                if let Some(ref act) = self.action {
                    if &e.action != act {
                        return false;
                    }
                }
                if let Some(ref res) = self.resource {
                    if &e.resource != res {
                        return false;
                    }
                }
                if let Some(status) = self.status {
                    let event_status = match &e.outcome {
                        AuditOutcome::Success => AuditStatus::Success,
                        AuditOutcome::Failure(_) => AuditStatus::Failure,
                        AuditOutcome::Denied(_) => AuditStatus::Blocked,
                    };
                    if event_status != status {
                        return false;
                    }
                }
                if let Some(sev) = self.severity {
                    if e.severity != sev {
                        return false;
                    }
                }
                if let Some(ref hash) = self.hash {
                    if let Ok(ev_hash) = compute_event_hash(e) {
                        if &ev_hash != hash {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                if let Some(ref sig) = self.signature {
                    if let Some(ev_sig) = &e.signature {
                        if ev_sig != sig {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                true
            })
            .collect()
    }
}

/// Export events to JSON
pub fn export_events_json(events: &[AuditEvent]) -> Result<String> {
    serde_json::to_string_pretty(events).map_err(|e| ForgeError::SerializationError(e.to_string()))
}

/*
// CSV export requires the csv crate. Uncomment and add csv to Cargo.toml to enable.
/// Export events to CSV
// pub fn export_events_csv(events: &[AuditEvent]) -> Result<String> {
//     let mut wtr = csv::Writer::from_writer(vec![]);
//     for event in events {
//         wtr.serialize(event).map_err(|e| ForgeError::SerializationError(e.to_string()))?;
//     }
//     let data = wtr.into_inner().map_err(|e| ForgeError::SerializationError(e.to_string()))?;
//     String::from_utf8(data).map_err(|e| ForgeError::SerializationError(e.to_string()))
// }
*/

/// Forensic: find event by hash
pub fn find_event_by_hash<'a>(events: &'a [AuditEvent], hash: &str) -> Option<&'a AuditEvent> {
    events
        .iter()
        .find(|e| compute_event_hash(e).ok().as_deref() == Some(hash))
}

/// Forensic: find event by signature
pub fn find_event_by_signature<'a>(events: &'a [AuditEvent], sig: &str) -> Option<&'a AuditEvent> {
    events.iter().find(|e| e.signature.as_deref() == Some(sig))
}

/// Forensic: verify chain integrity for a slice of events
pub fn verify_chain_integrity(events: &[AuditEvent]) -> Result<bool> {
    verify_audit_chain(events)
}

/// Production-grade, pluggable audit event store abstraction
pub trait AuditEventStore: Send + Sync {
    /// Insert a new audit event (transactional)
    fn insert_event(&self, event: &AuditEvent) -> Result<()>;
    /// Query audit events with advanced filters
    fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>>;
    /// Export events in the given format (e.g., JSON, CSV)
    fn export_events(&self, query: &AuditQuery, format: &str) -> Result<String>;
    /// Begin a transaction (if supported)
    fn begin_transaction(&self) -> Result<Box<dyn AuditEventStoreTransaction>>;
    /// Backup the audit store to a target path
    fn backup(&self, target_path: &str) -> Result<()>;
    /// Restore the audit store from a backup
    fn restore(&self, backup_path: &str) -> Result<()>;
    /// Run schema migrations (if needed)
    fn migrate_schema(&self, target_version: u32) -> Result<()>;
    /// Get the current schema version
    fn schema_version(&self) -> u32;
    /// Get the backend name/type
    fn backend_name(&self) -> &'static str;
}

/// Transaction abstraction for ACID support
pub trait AuditEventStoreTransaction: Send + Sync {
    /// Commit the transaction
    fn commit(self: Box<Self>) -> Result<()>;
    /// Rollback the transaction
    fn rollback(self: Box<Self>) -> Result<()>;
    /// Insert an event within the transaction
    fn insert_event(&mut self, event: &AuditEvent) -> Result<()>;
}

// pub struct SqliteAuditStore {
//     conn: Mutex<Connection>,
// }

// impl SqliteAuditStore {
//     /// Create a new SqliteAuditStore (optionally encrypted)
//     pub fn new(conn: rusqlite::Connection) -> Self {
//         Self {
//             conn: std::sync::Mutex::new(conn)
//         }
//     }
// }

// impl AuditEventStore for SqliteAuditStore {
//     /// Insert a new audit event (encrypted, transactional)
//     fn insert_event(&self, event: &AuditEvent) -> Result<()> {
//         // Create a longer-lived mutable binding for the connection
//         let mut conn = self.conn.lock().unwrap();
//         let tx = conn.transaction()
//             .map_err(|e| ForgeError::DatabaseTransactionError(e.to_string()))?;

//         tx.execute(
//             "INSERT INTO audit_events (event_id, timestamp, tenant_id, user_id, action, resource, resource_id, outcome, category, severity, details, signature, session_id, request_id, trace_id, prev_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
//             params![
//                 event.event_id.to_string(),
//                 event.timestamp.to_rfc3339(),
//                 event.identity.tenant_id,
//                 event.identity.user_id,
//                 event.action,
//                 event.resource,
//                 event.resource_id,
//                 serde_json::to_string(&event.outcome).unwrap(),
//                 serde_json::to_string(&event.category).unwrap(),
//                 serde_json::to_string(&event.severity).unwrap(),
//                 event.details.as_ref().map(|d| d.to_string()),
//                 event.signature,
//                 event.session_id,
//                 event.request_id,
//                 event.trace_id,
//                 event.prev_hash,
//             ]
//         ).map_err(|e| ForgeError::DatabaseQueryError(e.to_string()))?;

//         tx.commit().map_err(|e| ForgeError::DatabaseTransactionError(e.to_string()))?;
//         Ok(())
//     }

//     fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
//         let mut sql = "SELECT * FROM audit_events WHERE 1=1".to_string();
//         let mut params: Vec<(&str, &dyn rusqlite::ToSql)> = vec![];

//         if let Some(ref tenant) = query.tenant_id {
//             sql += " AND tenant_id = :tenant_id";
//             params.push((":tenant_id", tenant));
//         }

//         if let Some(ref act) = query.action {
//             sql += " AND action = :action";
//             params.push((":action", act));
//         }

//         // Add more filters as needed

//         let mut conn = self.conn.lock().unwrap();
//         let mut stmt = conn.prepare(&sql)
//             .map_err(|e| ForgeError::DatabaseQueryError(e.to_string()))?;

//         let rows = stmt.query_map(
//             &params[..],
//             |row| {
//                 // Parse row into AuditEvent
//                 let event_id: String = row.get(0)?;
//                 let timestamp: String = row.get(1)?;
//                 let tenant_id: String = row.get(2)?;
//                 let user_id: String = row.get(3)?;
//                 let action: String = row.get(4)?;
//                 let resource: String = row.get(5)?;
//                 let resource_id: Option<String> = row.get(6)?;
//                 let outcome: String = row.get(7)?;
//                 let category: String = row.get(8)?;
//                 let severity: String = row.get(9)?;
//                 let details: Option<String> = row.get(10)?;
//                 let signature: Option<String> = row.get(11)?;
//                 let session_id: Option<String> = row.get(12)?;
//                 let request_id: Option<String> = row.get(13)?;
//                 let trace_id: Option<String> = row.get(14)?;
//                 let prev_hash: Option<String> = row.get(15)?;

//                 Ok(AuditEvent {
//                     event_id: uuid::Uuid::parse_str(&event_id).unwrap(),
//                     timestamp: chrono::DateTime::parse_from_rfc3339(&timestamp).unwrap().with_timezone(&chrono::Utc),
//                     identity: IdentityContext::new(tenant_id, user_id),
//                     action,
//                     resource,
//                     resource_id,
//                     outcome: serde_json::from_str(&outcome).unwrap(),
//                     category: serde_json::from_str(&category).unwrap(),
//                     severity: serde_json::from_str(&severity).unwrap(),
//                     details: details.and_then(|d| serde_json::from_str(&d).ok()),
//                     signature,
//                     session_id,
//                     request_id,
//                     trace_id,
//                     prev_hash,
//                 })
//             }
//         ).map_err(|e| ForgeError::DatabaseQueryError(e.to_string()))?;

//         Ok(rows.filter_map(|r| r.ok()).collect())
//     }

//     fn export_events(&self, query: &AuditQuery, format: &str) -> Result<String> {
//         let events = self.query_events(query)?;
//         match format {
//             "json" => export_events_json(&events),
//             _ => Err(ForgeError::SerializationError("Unsupported export format".to_string())),
//         }
//     }
//     /// Begin a transaction (ACID)
//     fn begin_transaction(&self) -> Result<Box<dyn AuditEventStoreTransaction>> {
//         unimplemented!()
//     }
//     /// Backup the audit store to a target path
//     fn backup(&self, _target_path: &str) -> Result<()> {
//         // TODO: Use SQLite backup API
//         unimplemented!()
//     }
//     /// Restore the audit store from a backup
//     fn restore(&self, _backup_path: &str) -> Result<()> {
//         // TODO: Use SQLite restore API
//         unimplemented!()
//     }
//     /// Run schema migrations (if needed)
//     fn migrate_schema(&self, _target_version: u32) -> Result<()> {
//         // TODO: Use migration scripts
//         unimplemented!()
//     }
//     /// Get the current schema version
//     fn schema_version(&self) -> u32 { 1 }
//     /// Get the backend name/type
//     fn backend_name(&self) -> &'static str { "sqlite" }
// }

/// Redb/RocksDB audit store (compressed, sharded, event logs)
pub struct RedbAuditStore {/* fields omitted */}
impl RedbAuditStore {
    /// Create a new RedbAuditStore (with config)
    pub fn new(/* config fields */) -> Self {
        Self { /* fields omitted */ }
    }
}

impl AuditEventStore for RedbAuditStore {
    /// Insert a new audit event (compressed, encrypted, sharded)
    fn insert_event(&self, event: &AuditEvent) -> Result<()> {
        let mut manager = EventManager::new("audit_logs");
        manager.publish_event(event).map(|_| ())
    }
    /// Query audit events (by time, tenant, category, action, etc.)
    fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        // Use RedbManager to scan and filter events
        let manager = RedbManager::get_instance()?;
        let mut results = Vec::new();
        // For demo: scan all events in "audit_logs" topic
        let events: Vec<AuditEvent> = manager.get_all_events("audit_logs")?;
        for event in events {
            // Basic filtering (expand as needed)
            if let Some(ref tenant) = query.tenant_id {
                if &event.identity.tenant_id != tenant {
                    continue;
                }
            }
            if let Some(ref cat) = query.category {
                if &event.category != cat {
                    continue;
                }
            }
            if let Some(ref act) = query.action {
                if &event.action != act {
                    continue;
                }
            }
            if let Some(sev) = query.severity {
                if event.severity != sev {
                    continue;
                }
            }
            if let Some(ref hash) = query.hash {
                if let Ok(ev_hash) = compute_event_hash(&event) {
                    if &ev_hash != hash {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            // Add more filters as needed
            results.push(event);
        }
        Ok(results)
    }
    /// Export events in the given format (JSON only for now)
    fn export_events(&self, query: &AuditQuery, format: &str) -> Result<String> {
        let events = self.query_events(query)?;
        match format {
            "json" => export_events_json(&events),
            _ => Err(ForgeError::SerializationError(
                "Unsupported export format".to_string(),
            )),
        }
    }
    /// Begin a transaction (not yet implemented)
    fn begin_transaction(&self) -> Result<Box<dyn AuditEventStoreTransaction>> {
        Err(ForgeError::DatabaseTransactionError(
            "RedbAuditStore transactions not yet implemented".to_string(),
        ))
    }
    /// Backup the audit store to a target path (stub)
    fn backup(&self, _target_path: &str) -> Result<()> {
        // TODO: Use RedbManager to backup DB
        Ok(())
    }
    /// Restore the audit store from a backup (stub)
    fn restore(&self, _backup_path: &str) -> Result<()> {
        // TODO: Use RedbManager to restore DB
        Ok(())
    }
    /// Run schema migrations (stub)
    fn migrate_schema(&self, _target_version: u32) -> Result<()> {
        Ok(())
    }
    /// Get the current schema version
    fn schema_version(&self) -> u32 {
        1
    }
    /// Get the backend name/type
    fn backend_name(&self) -> &'static str {
        "redb"
    }
}

/// Cloud/distributed audit store (DynamoDB, CockroachDB, etc.)
pub struct CloudAuditStore {
    // For now, use a mock/in-memory Vec for demo/testing
    events: StdMutex<Vec<AuditEvent>>,
}

impl CloudAuditStore {
    /// Create a new CloudAuditStore (mock/in-memory for now)
    pub fn new() -> Self {
        Self {
            events: StdMutex::new(Vec::new()),
        }
    }
    // TODO: Add config for real cloud backends
}

impl AuditEventStore for CloudAuditStore {
    /// Insert a new audit event (mock/in-memory)
    fn insert_event(&self, event: &AuditEvent) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
    /// Query audit events (mock/in-memory, filter by tenant, action, etc.)
    fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let events = self.events.lock().unwrap();
        let mut results = Vec::new();
        for event in events.iter() {
            if let Some(ref tenant) = query.tenant_id {
                if &event.identity.tenant_id != tenant {
                    continue;
                }
            }
            if let Some(ref act) = query.action {
                if &event.action != act {
                    continue;
                }
            }
            if let Some(ref cat) = query.category {
                if &event.category != cat {
                    continue;
                }
            }
            if let Some(sev) = query.severity {
                if event.severity != sev {
                    continue;
                }
            }
            if let Some(ref hash) = query.hash {
                if let Ok(ev_hash) = compute_event_hash(event) {
                    if &ev_hash != hash {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            results.push(event.clone());
        }
        Ok(results)
    }
    /// Export events in the given format (JSON only for now)
    fn export_events(&self, query: &AuditQuery, format: &str) -> Result<String> {
        let events = self.query_events(query)?;
        match format {
            "json" => export_events_json(&events),
            _ => Err(ForgeError::SerializationError(
                "Unsupported export format".to_string(),
            )),
        }
    }
    /// Begin a transaction (not yet implemented)
    fn begin_transaction(&self) -> Result<Box<dyn AuditEventStoreTransaction>> {
        Err(ForgeError::DatabaseTransactionError(
            "CloudAuditStore transactions not yet implemented".to_string(),
        ))
    }
    /// Backup the audit store to a target path (serialize events to file)
    fn backup(&self, target_path: &str) -> Result<()> {
        let events = self.events.lock().unwrap();
        let json = serde_json::to_string(&*events)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        std::fs::write(target_path, json).map_err(|e| ForgeError::IoError(e.to_string()))?;
        Ok(())
    }
    /// Restore the audit store from a backup (deserialize events from file)
    fn restore(&self, backup_path: &str) -> Result<()> {
        let json =
            std::fs::read_to_string(backup_path).map_err(|e| ForgeError::IoError(e.to_string()))?;
        let events: Vec<AuditEvent> = serde_json::from_str(&json)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        let mut store = self.events.lock().unwrap();
        *store = events;
        Ok(())
    }
    /// Run schema migrations (stub)
    fn migrate_schema(&self, _target_version: u32) -> Result<()> {
        Ok(())
    }
    /// Get the current schema version
    fn schema_version(&self) -> u32 {
        1
    }
    /// Get the backend name/type
    fn backend_name(&self) -> &'static str {
        "cloud-mock"
    }
}

/// ShardedAuditStore: routes events by tenant, time, or hash to underlying stores
pub struct ShardedAuditStore {
    shards: Vec<Box<dyn AuditEventStore>>,
    // TODO: Add routing config, shard keys, failover logic
}

impl ShardedAuditStore {
    /// Create a new ShardedAuditStore with given shards
    pub fn new(shards: Vec<Box<dyn AuditEventStore>>) -> Self {
        Self { shards }
    }
    /// Add a new shard at runtime
    pub fn add_shard(&mut self, shard: Box<dyn AuditEventStore>) {
        self.shards.push(shard);
    }
    /// Remove a shard by index
    pub fn remove_shard(&mut self, idx: usize) {
        if idx < self.shards.len() {
            self.shards.remove(idx);
        }
    }
    /// Get the shard for a given event (by tenant, hash, etc.)
    fn select_shard(&self, event: &AuditEvent) -> usize {
        // Simple: hash tenant_id, mod by shard count
        let key = &event.identity.tenant_id;
        let hash = blake3::hash(key.as_bytes());
        (u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap()) % self.shards.len() as u64)
            as usize
    }
    /// Get the shard for a query (for demo, query all)
    fn all_shards(&self) -> &[Box<dyn AuditEventStore>] {
        &self.shards
    }
}

impl AuditEventStore for ShardedAuditStore {
    /// Insert a new audit event (routes to correct shard)
    fn insert_event(&self, event: &AuditEvent) -> Result<()> {
        let idx = self.select_shard(event);
        self.shards[idx].insert_event(event)
    }
    /// Query audit events (queries all shards, merges results)
    fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let mut results = Vec::new();
        for shard in self.all_shards() {
            let mut shard_results = shard.query_events(query)?;
            results.append(&mut shard_results);
        }
        Ok(results)
    }
    /// Export events in the given format (JSON only for now)
    fn export_events(&self, query: &AuditQuery, format: &str) -> Result<String> {
        let events = self.query_events(query)?;
        match format {
            "json" => export_events_json(&events),
            _ => Err(ForgeError::SerializationError(
                "Unsupported export format".to_string(),
            )),
        }
    }
    /// Begin a transaction (not yet implemented)
    fn begin_transaction(&self) -> Result<Box<dyn AuditEventStoreTransaction>> {
        Err(ForgeError::DatabaseTransactionError(
            "ShardedAuditStore transactions not yet implemented".to_string(),
        ))
    }
    /// Backup all shards
    fn backup(&self, target_path: &str) -> Result<()> {
        for (i, shard) in self.shards.iter().enumerate() {
            let path = format!("{}/shard_{}.bak", target_path, i);
            shard.backup(&path)?;
        }
        Ok(())
    }
    /// Restore all shards
    fn restore(&self, backup_path: &str) -> Result<()> {
        for (i, shard) in self.shards.iter().enumerate() {
            let path = format!("{}/shard_{}.bak", backup_path, i);
            shard.restore(&path)?;
        }
        Ok(())
    }
    /// Run schema migrations on all shards
    fn migrate_schema(&self, target_version: u32) -> Result<()> {
        for shard in &self.shards {
            shard.migrate_schema(target_version)?;
        }
        Ok(())
    }
    /// Get the current schema version (from first shard)
    fn schema_version(&self) -> u32 {
        self.shards.first().map(|s| s.schema_version()).unwrap_or(1)
    }
    /// Get the backend name/type
    fn backend_name(&self) -> &'static str {
        "sharded"
    }
}

/// Metrics for audit system (Prometheus-compatible)
#[derive(Default)]
pub struct AuditMetrics {
    pub event_count: AtomicUsize,
    pub error_count: AtomicUsize,
    pub per_sink_success: Mutex<HashMap<String, usize>>,
    pub per_sink_error: Mutex<HashMap<String, usize>>,
    pub queue_size: AtomicUsize,
}

impl AuditMetrics {
    pub fn inc_event(&self) {
        self.event_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_sink_success(&self, sink: &str) {
        let mut map = self.per_sink_success.lock().unwrap();
        *map.entry(sink.to_string()).or_insert(0) += 1;
    }
    pub fn inc_sink_error(&self, sink: &str) {
        let mut map = self.per_sink_error.lock().unwrap();
        *map.entry(sink.to_string()).or_insert(0) += 1;
    }
    pub fn set_queue_size(&self, size: usize) {
        self.queue_size.store(size, Ordering::Relaxed);
    }
    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut out = String::new();
        out += &format!("# HELP audit_event_count Total audit events\n# TYPE audit_event_count counter\naudit_event_count {}\n", self.event_count.load(Ordering::Relaxed));
        out += &format!("# HELP audit_error_count Total audit errors\n# TYPE audit_error_count counter\naudit_error_count {}\n", self.error_count.load(Ordering::Relaxed));
        out += &format!("# HELP audit_queue_size Current audit queue size\n# TYPE audit_queue_size gauge\naudit_queue_size {}\n", self.queue_size.load(Ordering::Relaxed));
        let map = self.per_sink_success.lock().unwrap();
        for (sink, count) in map.iter() {
            out += &format!("audit_sink_success{{sink=\"{}\"}} {}\n", sink, count);
        }
        let map = self.per_sink_error.lock().unwrap();
        for (sink, count) in map.iter() {
            out += &format!("audit_sink_error{{sink=\"{}\"}} {}\n", sink, count);
        }
        out
    }
}

/// Health status for sinks and audit system
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

pub trait HealthCheck {
    fn health(&self) -> HealthStatus;
}

// Example HealthCheck for MemoryAuditSink
impl HealthCheck for MemoryAuditSink {
    fn health(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

// Example HealthCheck for ReplicatedAuditSink
impl HealthCheck for ReplicatedAuditSink {
    fn health(&self) -> HealthStatus {
        // For now, just check if all sinks are present (cannot downcast trait objects safely)
        if self.sinks.is_empty() {
            HealthStatus::Degraded("No sinks configured".to_string())
        } else {
            HealthStatus::Healthy
        }
    }
}

// Stub: HTTP endpoint for Prometheus metrics (feature-gated)
#[cfg(feature = "metrics-http")]
pub fn start_metrics_http_server(metrics: &'static AuditMetrics, addr: &str) {
    // Use tiny_http, hyper, or axum for real implementation
    // For now, just a stub
    println!("Metrics HTTP server would run at {}", addr);
}

/// Initialize Redb for production use (singleton pattern)
pub fn init_audit_redb(options: Option<RedbOptions>) -> Result<()> {
    let opts = options.unwrap_or_default();
    init_redb(opts)
}

impl RedbAuditStore {
    /// Create a new RedbAuditStore with global RedbManager
    pub fn new_with_manager() -> Self {
        let _ = RedbManager::get_instance().expect("RedbManager must be initialized");
        Self { /* fields omitted */ }
    }
}

impl StreamableEvent for AuditEvent {
    fn event_type(&self) -> &'static str {
        "audit_event"
    }
    fn event_timestamp(&self) -> chrono::DateTime<chrono::Utc> {
        self.timestamp
    }
    fn to_stream_json(&self) -> crate::error::Result<String> {
        serde_json::to_string(self)
            .map_err(|e| crate::error::ForgeError::SerializationError(e.to_string()))
    }
    fn priority(&self) -> EventPriority {
        match self.severity {
            AuditSeverity::Critical => EventPriority::Critical,
            AuditSeverity::Error => EventPriority::High,
            AuditSeverity::Warning => EventPriority::Medium,
            AuditSeverity::Info => EventPriority::Low,
        }
    }
    fn topic(&self) -> &str {
        "audit_logs"
    }
    fn checkpoint_marker(&self) -> Option<String> {
        self.prev_hash.clone()
    }
    fn metadata(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("event_id".to_string(), self.event_id.to_string());
        map.insert("action".to_string(), self.action.clone());
        map.insert("resource".to_string(), self.resource.clone());
        if let Some(ref rid) = self.resource_id {
            map.insert("resource_id".to_string(), rid.clone());
        }
        map.insert("category".to_string(), format!("{:?}", self.category));
        map.insert("severity".to_string(), format!("{:?}", self.severity));
        map
    }
}

#[cfg(test)]
pub struct RedbAuditStoreTest {
    events: std::sync::Mutex<Vec<AuditEvent>>,
}

#[cfg(test)]
impl RedbAuditStoreTest {
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[cfg(test)]
impl AuditEventStore for RedbAuditStoreTest {
    fn insert_event(&self, event: &AuditEvent) -> Result<()> {
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
    fn query_events(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>> {
        let events = self.events.lock().unwrap();
        let mut results = Vec::new();
        for event in events.iter() {
            if let Some(ref tenant) = query.tenant_id {
                if &event.identity.tenant_id != tenant {
                    continue;
                }
            }
            if let Some(ref act) = query.action {
                if &event.action != act {
                    continue;
                }
            }
            if let Some(ref cat) = query.category {
                if &event.category != cat {
                    continue;
                }
            }
            if let Some(ref resource) = query.resource {
                if &event.resource != resource {
                    continue;
                }
            }
            if let Some(ref resource_id) = query.resource_id {
                if event.resource_id.as_ref() != Some(resource_id) {
                    continue;
                }
            }
            if let Some(sev) = query.severity {
                if event.severity != sev {
                    continue;
                }
            }
            if let Some(ref hash) = query.hash {
                if let Ok(ev_hash) = compute_event_hash(event) {
                    if &ev_hash != hash {
                        continue;
                    }
                } else {
                    continue;
                }
            }
            if let Some(ref sig) = query.signature {
                if event.signature.as_ref() != Some(sig) {
                    continue;
                }
            }
            if let Some(ref session_id) = query.session_id {
                if event.session_id.as_ref() != Some(session_id) {
                    continue;
                }
            }
            if let Some(ref request_id) = query.request_id {
                if event.request_id.as_ref() != Some(request_id) {
                    continue;
                }
            }
            if let Some(ref trace_id) = query.trace_id {
                if event.trace_id.as_ref() != Some(trace_id) {
                    continue;
                }
            }
            if let Some(ref prev_hash) = query.prev_hash {
                if event.prev_hash.as_ref() != Some(prev_hash) {
                    continue;
                }
            }
            if let Some(status) = query.status {
                let event_status = match &event.outcome {
                    AuditOutcome::Success => AuditStatus::Success,
                    AuditOutcome::Failure(_) => AuditStatus::Failure,
                    AuditOutcome::Denied(_) => AuditStatus::Blocked,
                };
                if event_status != status {
                    continue;
                }
            }
            results.push(event.clone());
        }

        Ok(results)
    }
    fn export_events(&self, query: &AuditQuery, format: &str) -> Result<String> {
        let events = self.query_events(query)?;
        match format {
            "json" => export_events_json(&events),
            _ => Err(ForgeError::SerializationError(
                "Unsupported export format".to_string(),
            )),
        }
    }
    fn begin_transaction(&self) -> Result<Box<dyn AuditEventStoreTransaction>> {
        Err(ForgeError::DatabaseTransactionError(
            "RedbAuditStoreTest transactions not implemented".to_string(),
        ))
    }
    fn backup(&self, target_path: &str) -> Result<()> {
        let events = self.events.lock().unwrap();
        let json = serde_json::to_string(&*events)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        std::fs::write(target_path, json).map_err(|e| ForgeError::IoError(e.to_string()))?;
        Ok(())
    }
    fn restore(&self, backup_path: &str) -> Result<()> {
        let json =
            std::fs::read_to_string(backup_path).map_err(|e| ForgeError::IoError(e.to_string()))?;
        let events: Vec<AuditEvent> = serde_json::from_str(&json)
            .map_err(|e| ForgeError::SerializationError(e.to_string()))?;
        let mut store = self.events.lock().unwrap();
        *store = events;
        Ok(())
    }
    fn migrate_schema(&self, _target_version: u32) -> Result<()> {
        Ok(())
    }
    fn schema_version(&self) -> u32 {
        1
    }
    fn backend_name(&self) -> &'static str {
        "redb-test"
    }
}
