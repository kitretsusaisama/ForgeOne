# Audit System

## Overview
The Audit module provides a comprehensive audit logging system for the ForgeOne platform, ensuring accountability, compliance, and security monitoring across the system.

## Key Features
- Immutable audit stream signing and verification
- Configurable audit policies and retention
- Multiple audit sink implementations (file, database, memory)
- Categorized and severity-based audit events
- Helper functions for common audit scenarios
- Query and export capabilities
- Compliance-oriented audit trail management

## Core Components

### AuditSeverity
Audit event severity levels:
- `Info` - Informational events
- `Warning` - Warning events
- `Error` - Error events
- `Critical` - Critical events

### AuditCategory
Audit event categories:
- `Authentication` - Authentication events (login, logout, etc.)
- `Authorization` - Authorization events (access granted/denied)
- `DataAccess` - Data access events (read, write, delete)
- `Configuration` - Configuration changes
- `System` - System events (startup, shutdown, etc.)
- `Security` - Security events (intrusion detection, etc.)
- `Compliance` - Compliance events
- `UserManagement` - User management events
- `Custom` - Custom events

### AuditOutcome
The outcome of an audit event:
- `Success` - The action succeeded
- `Failure` - The action failed
- `Denied` - The action was denied

### AuditEvent
An audit event for the system:
- `event_id` - The ID of this event
- `timestamp` - The timestamp of this event
- `identity` - The identity context of this event
- `action` - The action performed
- `resource` - The resource affected
- `resource_id` - The resource identifier (if applicable)
- `outcome` - The outcome of the action
- `category` - The category of the event
- `severity` - The severity level of the event
- `details` - Additional details about the event
- `signature` - The signature of this event
- `session_id` - Session identifier
- `request_id` - Request identifier
- `trace_id` - Trace identifier for distributed tracing
- `prev_hash` - Hash of the previous event (for tamper-evident chain)

### AuditPolicy
Audit policy for controlling audit behavior:
- `enabled` - Whether to enable audit logging
- `min_severity` - Minimum severity level to log
- `include_categories` - Categories to include
- `exclude_categories` - Categories to exclude
- `log_success` - Whether to log successful events
- `log_failure` - Whether to log failed events
- `include_context` - Whether to include context information
- `retention_days` - Maximum retention period in days
- `sign_events` - Whether to sign audit events

## Database Schema

### Redb Logical Schema

#### System Database
- `system.redb`
  - `metadata`: System-wide metadata (key-value)
  - `snapshots`: Snapshot metadata (key-value)
  - `metrics`: System metrics (key-value)
  - `settings`: Config and feature flags (key-value)

#### Logs Database (Sharded)
- `logs_shard_N.redb` (N = 0..shard_count-1)
  - `logs`: Log entries (id → serialized LogEntry)
  - `log_index`: Index for fast search (topic, timestamp)
  - `checkpoints`: Checkpoint markers for replay

#### Blobs Database (Sharded)
- `blobs_shard_N.redb`
  - `blob_metadata`: Blob metadata (id → serialized BlobMetadata)
  - `blob_chunks`: Chunked blob data (id+chunk → bytes)
  - `blob_index`: Index for fast lookup

#### Events Database (Sharded)
- `events_shard_N.redb`
  - `events`: Event entries (id → serialized EventMessage)
  - `event_index`: Index for fast search (topic, timestamp)
  - `topics`: Topic metadata

## Data Models
- `LogEntry`: id, topic, timestamp, severity, message, metadata, checkpoint_marker, content_hash
- `BlobMetadata`: id, name, content_type, size, created_at, created_by, checksum, encrypted, compressed, chunk_count, metadata
- `BlobChunk`: blob_id, chunk_index, data, checksum
- `EventMessage`: id, topic, timestamp, priority, payload, metadata, checkpoint_marker

## Usage Example
```rust
// Get the audit manager
let audit_manager = audit::get_audit_manager()?;

// Create an audit event
let event = AuditEvent {
    event_id: Uuid::new_v4(),
    timestamp: Utc::now(),
    identity: identity_context.clone(),
    action: "login".to_string(),
    resource: "system".to_string(),
    resource_id: None,
    outcome: AuditOutcome::Success,
    category: AuditCategory::Authentication,
    severity: AuditSeverity::Info,
    details: Some(serde_json::json!({"ip": "192.168.1.1"})),
    signature: None,
    session_id: Some(session_id.to_string()),
    request_id: Some(request_id.to_string()),
    trace_id: None,
    prev_hash: None,
};

// Log the audit event
audit_manager.log_event(event)?;
```

## Related Modules
- [Identity](./identity.md)
- [DB](./db.md)
- [Crypto](./crypto.md)
- [Policy](./policy.md)