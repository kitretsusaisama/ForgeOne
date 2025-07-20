# Database System

## Overview
The Database module provides a comprehensive database abstraction layer for the ForgeOne platform, supporting various database backends with a unified interface.

## Key Features
- Multiple database backend support
- Encryption and security
- Data integrity verification
- Performance metrics and monitoring
- Backup and recovery mechanisms
- Schema management
- Snapshot capabilities

## Core Components

### Database Backends
- `RedbManager` - Manager for the Redb database
- `EventManager` - Manager for event storage and retrieval

### Database Operations
- `access.rs` - Database access control and permissions
- `crypto.rs` - Database encryption and decryption
- `indxdb.rs` - Indexed database operations
- `integrity.rs` - Data integrity verification
- `metrics.rs` - Database performance metrics
- `model.rs` - Database data models
- `recovery.rs` - Database backup and recovery
- `redb.rs` - Redb-specific implementation
- `schema.rs` - Database schema management
- `snapshot.rs` - Database snapshot capabilities

### Data Models
- `StreamableEvent` - Event that can be streamed
- `EventPriority` - Priority levels for events

## Database Schema

### System Database
- `system.redb`
  - `metadata`: System-wide metadata (key-value)
  - `snapshots`: Snapshot metadata (key-value)
  - `metrics`: System metrics (key-value)
  - `settings`: Config and feature flags (key-value)

### Logs Database (Sharded)
- `logs_shard_N.redb` (N = 0..shard_count-1)
  - `logs`: Log entries (id → serialized LogEntry)
  - `log_index`: Index for fast search (topic, timestamp)
  - `checkpoints`: Checkpoint markers for replay

### Blobs Database (Sharded)
- `blobs_shard_N.redb`
  - `blob_metadata`: Blob metadata (id → serialized BlobMetadata)
  - `blob_chunks`: Chunked blob data (id+chunk → bytes)
  - `blob_index`: Index for fast lookup

### Events Database (Sharded)
- `events_shard_N.redb`
  - `events`: Event entries (id → serialized EventMessage)
  - `event_index`: Index for fast search (topic, timestamp)
  - `topics`: Topic metadata

## Usage Example
```rust
// Initialize the database
let db_options = DbOptions {
    path: "data/redb".to_string(),
    encryption_key: Some("secret-key".to_string()),
    max_size_gb: 10,
    shard_count: 4,
};
let db = init_redb(db_options)?;

// Store an event
let event = EventMessage {
    id: Uuid::new_v4(),
    topic: "system.startup".to_string(),
    timestamp: Utc::now(),
    priority: EventPriority::High,
    payload: serde_json::to_string(&payload)?,
    metadata: HashMap::new(),
    checkpoint_marker: None,
};
db.store_event(&event)?;
```

## Related Modules
- [Audit](./audit.md)
- [Crypto](./crypto.md)
- [Error](./error.md)