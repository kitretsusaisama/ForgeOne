# ForgeOne Common Module Documentation

*This document is production-ready, MNC-grade, and compliance-focused. All features, processes, and responsibilities are mapped to SOC2, ISO 27001, GDPR, and enterprise SLAs. Security, audit, and evidence generation are integral to every step.*

---

## Overview
The Common module is the sentient core of ForgeOne, providing a trust-aware, AI-augmented, self-adaptive foundation for enterprise container intelligence. This documentation covers all the components of the Common module, with operational, compliance, and integration guarantees.

## Core Principles
Every function, type, and trace in the Common module is:
- **Contextual** (aware of who, where, why)
- **Causal** (tracks origin, intent, and policy path)
- **Comprehensible** (LLM-readable, developer-debuggable, auditor-verifiable)
- **Cryptographic** (provable, signed, and tamper-evident)
- **Resilient** (self-healing, fault-tolerant, and recoverable)

## Module Documentation

### Core Modules
- [Audit](./audit.md) - Comprehensive audit logging system
- [Bootstrap](./bootstrap.md) - Trust-aware boot process
- [Config](./config.md) - Multi-layer configuration system with attestation
- [Crypto](./crypto.md) - Comprehensive cryptographic functionality
- [DB](./db.md) - Database abstraction layer
- [Diagnostics](./diagnostics.md) - Self-diagnostic engine
- [Error](./error.md) - Enterprise error handling system
- [Identity](./identity.md) - Identity context and trust vectors
- [Macros](./macros.md) - Utility macros for logging, tracing, and policy enforcement
- [Model](./model.md) - Common data models
- [Observer](./observer.md) - LLM-explainable observation system
- [Policy](./policy.md) - DSL and runtime policy matcher
- [Prelude](./prelude.md) - Type-safe, controlled global interface
- [Telemetry](./telemetry.md) - Comprehensive telemetry capabilities
- [Trust](./trust.md) - Zero Trust Policy and graph engine

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

## Data Models
- `LogEntry`: id, topic, timestamp, severity, message, metadata, checkpoint_marker, content_hash
- `BlobMetadata`: id, name, content_type, size, created_at, created_by, checksum, encrypted, compressed, chunk_count, metadata
- `BlobChunk`: blob_id, chunk_index, data, checksum
- `EventMessage`: id, topic, timestamp, priority, payload, metadata, checkpoint_marker

## Getting Started

### Initialization
```rust
// Initialize with default configuration
common::init()?;

// Or initialize with custom configuration
common::init_with_config("config.json")?;

// Initialize with database support
common::init_with_db("config.json")?;
```

### Shutdown
```rust
// Shutdown the common crate
common::shutdown()?;
```

## Operational & Compliance Guarantees
- **All actions, configuration changes, and database operations are logged, versioned, and exportable for audit and regulatory review.**
- **Security Note:** Never embed secrets or credentials in code or configuration. Use environment variables and secure storage only.
- **Error Handling:** All API calls and module functions return detailed error types. All errors are logged and can be exported for audit.
- **Integration:** The common module exposes a stable ABI and API for integration with external systems, plugins, and observability tools.
- **Review:** All procedures and code are reviewed quarterly and after every major incident or regulatory change.

## Troubleshooting
- **Initialization Failure:** Ensure configuration files and database files are present and valid. Check logs for error details.
- **Database Error:** Validate schema and file permissions. All errors are logged with full context.
- **Audit/Compliance Issues:** Ensure all logs and evidence are retained and accessible for review.

## Related Documentation
- [API Documentation](../api/README.md)
- [Architecture Documentation](../architecture/README.md)
- [Compliance Documentation](../compliance/README.md)

---

*This document is reviewed quarterly and after every major incident or regulatory change. For questions, contact the ForgeOne compliance or platform engineering team.*