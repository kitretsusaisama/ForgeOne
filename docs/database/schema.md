# ForgeOne Database Schema (Redb, Atomic Storage-Manager, DMCOA)

*This document provides an advanced, MNC-grade, production-ready, and compliance-focused schema for ForgeOne. All data models, features, and flows are mapped to SOC2, ISO 27001, GDPR, and enterprise audit requirements.*

## 1. Atomic Module Reference
- [modules/storage-manager-l6.txt]: Storage, schema, migration, backup/restore
- [modules/common-l1.txt]: Shared types, config, error handling

## 2. Redb Logical Schema & Compliance Mapping

### **System Database**
- `system.redb`
  - `metadata`: System-wide metadata (key-value, encrypted, audit-logged) [GDPR Art.32, SOC2 CC6]
  - `snapshots`: Snapshot metadata (key-value, encrypted, versioned, audit-logged) [ISO 27001 A.12, SOC2 CC7]
  - `metrics`: System metrics (key-value, retention policy, audit-logged) [SOC2 CC7]
  - `settings`: Config and feature flags (key-value, encrypted, versioned, audit-logged) [SOC2 CC6, ISO 27001 A.9]

### **Logs Database (Sharded)**
- `logs_shard_N.redb` (N = 0..shard_count-1)
  - `logs`: Log entries (id → serialized LogEntry, encrypted, immutable, audit-logged) [SOC2 CC7, ISO 27001 A.12, GDPR Art.30]
  - `log_index`: Index for fast search (topic, timestamp, audit-logged)
  - `checkpoints`: Checkpoint markers for replay (versioned, audit-logged)

### **Blobs Database (Sharded)**
- `blobs_shard_N.redb`
  - `blob_metadata`: Blob metadata (id → serialized BlobMetadata, encrypted, audit-logged) [GDPR Art.32, SOC2 CC6]
  - `blob_chunks`: Chunked blob data (id+chunk → bytes, encrypted, compressed, audit-logged) [SOC2 CC6, ISO 27001 A.10]
  - `blob_index`: Index for fast lookup (audit-logged)

### **Events Database (Sharded)**
- `events_shard_N.redb`
  - `events`: Event entries (id → serialized EventMessage, encrypted, audit-logged) [SOC2 CC7, ISO 27001 A.12]
  - `event_index`: Index for fast search (topic, timestamp, audit-logged)
  - `topics`: Topic metadata (encrypted, audit-logged)

## 3. Data Models & Compliance
- **LogEntry**: id, topic, timestamp, severity, message, metadata, checkpoint_marker, content_hash [GDPR Art.30, SOC2 CC7]
- **BlobMetadata**: id, name, content_type, size, created_at, created_by, checksum, encrypted, compressed, chunk_count, metadata [GDPR Art.32, SOC2 CC6]
- **BlobChunk**: blob_id, chunk_index, data, checksum [SOC2 CC6, ISO 27001 A.10]
- **EventMessage**: id, topic, timestamp, priority, payload, metadata, checkpoint_marker [SOC2 CC7, ISO 27001 A.12]

## 4. Security, Encryption, and Audit
- **Encryption:** AES-GCM for all data at rest, field-level encryption for sensitive fields. Key rotation is automated and logged. [SOC2 CC6, ISO 27001 A.10, GDPR Art.32]
- **Audit Trails:** All access, changes, and queries are logged immutably. [SOC2 CC7, ISO 27001 A.12, GDPR Art.30]
- **Key Management:** Automated rotation, backup, and restore. All key events are logged and auditable. [SOC2 CC6, ISO 27001 A.10]
- **Access Control:** RBAC/ABAC enforced for all operations. [SOC2 CC6, ISO 27001 A.9]

## 5. Operational Flows
### 5.1 Data Ingestion
- All data is validated, encrypted, and audit-logged on write.
- Sharding and indexing are applied automatically.
- Compliance checks (retention, residency) are enforced at ingestion.

### 5.2 Backup & Restore
- Automated, scheduled, cross-region, encrypted backups.
- Restore operations are versioned, validated, and audit-logged.
- DR drills are performed quarterly, with evidence retained for audit.

### 5.3 Audit & Evidence Generation
- All access, backup, restore, and schema changes are logged, versioned, and exportable for audit and regulatory review.
- Evidence is generated for every compliance requirement (SOC2, ISO 27001, GDPR).

## 6. Testing & Validation Requirements
- All schema changes and migrations must be tested in staging before production.
- Automated tests for data integrity, encryption, access control, and audit logging.
- Quarterly DR drills and restore validation.
- Evidence of all tests and validations is retained for audit.

## 7. Evidence for Audits & Regulatory Reviews
- Immutable, versioned logs for all data operations.
- Backup/restore event logs, access logs, and schema change history.
- Exportable evidence packages for SOC2, ISO 27001, GDPR, and enterprise audits.

## 8. See Also
- [Backups](./backups.md)
- [Storage-Manager Module](../../modules/storage-manager-l6.txt)
- [Common Module](../../modules/common-l1.txt)