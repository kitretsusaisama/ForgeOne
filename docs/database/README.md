# ForgeOne Database (Atomic Storage-Manager, DMCOA, Redb)

*This document details the ForgeOne database architecture and operations for MNC-grade, production-ready, and compliance-driven deployments. All features and processes are mapped to SOC2, ISO 27001, GDPR, and enterprise SLAs.*

## 1. Atomic Module Mapping
- **Storage Manager:** [modules/storage-manager-l6.txt]
- **Common Types/Config:** [modules/common-l1.txt]

## 2. Responsibilities & Operational Guarantees
- **Redb:** Hyper-compressed, ACID-compliant, sharded key-value store for logs, blobs, events, and snapshots. All data is encrypted at rest (AES-GCM), with key rotation and field-level encryption.
- **Vault:** Encrypted secrets and config storage, with audit logging and automated key management.
- **Backups:** Automated, scheduled, cross-region, encrypted (AES-GCM, Zstd), with DR drills and restore validation. Immutable, auditable backup logs.
- **Compliance:** SOC2, ISO 27001, GDPR, CIS Benchmarks. All changes and access are logged, signed, and auditable. Evidence is generated for every backup, restore, and schema change.
- **Data Residency & Retention:** Data is stored in compliance with regional requirements. Retention policies are enforced and auditable.
- **Audit Evidence:** Immutable logs, backup/restore events, access logs, and schema change history are available for audit and regulatory review.

## 3. Storage Features & Compliance Implications
- **Sharding:** Horizontal scaling, up to 16 shards per type. Enables data isolation and compliance with data residency.
- **Encryption:** AES-GCM, key rotation, field-level encryption. All access is logged and auditable.
- **Compression:** Zstd, deduplication (BLAKE3). Reduces storage cost and supports compliance with data minimization.
- **Snapshots:** Fast, atomic, DNA-hash validated. All snapshot events are logged for audit.
- **Audit:** All changes tracked, immutable logs, evidence for SOC2/ISO 27001/GDPR.
- **Disaster Recovery:** Cross-region replication, automated DR drills, and restore validation. All DR events are logged and auditable.

## 4. Data Residency, Retention, and Audit Evidence
- **Residency:** Data is stored in specified regions to comply with GDPR and enterprise requirements.
- **Retention:** Configurable retention policies for all data types. Automated enforcement and audit logging.
- **Audit Evidence:** All access, backup, restore, and schema changes are logged, versioned, and exportable for audit.

## 5. Production Best Practices
- Enforce encryption at rest and in transit for all data.
- Schedule regular, automated backups and DR drills. Validate restores.
- Monitor and audit all access, backup, and schema change events.
- Test all schema changes and migrations in staging before production.
- Review and update retention and residency policies quarterly or after regulatory changes.
- Integrate with SIEM/SOC for real-time monitoring and compliance reporting.

## 6. Key Docs
- [Backups](./backups.md)
- [Schema](./schema.md)
- [Storage-Manager Module](../../modules/storage-manager-l6.txt)
- [Common Module](../../modules/common-l1.txt) 