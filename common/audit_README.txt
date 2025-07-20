============================
ForgeOne Advanced Audit System
============================

Features Implemented
--------------------
- Tamper-evident, chain-linked audit events (blockchain-style)
- Asynchronous, non-blocking logging (background thread)
- Pluggable, multi-sink architecture (runtime hot-add/remove)
- Real-time streaming sink stubs (webhook, message queue, gRPC)
- Dynamic, policy-driven filtering and redaction (per-tenant, runtime updates)
- Advanced query and forensics API (multi-format export, indexed search)
- Cryptographic proof-of-integrity and attestation (segment signing, chain verification)
- High-availability and fault-tolerance (replication, failover, recovery)
- Prometheus metrics and health monitoring (event rates, sink health, queue sizes, errors)
- Comprehensive, automated testing (property-based, fuzzing, chaos, concurrency)

How to Use in Other Modules
--------------------------
1. **Add as a dependency:**
   - In your module's `Cargo.toml`, add:
     ```toml
     [dependencies]
     common = { path = "../common" }
     ```
2. **Import the audit module:**
   ```rust
   use common::audit::*;
   ```
3. **Initialize and configure:**
   - Create an `AuditManager` or `DynamicAuditManager` as needed.
   - Add sinks (file, memory, DB, streaming, replicated, WAL, etc.).
   - Optionally enable async logging, HA, or metrics.

Example Usage
-------------

// --- Logging an event ---
let identity = IdentityContext::new("tenant1".to_string(), "user1".to_string());
let event = create_audit_event(
    identity,
    "ContainerStarted".to_string(),
    "container123".to_string(),
    AuditOutcome::Success,
    AuditCategory::System,
    AuditSeverity::Info,
    None
);
manager.log(event)?;

// --- Async logging ---
manager.enable_async_logging();
manager.log_async(event);

// --- Add a sink at runtime ---
manager.add_sink_dyn(Box::new(FileAuditSink::new("/var/log/audit.log", false, None)?));

// --- Per-tenant policy and redaction ---
let mut policy = ExtendedAuditPolicy::default();
policy.redaction.insert("user_id".to_string(), RedactionRule::Mask("MASKED".to_string()));
dyn_manager.set_policy("tenant1".to_string(), policy);

// --- Query and export ---
let query = AuditQuery { tenant_id: Some("tenant1".to_string()), ..Default::default() };
let results = query.query_events(&events);
let json = export_events_json(&results)?;

// --- Chain integrity and attestation ---
let ok = verify_chain_integrity(&events)?;

// --- High-availability (replication, WAL) ---
let rep_sink = ReplicatedAuditSink { sinks: vec![...], max_retries: 3, retry_delay: Duration::from_millis(10) };
manager.add_sink_dyn(Box::new(rep_sink));
let wal_sink = WriteAheadLogAuditSink { path: "/var/log/audit.wal".to_string(), inner: Box::new(FileAuditSink::new(...)?)};
manager.add_sink_dyn(Box::new(wal_sink));

// --- Metrics and health ---
let metrics = AuditMetrics::default();
metrics.inc_event();
let prom = metrics.export_prometheus();

// --- Testing ---
// See audit_tests.rs for property-based, fuzzing, chaos, and concurrency tests.

Notes
-----
- All sinks, policies, and managers are thread-safe.
- Extend with your own sinks or policies as needed.
- For advanced use (network replication, DB-backed queries), see stubs and TODOs in the code. 