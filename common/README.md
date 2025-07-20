# ForgeOne `common` Crate

## Conscious Substrate (10^17x Class)

*Designed for AI. Hardened by Zero Trust. Forged for Superintelligence.*

## Overview

This crate is the sentient core of ForgeOne, providing a trust-aware, AI-augmented, self-adaptive foundation for enterprise container intelligence.

Every function, type, and trace is:

* **Contextual** (aware of who, where, why)
* **Causal** (tracks origin, intent, and policy path)
* **Comprehensible** (LLM-readable, developer-debuggable, auditor-verifiable)
* **Cryptographic** (provable, signed, and tamper-evident)

## Features

- 🧠 **LLM-Traceable Observer**: Converts any runtime event into a prompt-summarized feedback string
- 🔐 **Cryptographic Provenance**: Every config or identity can be signed and verified
- 📜 **ZTA Policy Graph Engine**: DSL + Runtime + Trust Vector Interop
- 🧪 **Self-Diagnostics**: AI-readable status checks
- 🔁 **Telemetry Context Surface**: Logs, traces, metrics flow into agents or platforms
- ⚙️ **Zero-Bloat Boot**: Sub-1ms init time
- 🧬 **Immutable Context**: Every input is immutable + trace-locked

## Module Structure

```
common/
├── src/
│   ├── lib.rs                 # Atomic prelude
│   ├── bootstrap.rs           # L1 trust-aware boot
│   ├── config.rs              # Multi-layer config + attestation
│   ├── error.rs               # Diagnostic + audit-traceable errors
│   ├── identity.rs            # Tenant, user, agent, device lineage
│   ├── trust.rs               # Zero Trust Policy + graph engine
│   ├── policy.rs              # DSL + runtime policy matcher
│   ├── telemetry.rs           # Trace ID + span correlation + metrics
│   ├── observer.rs            # LLM-explainable trace summaries
│   ├── diagnostics.rs         # Runtime self-verification engine
│   ├── audit.rs               # Immutable audit stream signer
│   ├── crypto.rs              # Signature, fingerprint, entropy sealing
│   ├── macros.rs              # autolog!, trace_id!, enforce_zta!
│   └── prelude.rs             # Type-safe, controlled global interface
└── tests/
    └── consciousness.rs       # Self-diagnosing AI/trace-based test logic
```

## Usage

### Initialization

```rust
use common::prelude::*;

// Initialize with default configuration
init()?;

// Or initialize with custom configuration
init_with_config("config.yaml")?;
```

### Identity Context

```rust
let identity = IdentityContext::new("tenant-id".to_string(), "user-id".to_string())
    .with_agent("agent-id".to_string())
    .with_device("device-fingerprint".to_string())
    .with_geo_ip("127.0.0.1".to_string())
    .with_trust(TrustVector::Unverified);
```

### Policy Evaluation

```rust
let mut policy_set = PolicySet::new("my-policy".to_string(), "1.0".to_string());

policy_set.add_rule(PolicyRule {
    role: "user-id".to_string(),
    action: "read".to_string(),
    resource: "resource-id".to_string(),
    effect: PolicyEffect::Allow,
});

let effect = policy_set.evaluate(&identity, "read", "resource-id");
```

### Telemetry

```rust
let mut span = TelemetrySpan::new("operation-name".to_string(), identity.clone());

span.add_attribute("key".to_string(), "value".to_string());
span.log_info("Operation started");

// Perform operation

span.log_info("Operation completed");
span.end();
```

### Audit

```rust
let event = create_audit_event(
    identity.clone(),
    "read".to_string(),
    "resource-id".to_string(),
    AuditOutcome::Success,
    Some(serde_json::json!({"details": "value"})),
);

let mut audit_log = AuditLog::new()
    .with_file("audit.log")?;

audit_log.log_event(event)?;
```

### Cryptography

```rust
let key_pair = generate_key_pair()?;

let data = b"data to sign";
let signature = sign(data, &key_pair.private_key)?;

let verified = verify(data, &signature, &key_pair.public_key)?;
assert!(verified);
```

### Diagnostics

```rust
let report = run_diagnostics(&identity);
println!("{}", report.to_llm_string());
```

## License

Proprietary - ForgeOne Enterprise Container Platform