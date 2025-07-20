# Prelude Module

## Overview
The Prelude module provides a type-safe, controlled global interface for the ForgeOne platform. It re-exports commonly used types and functions from various modules for easy access, allowing developers to import a single module instead of multiple individual ones.

## Key Features
- Centralized imports for common types and functions
- Simplified initialization and diagnostics
- Helper functions for common operations
- Cryptographic utility functions
- Audit and telemetry helpers

## Core Components

### Re-exported Types
The Prelude module re-exports the following types:

#### Error Types
- `ForgeError` - The main error type for ForgeOne
- `Result<T>` - A type alias for `std::result::Result<T, ForgeError>`
- `TraceableError` - An error with tracing information

#### Identity Types
- `IdentityContext` - Context for identity operations
- `TrustVector` - Trust vector for identity context

#### Policy Types
- `PolicyEffect` - Effect of a policy evaluation
- `PolicyRule` - A rule in a policy
- `PolicySet` - A set of policy rules

#### Trust Types
- `ZtaNode` - A node in the Zero Trust Architecture graph
- `ZtaPolicyGraph` - A graph of ZTA nodes

#### Telemetry Types
- `TelemetrySpan` - A span for telemetry
- `TelemetryEvent` - An event for telemetry

#### Observer Types
- `Observation` - An observation for the system
- `ObservationType` - Type of observation
- `ObservationSeverity` - Severity of observation

#### Diagnostics Types
- `DiagnosticReport` - A report of system diagnostics
- `DiagnosticError` - An error during diagnostics

#### Audit Types
- `AuditEvent` - An audit event
- `AuditOutcome` - Outcome of an audit event
- `AuditLog` - A log of audit events
- `AuditCategory` - Category of an audit event
- `AuditSeverity` - Severity of an audit event

#### Config Types
- `ForgeConfig` - Configuration for ForgeOne
- `SignedConfig` - A signed configuration

### Re-exported Macros
- `autolog!` - Log with identity context
- `trace_id!` - Generate a trace ID
- `enforce_zta!` - Enforce a Zero Trust policy
- `telemetry_span!` - Create a telemetry span
- `audit_event!` - Create an audit event
- `observe!` - Create an observation

### Helper Functions

#### Initialization
- `initialize()` - Initialize the common crate with default configuration
- `initialize_with_config(config_path)` - Initialize with custom configuration

#### Diagnostics
- `run_diagnostics(identity)` - Run diagnostics on the system
- `check_health()` - Check the health of the system

#### Telemetry
- `generate_trace_id()` - Generate a new trace ID
- `explain_for_agent(identity, outcome)` - Explain a result for an agent
- `explain_span_for_agent(span)` - Explain a telemetry span for an agent

#### Audit
- `create_audit_event(...)` - Create a new audit event
- `verify_event_signature(event, public_key)` - Verify the signature of an audit event

#### Cryptography
- `generate_key_pair()` - Generate a new key pair
- `sign(data, private_key)` - Sign data with a private key
- `verify(data, signature, public_key)` - Verify a signature
- `generate_device_fingerprint()` - Generate a device fingerprint
- `generate_token(length)` - Generate a secure random token
- `hash_sha256(data)` - Hash data with SHA-256

## Usage Example
```rust
use common::prelude::*;

// Initialize the common crate
initialize()?;

// Create an identity context
let identity = IdentityContext::new("user123");

// Generate a trace ID
let trace_id = generate_trace_id();

// Create a policy set
let mut policy_set = PolicySet::new("default", "1.0");
policy_set.add_rule(PolicyRule::new("admin", "read", "document/*", PolicyEffect::Allow));

// Enforce a policy
let result = enforce_zta!(&identity, "read", "document/123", &policy_set);

// Create an audit event
let event = create_audit_event(
    identity.clone(),
    "read".to_string(),
    "document/123".to_string(),
    AuditOutcome::Success,
    AuditCategory::DataAccess,
    AuditSeverity::Info,
    None,
);

// Check system health
let is_healthy = check_health().await;
```

## Related Modules
- [Error](./error.md)
- [Identity](./identity.md)
- [Policy](./policy.md)
- [Trust](./trust.md)
- [Telemetry](./telemetry.md)
- [Observer](./observer.md)
- [Diagnostics](./diagnostics.md)
- [Audit](./audit.md)
- [Config](./config.md)
- [Crypto](./crypto.md)