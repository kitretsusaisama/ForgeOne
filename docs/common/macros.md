# Macros Module

## Overview
The Macros module provides a collection of utility macros for the ForgeOne platform, simplifying common operations and enforcing consistent patterns across the codebase.

## Key Features
- Identity-aware logging macros
- Trace ID generation
- Zero Trust policy enforcement
- Telemetry span creation
- Audit event generation
- Observation creation

## Core Components

### `autolog!`
A macro for logging messages with the current identity context:
```rust
autolog!(level, identity, message...)
```

This macro automatically includes identity information in log messages:
- User ID
- Tenant ID
- Request ID
- Trust vector

### `trace_id!`
A macro for generating a new trace ID:
```rust
let id = trace_id!();
```

Generates a UUID v4 for tracing purposes.

### `enforce_zta!`
A macro for enforcing Zero Trust policies:
```rust
enforce_zta!(identity, action, resource, policy)
```

Evaluates a policy against an identity, action, and resource, returning:
- `Ok(())` if allowed
- `Err(ForgeError::PolicyViolation)` if denied or requires escalation

### `telemetry_span!`
A macro for creating a new telemetry span:
```rust
let span = telemetry_span!(name, identity);
```

Creates a new telemetry span with the given name and identity context.

### `audit_event!`
A macro for creating a new audit event:
```rust
let event = audit_event!(identity, action, resource, outcome);
let event_with_details = audit_event!(identity, action, resource, outcome, details);
```

Creates a new audit event with the given parameters.

### `observe!`
A macro for creating a new observation:
```rust
let observation = observe!(identity, type, content, severity);
```

Creates a new observation with the given parameters.

## Usage Example
```rust
// Log a message with identity context
autolog!(tracing::Level::INFO, identity_context, "Processing request {}", request_id);

// Generate a trace ID
let trace_id = trace_id!();

// Enforce a Zero Trust policy
let result = enforce_zta!(identity_context, "read", "document/123", policy_set);

// Create a telemetry span
let span = telemetry_span!("process_request", identity_context);

// Create an audit event
let event = audit_event!(identity_context, "read", "document/123", AuditOutcome::Success);

// Create an observation
let observation = observe!(identity_context, ObservationType::Info, "Request processed", ObservationSeverity::Info);
```

## Related Modules
- [Identity](./identity.md)
- [Policy](./policy.md)
- [Audit](./audit.md)
- [Telemetry](./telemetry.md)
- [Observer](./observer.md)