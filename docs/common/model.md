# Common Data Models

## Overview
The Model module provides common data models for the ForgeOne microkernel, establishing the core data structures used throughout the system.

## Key Features
- Identity and trust representation
- System call recording and monitoring
- Execution tracing and lineage
- Standardized data structures

## Core Components

### TrustVector
Represents the trust level of an identity:
- `Trusted` - Fully trusted identity
- `Partial` - Partially trusted identity
- `Untrusted` - Untrusted identity
- `Compromised` - Compromised identity

### IdentityContext
Identity context for execution:
- `user_id` - Unique identifier for the user
- `container_id` - Container ID
- `trust_vector` - Trust vector for the identity
- `roles` - Roles assigned to the identity
- `attributes` - Additional attributes for the identity

Helper methods:
- `new()` - Create a new identity context
- `with_trust_vector()` - Set the trust vector for this identity
- `with_role()` - Add a role to this identity
- `with_attribute()` - Add an attribute to this identity

### SyscallRecord
Record of a syscall execution:
- `name` - Name of the syscall
- `args` - Arguments passed to the syscall
- `allowed` - Whether the syscall was allowed
- `timestamp` - Timestamp of the syscall

### ExecutionDNA
DNA-style container trace log:
- `container_id` - Container ID
- `trace_id` - Trace ID
- `identity_context` - Identity context for this execution

## Usage Example
```rust
// Create a new identity context
let identity = IdentityContext::new("user123")
    .with_trust_vector(TrustVector::Trusted)
    .with_role("admin")
    .with_attribute("department", "engineering");

// Record a syscall
let syscall = SyscallRecord::new(
    "open",
    &["/etc/passwd", "r"],
    false
);
```

## Related Modules
- [Identity](./identity.md)
- [Trust](./trust.md)
- [Audit](./audit.md)