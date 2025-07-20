# Identity Management System

## Overview
The Identity module provides identity context and trust vectors for the ForgeOne platform. It handles tenant, user, agent, and device lineage tracking.

## Key Features
- Identity context for requests and operations
- Trust vectors for security classification
- Tenant and user identification
- Agent and device tracking
- Cryptographic attestation

## Core Components

### TrustVector
Represents the trust level of an identity:
- `Root` - Root level trust (system level)
- `Signed` - Cryptographically signed trust with signature
- `Enclave` - Secure enclave trust
- `EdgeGateway` - Edge gateway trust
- `Unverified` - Unverified trust (default)
- `Compromised` - Compromised trust (known bad)

### IdentityContext
Identity context for a request or operation:
- `request_id` - The unique ID for this request
- `session_id` - The session ID for this request
- `tenant_id` - The tenant ID for this request
- `user_id` - The user ID for this request
- `agent_id` - The agent ID for this request (LLM, runtime, CLI, API)
- `device_fingerprint` - The device fingerprint for this request
- `geo_ip` - The geo IP for this request
- `trust_vector` - The trust vector for this request
- `cryptographic_attestation` - Cryptographic attestation for this request

## Helper Methods
- `new()` - Create a new identity context with default values
- `root()` - Create a new root identity context
- `with_agent()` - Set the agent ID for this identity
- `with_device()` - Set the device fingerprint for this identity
- `with_geo_ip()` - Set the geo IP for this identity
- `with_trust()` - Set the trust vector for this identity

## Usage Example
```rust
// Create a new identity context
let identity = IdentityContext::new("tenant123".to_string(), "user456".to_string());

// Create a root identity context
let root_identity = IdentityContext::root();

// Create an identity with additional information
let enhanced_identity = IdentityContext::new("tenant123".to_string(), "user456".to_string())
    .with_agent("cli".to_string())
    .with_device("laptop-abc123".to_string())
    .with_geo_ip("192.168.1.1".to_string())
    .with_trust(TrustVector::Signed("signature123".to_string()));
```

## Related Modules
- [Trust](./trust.md)
- [Policy](./policy.md)
- [Audit](./audit.md)
- [Crypto](./crypto.md)