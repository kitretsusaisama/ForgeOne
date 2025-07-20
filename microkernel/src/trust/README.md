# Trust Module for ForgeOne Microkernel

## Overview

The Trust module is the central security component of the ForgeOne Microkernel, implementing a Zero Trust Architecture (ZTA) for secure execution. It provides policy evaluation, syscall enforcement, and quarantine mechanisms for compromised processes.

Key features include:

- **Dynamic Policy Graphs**: Flexible policy definitions with versioning and inheritance
- **Context-Aware Decisions**: Trust decisions based on identity, behavior, and environment
- **Adaptive Trust Vectors**: Dynamic trust scoring with multiple factors
- **Policy Versioning**: Support for policy evolution and migration
- **Per-Syscall Enforcement**: Fine-grained control over system calls
- **Argument Validation**: Deep inspection of syscall arguments
- **Comprehensive Tracing**: Detailed logging of policy decisions
- **Policy Violation Handling**: Configurable responses to violations
- **Quarantine Mechanisms**: Isolation of compromised processes

## Components

### ZTA Policy Module (`zta_policy.rs`)

Defines the policy graph structure and evaluation logic for Zero Trust Architecture:

- `ZtaPolicyGraph`: Core policy graph with policies, trust thresholds, and identity rules
- `SyscallPolicy`: Defines allowed/denied syscalls with constraints
- `IdentityRule`: Rules for identity-based access control
- `PolicyEvaluationResult`: Result of policy evaluation

### Syscall Enforcer Module (`syscall_enforcer.rs`)

Enforces ZTA policies on syscalls:

- `SyscallEnforcer`: Enforces policies on syscalls
- `EnforcementMode`: Modes of enforcement (Enforce, Audit, Permissive)
- `ViolationAction`: Actions for policy violations (Block, Quarantine, Warn, Allow)
- `ViolationHandler`: Handles policy violations
- `SyscallTrace`: Records syscall execution details

### Redzone Module (`redzone.rs`)

Provides quarantine mechanisms for compromised processes:

- `Redzone`: Manages quarantined processes
- `QuarantinedProcess`: Represents a quarantined process
- `IsolationLevel`: Levels of isolation (Full, Network, Filesystem, Custom)
- `ForensicMode`: Modes of forensic data collection (None, Metadata, Full)
- `QuarantineStatus`: Status of quarantined processes (Active, Analyzing, Terminated, Recovered)

### Attestation Module (`attestation.rs`)

Provides cryptographic attestation mechanisms:

- `AttestationManager`: Manages attestation claims and verification
- `AttestationClaim`: Represents an attestation claim
- `AttestationResult`: Result of attestation verification
- `AttestationType`: Types of attestation (Local, Remote, Hardware, Custom)
- `AttestationStatus`: Status of attestation (Pending, Valid, Invalid, Expired)

### Trust Evaluation Module (`evaluation.rs`)

Evaluates trust based on identity, attestation, and policy:

- `TrustEvaluator`: Evaluates trust for contexts
- `TrustEvaluationContext`: Context for trust evaluation
- `TrustEvaluationResult`: Result of trust evaluation
- `TrustScoreComponents`: Components of trust score

## Usage

### Initializing the Trust Module

```rust
use microkernel::trust;

// Initialize the trust module
trust::init().expect("Failed to initialize trust module");
```

### Evaluating a Syscall

```rust
use microkernel::trust;
use common::identity::IdentityContext;

// Create an identity context
let identity = IdentityContext::system();

// Evaluate a syscall
let action = trust::evaluate_syscall(
    "read_file",
    &["config.txt".to_string()],
    identity,
).expect("Failed to evaluate syscall");

// Handle the action
match action {
    trust::ViolationAction::Block => {
        println!("Syscall blocked by ZTA policy");
    },
    trust::ViolationAction::Quarantine => {
        println!("Process quarantined due to ZTA policy violation");
    },
    trust::ViolationAction::Warn => {
        println!("ZTA policy warning for syscall");
    },
    trust::ViolationAction::Allow => {
        println!("Syscall allowed by ZTA policy");
    },
}
```

### Quarantining a Process

```rust
use microkernel::trust;
use common::identity::IdentityContext;
use uuid::Uuid;

// Create an identity context
let identity = IdentityContext::system();

// Create a syscall trace
let syscall_trace = trust::SyscallTrace {
    id: Uuid::new_v4(),
    syscall_name: "read_file".to_string(),
    args: vec!["sensitive.txt".to_string()],
    timestamp: chrono::Utc::now(),
    identity: identity.clone(),
    result: "DENIED".to_string(),
};

// Quarantine the process
let container_id = Uuid::new_v4(); // Get from execution context
let process_id = trust::quarantine_process(
    container_id,
    identity,
    "Unauthorized access attempt",
    vec![syscall_trace],
).expect("Failed to quarantine process");

println!("Process quarantined: {}", process_id);
```

### Verifying Attestation

```rust
use microkernel::trust;
use microkernel::trust::attestation;
use common::identity::IdentityContext;
use common::identity::TrustVector;
use std::collections::HashMap;

// Create an identity context
let identity = IdentityContext::system();

// Register an attestation claim
let claim_id = attestation::register_claim(
    attestation::AttestationType::Local,
    identity,
    TrustVector::Signed,
    HashMap::new(),
    None,
).expect("Failed to register attestation claim");

// Verify the attestation claim
let result = trust::verify_attestation(claim_id)
    .expect("Failed to verify attestation");

println!("Attestation verified: {:?}", result.status);
```

### Evaluating Trust

```rust
use microkernel::trust;
use microkernel::trust::evaluation;
use common::identity::IdentityContext;
use std::collections::HashMap;

// Create an identity context
let identity = IdentityContext::system();

// Create an evaluation context
let context_id = evaluation::create_context(
    identity,
    Vec::new(),
    HashMap::new(),
).expect("Failed to create evaluation context");

// Evaluate trust
let result = trust::evaluate_trust(context_id)
    .expect("Failed to evaluate trust");

println!("Trust score: {}", result.trust_score);
println!("Trust vector: {:?}", result.recommended_trust_vector);
```

## Integration with Other Modules

The Trust module integrates with several other modules in the ForgeOne Microkernel:

- **Core Module**: Provides secure boot and identity verification
- **Execution Module**: Enforces ZTA policies on syscalls and container execution
- **Observer Module**: Records policy decisions and violations for auditing
- **Crypto Module**: Provides cryptographic attestation mechanisms
- **Common Identity Module**: Defines identity context and trust vectors
- **Common Trust Module**: Provides the base ZTA policy graph implementation

## Testing

The Trust module includes comprehensive tests in `microkernel/tests/trust_tests.rs`.

## License

This module is part of the ForgeOne Microkernel and is licensed under the same terms as the rest of the project.