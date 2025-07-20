# Syscall Engine

## Overview

The Syscall Engine module (`syscall_engine/mod.rs`) implements the `SyscallAPI` trait for actual secure syscall execution in the ForgeOne microkernel system. It provides the core functionality for executing syscalls with security checks, RBAC enforcement, and audit logging.

## Purpose

The primary purpose of the Syscall Engine is to:

1. **Implement Syscall Logic**: Provide the actual implementation of syscall operations.
2. **Enforce Security Policies**: Apply security checks and RBAC enforcement to all syscall operations.
3. **Audit Syscall Operations**: Log all syscall operations for security auditing and debugging purposes.
4. **Integrate with ZTA**: Work with the Zero Trust Architecture (ZTA) policy graph to determine if syscalls should be allowed.

## Components

### SyscallEngine Struct

The `SyscallEngine` struct implements the `SyscallAPI` trait with actual syscall logic. It includes methods for various syscall operations, such as:

- `mount_volume`: Mount a volume with the given name, with security checks and audit logging.
- `ns_enter`: Enter a namespace with the given process ID, with security checks and audit logging.
- `audit_syscall`: Log a syscall operation for auditing purposes.

### Helper Functions

The Syscall Engine also includes helper functions for security checks and audit logging:

- `get_identity_context`: Get the identity context for the current process.
- `check_policy`: Check if a syscall operation is allowed by the ZTA policy graph.
- `log_syscall`: Log a syscall operation for auditing purposes.

## Usage

### In Microkernel Code

```rust
use crate::syscall_engine::SyscallEngine;
use common::syscall_client::SyscallAPI;

fn perform_operation() -> Result<(), Error> {
    let syscall = SyscallEngine::new();
    syscall.mount_volume("data")?;
    Ok(())
}
```

### In Syscall Bridge

The Syscall Engine is used by the Syscall Bridge to provide the actual implementation of syscall operations when the `microkernel` feature is enabled:

```rust
#[cfg(feature = "microkernel")]
pub use microkernel::syscall_engine::SyscallEngine as ActiveSyscall;
```

## Security Considerations

The Syscall Engine is designed with security in mind:

- **Security Checks**: All syscall operations include security checks to ensure they are allowed.
- **RBAC Enforcement**: Role-based access control is applied to all syscall operations.
- **Audit Logging**: All syscall operations are logged for security auditing and debugging purposes.
- **ZTA Integration**: The Syscall Engine integrates with the Zero Trust Architecture (ZTA) policy graph to determine if syscalls should be allowed.

## Implementation Details

The Syscall Engine consists of a single module (`mod.rs`) that defines:

- The `SyscallEngine` struct, which implements the `SyscallAPI` trait with actual syscall logic.
- Helper functions for security checks and audit logging.

## Related Documentation

- [Syscall Architecture](../../docs/syscall_architecture.md): Overview of the syscall architecture.
- [Syscall Execution Flow](../../docs/syscall_execution_flow.md): Detailed description of the syscall execution flow.
- [Microkernel Architecture](../../docs/microkernel_architecture.svg): Visual representation of the microkernel architecture.