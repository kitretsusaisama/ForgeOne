# Syscall Bridge

## Overview

The Syscall Bridge module provides a compile-time bridge between the common crate and the microkernel. It allows for feature-gated syscall operations without direct dependency on the microkernel, enforcing a hard boundary between these components.

## Purpose

The primary purpose of the Syscall Bridge is to:

1. **Enforce Hard Boundaries**: Create a clear separation between the common crate and the microkernel.
2. **Enable Compile-Time Dispatch**: Use feature flags to determine which syscall implementation to use at compile time.
3. **Provide a Unified Interface**: Ensure that all code interacts with syscalls through a consistent API.
4. **Support Testing**: Allow for easy mocking of syscalls in test environments.

## Architecture

The Syscall Bridge uses Rust's feature flags to determine which implementation of the `SyscallAPI` trait to use:

- When the `microkernel` feature is enabled, it uses the actual `SyscallEngine` implementation from the microkernel.
- When the `microkernel` feature is disabled, it uses a `MockSyscall` implementation that provides no-op stubs for all syscall methods.

## Usage

### In Production Code

```rust
use syscall_bridge::ActiveSyscall;

fn perform_operation() -> Result<(), Error> {
    let syscall = ActiveSyscall::new();
    syscall.mount_volume("data")?;
    Ok(())
}
```

### In Test Code

When testing, you can disable the `microkernel` feature to use the `MockSyscall` implementation:

```rust
// Cargo.toml
[dev-dependencies]
syscall-bridge = { path = "../syscall-bridge", default-features = false }
```

```rust
// In your test code
use syscall_bridge::ActiveSyscall;

#[test]
fn test_operation() {
    let syscall = ActiveSyscall::new();
    assert!(syscall.mount_volume("test").is_ok());
}
```

## Security Considerations

The Syscall Bridge is designed with security in mind:

- **Compile-Time Enforcement**: The hard boundary between the common crate and the microkernel is enforced at compile time, preventing accidental dependencies.
- **No Runtime IPC**: The architecture avoids the overhead and complexity of runtime IPC mechanisms like sockets.
- **Audit Logging**: All syscall operations are logged for security auditing and debugging purposes.

## Implementation Details

The Syscall Bridge consists of a single module (`mod.rs`) that defines:

- The `ActiveSyscall` type alias, which resolves to either `SyscallEngine` or `MockSyscall` based on feature flags.
- The `MockSyscall` struct and its implementation of the `SyscallAPI` trait, providing no-op stubs for all syscall methods.

## Related Documentation

- [Syscall Architecture](../docs/syscall_architecture.md): Overview of the syscall architecture.
- [Syscall Execution Flow](../docs/syscall_execution_flow.md): Detailed description of the syscall execution flow.
- [Microkernel Architecture](../docs/microkernel_architecture.svg): Visual representation of the microkernel architecture.