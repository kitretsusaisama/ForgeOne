# Syscall Client

## Overview

The Syscall Client module (`syscall_client.rs`) defines the interface for syscall operations in the ForgeOne microkernel system. It provides a trait (`SyscallAPI`) that abstracts syscall operations and a client implementation (`SyscallClient`) that forwards syscall requests to the appropriate backend based on compile-time feature flags.

## Purpose

The primary purpose of the Syscall Client is to:

1. **Define the Syscall Interface**: Provide a clear and consistent interface for all syscall operations.
2. **Abstract Implementation Details**: Hide the details of how syscalls are executed from client code.
3. **Enable Feature-Gated Behavior**: Allow for different implementations based on compile-time feature flags.
4. **Support Testing**: Facilitate testing by allowing for easy mocking of syscall operations.

## Components

### SyscallAPI Trait

The `SyscallAPI` trait defines the interface for syscall operations. It includes methods for various syscall operations, such as:

- `mount_volume`: Mount a volume with the given name.
- `ns_enter`: Enter a namespace with the given process ID.
- `audit_syscall`: Log a syscall operation for auditing purposes.

### SyscallClient Struct

The `SyscallClient` struct provides a client implementation of the `SyscallAPI` trait. It forwards syscall requests to the appropriate backend based on compile-time feature flags:

- When the `microkernel` feature is enabled, it forwards requests to the actual microkernel implementation.
- When the `microkernel` feature is disabled, it provides no-op stubs for all syscall methods.

## Usage

### In Application Code

```rust
use common::syscall_client::{SyscallAPI, SyscallClient};

fn perform_operation() -> Result<(), Error> {
    let syscall = SyscallClient::new();
    syscall.mount_volume("data")?;
    Ok(())
}
```

### In Library Code

When writing library code that needs to perform syscalls, you should accept any type that implements the `SyscallAPI` trait:

```rust
use common::syscall_client::SyscallAPI;

fn perform_operation<S: SyscallAPI>(syscall: &S) -> Result<(), Error> {
    syscall.mount_volume("data")?;
    Ok(())
}
```

## Security Considerations

The Syscall Client is designed with security in mind:

- **No Implementation Logic**: The `SyscallAPI` trait defines only the interface, with no implementation logic.
- **Compile-Time Dispatch**: The `SyscallClient` uses compile-time feature flags to determine which implementation to use.
- **Audit Logging**: All syscall operations can be logged for security auditing and debugging purposes.

## Implementation Details

The Syscall Client consists of a single module (`syscall_client.rs`) that defines:

- The `SyscallAPI` trait, which defines the interface for syscall operations.
- The `SyscallClient` struct, which provides a client implementation of the `SyscallAPI` trait.

## Related Documentation

- [Syscall Architecture](../docs/syscall_architecture.md): Overview of the syscall architecture.
- [Syscall Execution Flow](../docs/syscall_execution_flow.md): Detailed description of the syscall execution flow.
- [Microkernel Architecture](../docs/microkernel_architecture.svg): Visual representation of the microkernel architecture.