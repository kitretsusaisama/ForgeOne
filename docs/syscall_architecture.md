# Hard-Boundary Syscall Architecture

## Overview

This document describes the hard-boundary syscall architecture implemented in the ForgeOne microkernel system. The architecture provides a secure, modular, and efficient way to handle syscalls across module boundaries without using sockets or other heavy IPC mechanisms.

## Architecture Diagram

```
┌───────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                        Application Layer                              │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                          Common Crate                                 │
│                                                                       │
│  ┌─────────────────────┐      ┌─────────────────────────────────┐    │
│  │                     │      │                                 │    │
│  │  SyscallAPI Trait   │◄─────┤      SyscallClient             │    │
│  │  (syscall_client.rs)│      │      (syscall_client.rs)       │    │
│  │                     │      │                                 │    │
│  └─────────────────────┘      └─────────────────────────────────┘    │
│                                              │                       │
└──────────────────────────────────────────────┼───────────────────────┘
                                               │
                                               ▼
┌───────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                        Syscall Bridge                                 │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐      │
│  │                                                             │      │
│  │                      ActiveSyscall                          │      │
│  │                                                             │      │
│  └─────────────────────────────────────────────────────────────┘      │
│                                │                                      │
└────────────────────────────────┼──────────────────────────────────────┘
                                 │
                                 ▼
┌───────────────────────────────────────────────────────────────────────┐
│                                                                       │
│                        Microkernel                                    │
│                                                                       │
│  ┌─────────────────────┐      ┌─────────────────────────────────┐    │
│  │                     │      │                                 │    │
│  │  SyscallEngine     │◄─────┤      secure_syscall()           │    │
│  │  (syscall_engine.rs)│      │      (execution/syscall.rs)    │    │
│  │                     │      │                                 │    │
│  └─────────────────────┘      └─────────────────────────────────┘    │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

## Component Descriptions

### Common Crate

- **SyscallAPI Trait**: Defines the interface for syscall operations without any implementation logic.
- **SyscallClient**: Provides a client implementation that forwards syscall requests to the appropriate backend based on compile-time feature flags.

### Syscall Bridge

- **ActiveSyscall**: A type alias that resolves to either the real `SyscallEngine` (when the `microkernel` feature is enabled) or a `MockSyscall` implementation (when the feature is disabled).

### Microkernel

- **SyscallEngine**: Implements the `SyscallAPI` trait with actual syscall logic, including security checks, RBAC enforcement, and audit logging.
- **secure_syscall()**: A function that wraps syscall execution with Zero Trust Architecture (ZTA) policy enforcement, dynamic policy rewriting, and audit logging.

## Security Features

- **Compile-time Boundaries**: The architecture uses Rust's compile-time feature flags to enforce boundaries between modules.
- **Zero Trust Architecture**: All syscalls are validated against a ZTA policy graph before execution.
- **Audit Logging**: All syscall operations are logged for security auditing and debugging purposes.
- **RBAC Enforcement**: Role-based access control is applied to all syscall operations.

## Advantages

- **No Runtime IPC/Sockets**: The architecture avoids the overhead and complexity of runtime IPC mechanisms like sockets.
- **In-Memory Boundary**: All communication happens in-memory, which is faster and easier to audit.
- **Compile-Time Replaceable Logic**: The implementation can be swapped at compile-time based on feature flags.
- **Multi-Tenant Safe**: User isolation is enforced before running syscalls, making the system safe for multi-tenant environments.
- **Production-Ready**: The architecture is suitable for cloud, edge, or rootless development environments.

## Implementation Details

### Feature Flags

The architecture uses the following feature flags:

- `microkernel`: When enabled, uses the real `SyscallEngine` implementation. When disabled, uses a `MockSyscall` implementation.
- `syscall-client`: When enabled in the common crate, initializes the `SYSCALL` instance for observer functionality.

### Dependency Flow

1. Application code depends on the `common` crate and uses the `SyscallAPI` trait.
2. The `common` crate depends on the `syscall-bridge` module for the `ActiveSyscall` type.
3. The `syscall-bridge` module depends on the `microkernel` crate only when the `microkernel` feature is enabled.

This dependency flow ensures that the `common` crate never directly depends on the `microkernel` crate, maintaining the hard boundary between them.