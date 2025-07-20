# ForgeOne Common Module - Implementation Guide

## Overview

This implementation guide provides detailed, step-by-step instructions for implementing the advanced folder structure for the ForgeOne Common module. While the [migration_script.ps1](migration_script.ps1) automates much of this process, this guide provides a manual approach for developers who prefer to implement the changes manually or need to troubleshoot issues with the automated migration.

## Prerequisites

1. Backup your current codebase to avoid data loss.
2. Ensure you have the necessary permissions to modify the codebase.
3. Familiarize yourself with the [advanced_folder_structure_plan.md](advanced_folder_structure_plan.md) document.

## Implementation Steps

### Phase 1: Module Reorganization

#### Step 1.1: Create Module Directories

Create the following directories in the `src` directory:

```
src/
├── bootstrap/
├── config/
├── crypto/
├── db/
├── error/
├── identity/
├── trust/
├── policy/
├── telemetry/
├── observer/
├── diagnostics/
├── audit/
├── model/
└── macros/
```

#### Step 1.2: Create mod.rs Files

Create a `mod.rs` file in each module directory with the following content (replace `ModuleName` with the actual module name):

```rust
//! ModuleName module for ForgeOne Common

// Re-export all public items
```

#### Step 1.3: Move Existing Code

For each module, move the content of the corresponding `.rs` file in the `src` directory to the `mod.rs` file in the module directory. For example, move the content of `src/bootstrap.rs` to `src/bootstrap/mod.rs`.

#### Step 1.4: Create Submodule Files

Create the following submodule files for each module:

**bootstrap/**
```
bootstrap/
├── mod.rs
├── init.rs
└── shutdown.rs
```

**config/**
```
config/
├── mod.rs
├── loader.rs
├── validator.rs
└── signed.rs
```

**crypto/**
```
crypto/
├── mod.rs
├── keys.rs
├── signatures.rs
├── encryption.rs
├── hashing.rs
└── random.rs
```

**db/**
```
db/
├── mod.rs
├── access.rs
├── crypto.rs
├── indxdb.rs
├── integrity.rs
├── metrics.rs
├── model.rs
├── recovery.rs
├── redb.rs
├── schema.rs
├── snapshot.rs
├── sharding.rs
└── vault.rs
```

**error/**
```
error/
├── mod.rs
├── types.rs
├── traceable.rs
└── predictor.rs
```

**identity/**
```
identity/
├── mod.rs
├── context.rs
└── trust.rs
```

**trust/**
```
trust/
├── mod.rs
├── graph.rs
├── node.rs
└── evaluation.rs
```

**policy/**
```
policy/
├── mod.rs
├── effect.rs
├── rule.rs
└── set.rs
```

**telemetry/**
```
telemetry/
├── mod.rs
├── metrics.rs
├── tracing.rs
├── health.rs
└── profiling.rs
```

**observer/**
```
observer/
├── mod.rs
├── types.rs
├── severity.rs
└── llm.rs
```

**diagnostics/**
```
diagnostics/
├── mod.rs
├── health.rs
├── predictive.rs
└── reporting.rs
```

**audit/**
```
audit/
├── mod.rs
├── event.rs
├── log.rs
├── policy.rs
└── compliance.rs
```

**model/**
```
model/
├── mod.rs
├── syscall.rs
├── execution.rs
└── resource.rs
```

**macros/**
```
macros/
├── mod.rs
├── logging.rs
├── tracing.rs
├── policy.rs
└── audit.rs
```

#### Step 1.5: Update lib.rs

Update `src/lib.rs` to re-export the modules from their new locations:

```rust
// Re-export modules
pub mod bootstrap;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod identity;
pub mod trust;
pub mod policy;
pub mod telemetry;
pub mod observer;
pub mod diagnostics;
pub mod audit;
pub mod model;
pub mod macros;

// Re-export prelude
pub mod prelude;

// Re-export initialization functions
pub use bootstrap::init;
pub use bootstrap::init_with_config;
pub use bootstrap::init_with_db;
pub use bootstrap::init_with_db_options;

// Re-export shutdown function
pub use bootstrap::shutdown;
```

#### Step 1.6: Update Imports

Update imports in all files to reflect the new structure. For example, change:

```rust
use crate::bootstrap::init;
```

to:

```rust
use crate::bootstrap::init;
```

(In this case, the import doesn't change because we're re-exporting from the same path, but other imports may need to be updated.)

### Phase 2: Test Reorganization

#### Step 2.1: Create Test Directories

Create the following directories in the `tests` directory:

```
tests/
├── common/
├── unit/
│   ├── bootstrap/
│   ├── config/
│   ├── crypto/
│   ├── db/
│   ├── error/
│   ├── identity/
│   ├── trust/
│   ├── policy/
│   ├── telemetry/
│   ├── observer/
│   ├── diagnostics/
│   ├── audit/
│   ├── model/
│   └── macros/
├── integration/
└── performance/
```

#### Step 2.2: Create Common Test Utilities

Create the following files in the `tests/common` directory:

```
common/
├── mod.rs
├── fixtures.rs
└── helpers.rs
```

With the following content:

**mod.rs**
```rust
//! Common test utilities for ForgeOne Common

pub mod fixtures;
pub mod helpers;
```

**fixtures.rs**
```rust
//! Test fixtures for ForgeOne Common
```

**helpers.rs**
```rust
//! Test helpers for ForgeOne Common
```

#### Step 2.3: Move Existing Tests

Move existing test files to their appropriate locations in the new test directory structure. For example, move `tests/bootstrap_test.rs` to `tests/unit/bootstrap/bootstrap_test.rs`.

#### Step 2.4: Update Test Imports

Update imports in all test files to reflect the new structure. For example, change:

```rust
use common::bootstrap;
```

to:

```rust
use common::bootstrap;
```

(In this case, the import doesn't change because we're importing from the crate, but other imports may need to be updated.)

### Phase 3: Data Reorganization

#### Step 3.1: Create Data Directories

Create the following directories in the `data` directory:

```
data/
├── redb/
├── vault/
└── backups/
    ├── system/
    ├── logs/
    ├── blobs/
    └── events/
```

#### Step 3.2: Create Placeholder Files

Create a placeholder file for the vault:

```
data/vault/secrets.vault
```

With the following content:

```
# Placeholder for encrypted secrets vault
```

#### Step 3.3: Update Data Access Code

Update code that accesses data to reflect the new structure. For example, change:

```rust
let db_path = "data/system.redb";
```

to:

```rust
let db_path = "data/redb/system.redb";
```

### Phase 4: Examples

#### Step 4.1: Create Examples Directory

Create the `examples` directory:

```
examples/
```

#### Step 4.2: Create Example Files

Create the following example files:

```
examples/
├── basic_usage.rs
├── audit_example.rs
├── policy_example.rs
└── db_example.rs
```

With the following content (replace `ExampleName` with the actual example name):

```rust
//! ExampleName example for ForgeOne Common

fn main() {
    println!("ExampleName example for ForgeOne Common");
}
```

### Phase 5: Documentation

#### Step 5.1: Create Documentation Files

Create documentation files for each module in the `docs` directory:

```
docs/
├── README.md
├── architecture.md
├── bootstrap.md
├── config.md
├── crypto.md
├── db.md
├── error.md
├── identity.md
├── trust.md
├── policy.md
├── telemetry.md
├── observer.md
├── diagnostics.md
├── audit.md
├── model.md
├── macros.md
└── examples/
    ├── basic_usage.md
    ├── audit_example.md
    ├── policy_example.md
    └── db_example.md
```

#### Step 5.2: Update Main README

Update the main README to reflect the new structure.

## Verification

After implementing the changes, verify that the codebase still builds and all tests pass:

```bash
cargo build
cargo test
```

## Troubleshooting

### Common Issues

1. **Missing Imports**: If you encounter missing import errors, check that you've updated all imports to reflect the new structure.

2. **Module Not Found**: If you encounter module not found errors, check that you've created all the necessary directories and files.

3. **Build Errors**: If you encounter build errors, check that you've moved all the necessary code to the new locations.

### Solutions

1. **Revert to Backup**: If you encounter issues that you can't resolve, revert to your backup and try again.

2. **Use the Migration Script**: If you're having trouble implementing the changes manually, try using the migration script instead.

3. **Incremental Changes**: If you're having trouble implementing all the changes at once, try implementing them incrementally, starting with one module at a time.

## Conclusion

By following this implementation guide, you should be able to successfully implement the advanced folder structure for the ForgeOne Common module. If you encounter any issues, refer to the troubleshooting section or consult the migration script for guidance.