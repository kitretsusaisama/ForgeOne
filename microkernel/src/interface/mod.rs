//!
//! # ForgeOne Microkernel: Advanced Containerization Interface Module
//!
//! ## Overview
//! This module defines the core interfaces for the advanced containerization platform within the ForgeOne Microkernel.
//! It provides abstractions for orchestrating, executing, and managing workloads as containers, including support for WebAssembly modules, native binaries, and multi-tenant containerized applications.
//! The design is focused on secure, scalable, and extensible container orchestration for production-grade, multi-national corporation (MNC) environments.
//!
//! ## Key Responsibilities
//! - Define and expose safe, auditable interfaces for advanced container orchestration and lifecycle management.
//! - Support pluggable execution backends (WASM, native, containers) with strong isolation guarantees.
//! - Enforce strict separation, resource control, and sandboxing between containers and workloads.
//! - Provide hooks for monitoring, logging, policy enforcement, and dynamic scaling.
//!
//! ## Security & Safety
//! - Interfaces are designed with least-privilege, defense-in-depth, and multi-tenant isolation principles.
//! - Input validation, memory safety, and capability-based access control are enforced at all levels.
//! - Integrated audit trails, diagnostics, and compliance features for regulated environments.
//!
//! ## Extensibility
//! - Interfaces are modular and designed for easy extension and integration with custom plugins, third-party modules, and orchestration frameworks.
//! - Backward compatibility is maintained via versioned traits and feature flags.
//!
//! ## Usage
//! See the [architecture documentation](../../../docs/architecture/core.md) and [developer guide](../../../docs/plugins/developer-guide.md) for integration patterns, extension points, and container orchestration examples.
//!
//! ## TODO
//! - Document all public traits and structs in this module.
//! - Add code examples for advanced container orchestration scenarios.
//!
//! Execution module for the ForgeOne Microkernel
//!
//! The Execution module provides the functionality for executing workloads,
//! including WebAssembly modules, native code, and containers.

/// Trait for basic container lifecycle management
pub trait ContainerLifecycle {
    /// Create a new container with the given workload and identity context
    fn create_container(
        &self,
        workload: crate::core::runtime::Workload,
        identity: &common::identity::IdentityContext,
    ) -> common::error::Result<uuid::Uuid>;
    /// Start a container by its ID
    fn start_container(&self, container_id: &uuid::Uuid) -> common::error::Result<()>;
    /// Stop a container by its ID
    fn stop_container(&self, container_id: &uuid::Uuid) -> common::error::Result<()>;
    /// Remove a container by its ID
    fn remove_container(&self, container_id: &uuid::Uuid) -> common::error::Result<()>;
    /// Get the state of a container
    fn get_container_state(
        &self,
        container_id: &uuid::Uuid,
    ) -> common::error::Result<crate::core::runtime::ContainerState>;
}

/// Trait for advanced container orchestration
pub trait ContainerOrchestrator: ContainerLifecycle {
    /// List all active containers
    fn list_containers(&self)
        -> common::error::Result<Vec<crate::core::runtime::ContainerContext>>;
    /// Scale containers up or down
    fn scale_containers(&self, desired_count: usize) -> common::error::Result<()>;
    /// Apply resource limits to a container
    fn set_resource_limits(
        &self,
        container_id: &uuid::Uuid,
        limits: crate::core::runtime::ResourceLimits,
    ) -> common::error::Result<()>;
    /// Attach monitoring hooks to a container
    fn attach_monitoring(&self, container_id: &uuid::Uuid) -> common::error::Result<()>;
}

/// Trait for extensibility (plugins, custom schedulers, etc.)
pub trait ContainerPlatformExtension {
    /// Register a custom extension or plugin
    fn register_extension(&self, name: &str, extension: Box<dyn std::any::Any + Send + Sync>);
    /// Query for a registered extension
    fn get_extension(&self, name: &str) -> Option<&(dyn std::any::Any + Send + Sync)>;
}
