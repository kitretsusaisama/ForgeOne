//! # ForgeOne Microkernel
//!
//! A sentient, reflexive, cryptographically sovereign execution brain — a microkernel
//! so hyper-optimized, it can predict malicious behavior, explain itself to auditors,
//! AI agents, and humans, dynamically rewrite its syscall logic based on trust vector
//! entropy, and launch secure workloads across cloud, edge, and air-gapped systems
//! with zero manual intervention.
//!
//! ## Features
//!
//! - **Execution Brain**: Fully modularized kernel graph with runtime decisions driven by
//!   LLM-interpretable memory-trace correlation
//! - **Dynamic ZTA Rewriter**: ZTA engine rewrites syscall policies in real time based on
//!   anomaly heatmaps
//! - **Immutable PKG Capsules**: `.forgepkg` supports multi-signature quorum + lattice-sealed ACLs
//! - **Self-Awareness Module**: Kernel evaluates its own integrity + performance and reports
//!   in human+machine form
//! - **Conscious Span DNA**: Every container execution maintains a DNA-style hash trace
//! - **Trusted Federation**: Nodes exchange trust state via P2P lattice with audit-capable state sync
//! - **Zero-Trust Red Zones**: Compromised processes are live-migrated to a ring-fenced memory
//!   quarantine zone

// Core modules
pub use common::config;
pub mod core;
pub use common::crypto;
pub use common::diagnostics;
pub mod execution;
pub mod interface;
pub use common::observer;
pub mod syscall_bridge;
pub mod syscall_engine;
pub use common::telemetry;
pub mod trust;
pub use common::syscall_client::SyscallAPI;

// Re-export common error types
pub use common::error::{ForgeError, Result};

/// Version of the microkernel
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the microkernel with default configuration
pub fn init() -> Result<core::boot::BootContext> {
    // Initialize telemetry
    telemetry::init_syscall_metrics();

    let boot_context = core::boot::init()?;
    tracing::info!(version = VERSION, "ForgeOne Microkernel initialized");
    Ok(boot_context)
}

/// Initialize the microkernel with custom configuration
pub fn init_with_config(config_path: &str) -> Result<core::boot::BootContext> {
    // Initialize telemetry
    telemetry::init_syscall_metrics();

    let config = config::runtime::load_runtime_config(config_path)?;
    let boot_context = core::boot::init_with_config(&config)?;
    tracing::info!(
        version = VERSION,
        "ForgeOne Microkernel initialized with custom config"
    );
    Ok(boot_context)
}

/// Shutdown the microkernel
pub fn shutdown() -> Result<()> {
    core::boot::shutdown()?;
    tracing::info!("ForgeOne Microkernel shutdown complete");
    Ok(())
}

/// Execute a secure syscall with ZTA enforcement
pub fn secure_syscall(
    syscall: &str,
    args: &[&str],
    identity: &common::identity::IdentityContext,
) -> Result<()> {
    // Create execution span for tracing
    let mut span = observer::trace::ExecutionSpan::new(syscall, identity.clone());

    // Convert args to String for trust evaluation
    let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

    // Evaluate syscall against ZTA policies
    let action = trust::evaluate_syscall(syscall, &string_args, identity.clone()).map_err(|e| {
        ForgeError::AuthorizationError {
            resource: syscall.to_string(),
            action: "zta_policy".to_string(),
            policy_id: "zta".to_string(),
            required_permissions: vec![],
        }
    })?;

    // Handle the action based on the evaluation result
    match action {
        trust::ViolationAction::Block => {
            // Block the syscall
            span.add_event("syscall_blocked");
            return Err(ForgeError::AuthorizationError {
                resource: syscall.to_string(),
                action: "zta_policy".to_string(),
                policy_id: "zta".to_string(),
                required_permissions: vec![],
            });
        }
        trust::ViolationAction::Quarantine => {
            // Quarantine the process
            span.add_event("process_quarantined");

            // Create syscall trace for quarantine
            let syscall_trace = trust::SyscallTrace {
                id: 0, // or another unique identifier if needed
                syscall: syscall.to_string(),
                syscall_name: syscall.to_string(),
                args: string_args,
                identity: identity.clone(),
                trust_score: 0.0, // set appropriately
                allowed: false,   // set appropriately
                reason: Some("Quarantined due to ZTA policy violation".to_string()),
                timestamp: chrono::Utc::now(),
                result: "QUARANTINED".to_string(),
            };

            // Quarantine the process
            let container_id = uuid::Uuid::new_v4();

            trust::quarantine_process(
                container_id,
                identity.clone(),
                &format!("ZTA policy violation in syscall: {}", syscall),
                vec![syscall_trace],
            )
            .map_err(|_e| ForgeError::AuthorizationError {
                resource: syscall.to_string(),
                action: "zta_policy".to_string(),
                policy_id: "zta".to_string(),
                required_permissions: vec![],
            })?;

            return Err(ForgeError::AuthorizationError {
                resource: syscall.to_string(),
                action: "zta_policy".to_string(),
                policy_id: "zta".to_string(),
                required_permissions: vec![],
            });
        }
        trust::ViolationAction::Warn => {
            // Log a warning but allow the syscall
            span.add_event("syscall_warning");
            tracing::warn!(syscall = syscall, "ZTA policy warning for syscall");
        }
        trust::ViolationAction::Allow => {
            // Allow the syscall despite violation
            span.add_event("syscall_allowed");
            tracing::info!(syscall = syscall, "ZTA policy override for syscall");
        }
    }

    // Execute the syscall
    execution::syscall::execute_syscall(syscall, args)
}
