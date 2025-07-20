//! # Trust Module for ForgeOne Microkernel
//!
//! This module provides Zero Trust Architecture (ZTA) enforcement for the ForgeOne microkernel.
//! It includes policy evaluation, syscall enforcement, and quarantine mechanisms for compromised processes.
//! The Trust module is central to the microkernel's security model, providing dynamic policy graphs,
//! context-aware decisions, adaptive trust vectors, and policy versioning.

// Submodules
pub mod attestation;
pub mod evaluation;
pub mod redzone;
pub mod syscall_enforcer;
pub mod zta_policy;

// Re-exports
pub use attestation::{
    AttestationClaim, AttestationManager, AttestationResult, AttestationStatus, AttestationType,
};
pub use evaluation::{
    TrustEvaluationContext, TrustEvaluationResult, TrustEvaluator, TrustScoreComponents,
};
pub use redzone::{
    ForensicMode, IsolationLevel, QuarantineStatus, QuarantinedProcess, Redzone, RedzoneStatus,
};
pub use syscall_enforcer::{
    EnforcementMode, SyscallEnforcer, SyscallTrace, ViolationAction, ViolationHandler,
};
pub use zta_policy::{IdentityRule, PolicyEvaluationResult, SyscallPolicy, ZtaPolicyGraph};

/// Initialize the Trust module
pub fn init() -> Result<(), String> {
    // Initialize the ZTA policy graph
    let policy_graph = zta_policy::init()?;

    // Initialize the syscall enforcer
    // No explicit initialization required for syscall_enforcer

    // Initialize the redzone
    redzone::init()?;

    // Initialize the attestation manager
    attestation::init()?;

    // Initialize the trust evaluator
    // evaluation::init(policy_graph)?;
    tracing::info!("Trust module initialized");

    Ok(())
}

/// Shutdown the Trust module
pub fn shutdown() -> Result<(), String> {
    // Perform any necessary cleanup
    tracing::info!("Trust module shutdown");

    Ok(())
}

/// Evaluate a syscall against ZTA policies
pub fn evaluate_syscall(
    syscall_name: &str,
    args: &[String],
    identity: common::identity::IdentityContext,
) -> Result<ViolationAction, String> {
    // Directly use the default enforcer
    let enforcer = syscall_enforcer::SyscallEnforcer::default();
    enforcer
        .enforce(&crate::execution::syscall::SyscallContext {
            syscall_name: syscall_name.to_string(),
            syscall_type: crate::execution::syscall::SyscallType::System,
            args: args.iter().map(|s| s.to_string()).collect(),
            identity: std::sync::Arc::new(identity.clone()),
            policy_decision: None,
            execution_time: None,
            result: Some(crate::execution::syscall::SyscallResult::Success),
        })
        .map_err(|action| format!("Syscall violation: {:?}", action))?;
    Ok(ViolationAction::Allow)
}

/// Quarantine a process
pub fn quarantine_process(
    container_id: uuid::Uuid,
    identity: common::identity::IdentityContext,
    reason: &str,
    syscall_traces: Vec<SyscallTrace>,
) -> Result<uuid::Uuid, String> {
    redzone::quarantine(container_id, identity, reason, syscall_traces)
}

/// Verify attestation claim
pub fn verify_attestation(claim_id: uuid::Uuid) -> Result<AttestationResult, String> {
    attestation::verify_claim(claim_id)
}

/// Evaluate trust for a context
pub fn evaluate_trust(context_id: uuid::Uuid) -> Result<TrustEvaluationResult, String> {
    evaluation::evaluate_trust(context_id)
}
