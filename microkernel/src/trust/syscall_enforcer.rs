//! # Syscall Enforcer Module for ForgeOne Microkernel
//!
//! This module provides syscall enforcement for the ForgeOne microkernel.
//! It applies specific policies to each syscall, validates arguments against policy constraints,
//! records all policy decisions for audit and replay, and manages responses to policy violations.

use crate::execution::syscall::{SyscallContext, SyscallResult};
use crate::trust::zta_policy::{get_policy_graph, SyscallPolicy, ZtaPolicyGraph};
use chrono::Utc;
use common::identity::IdentityContext;
use common::observer::record_syscall;
use std::sync::{Arc, RwLock};
use tracing;
use uuid::Uuid;

/// Enforcement mode for the syscall enforcer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Enforce policies and block violations
    Enforce,
    /// Log violations but allow syscalls
    Audit,
    /// Allow syscalls but warn about violations
    Permissive,
}

/// Action to take when a policy violation is detected
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViolationAction {
    /// Block the syscall
    Block,
    /// Quarantine the process
    Quarantine,
    /// Warn about the violation but allow the syscall
    Warn,
    /// Allow the syscall despite the violation
    Allow,
}

/// Handler for policy violations
pub trait ViolationHandler: Send + Sync {
    /// Handle a policy violation
    fn handle_violation(
        &self,
        context: &SyscallContext,
        policy: &SyscallPolicy,
        reason: &str,
    ) -> ViolationAction;
}

/// Default implementation of ViolationHandler
pub struct DefaultViolationHandler {
    /// Enforcement mode
    pub mode: EnforcementMode,
}

impl DefaultViolationHandler {
    /// Create a new DefaultViolationHandler
    pub fn new() -> Self {
        Self {
            mode: EnforcementMode::Enforce,
        }
    }

    /// Create a new DefaultViolationHandler with a specific mode
    pub fn with_mode(mode: EnforcementMode) -> Self {
        Self { mode }
    }
}

impl ViolationHandler for DefaultViolationHandler {
    fn handle_violation(
        &self,
        context: &SyscallContext,
        policy: &SyscallPolicy,
        reason: &str,
    ) -> ViolationAction {
        // Log the violation
        tracing::warn!(
            "Policy violation: {} by {} ({}): {}",
            context.syscall_name,
            context.identity.user_id,
            context.identity.tenant_id,
            reason
        );

        // Determine action based on enforcement mode
        match self.mode {
            EnforcementMode::Enforce => {
                // High-risk syscalls should quarantine
                if policy.min_trust_score > 0.8 {
                    ViolationAction::Quarantine
                } else {
                    ViolationAction::Block
                }
            }
            EnforcementMode::Audit => ViolationAction::Warn,
            EnforcementMode::Permissive => ViolationAction::Allow,
        }
    }
}

/// Syscall enforcer for the ForgeOne microkernel
pub struct SyscallEnforcer {
    /// Policy graph for evaluating syscalls
    pub policy_graph: Arc<RwLock<ZtaPolicyGraph>>,
    /// Whether to trace syscalls
    pub trace_enabled: bool,
    /// Enforcement mode
    pub enforcement_mode: EnforcementMode,
    /// Handler for policy violations
    pub violation_handler: Box<dyn ViolationHandler>,
}

impl SyscallEnforcer {
    /// Create a new SyscallEnforcer
    pub fn new(
        policy_graph: Arc<RwLock<ZtaPolicyGraph>>,
        trace_enabled: bool,
        enforcement_mode: EnforcementMode,
        violation_handler: Box<dyn ViolationHandler>,
    ) -> Self {
        Self {
            policy_graph,
            trace_enabled,
            enforcement_mode,
            violation_handler,
        }
    }

    /// Create a new SyscallEnforcer with default settings
    pub fn default() -> Self {
        Self {
            policy_graph: get_policy_graph(),
            trace_enabled: true,
            enforcement_mode: EnforcementMode::Enforce,
            violation_handler: Box::new(DefaultViolationHandler::new()),
        }
    }

    /// Enforce a syscall
    pub fn enforce(&self, context: &SyscallContext) -> Result<(), ViolationAction> {
        // Get the policy graph
        let graph = self.policy_graph.read().unwrap();

        // Evaluate the policy
        let result = graph.evaluate(context);

        // Record the syscall if tracing is enabled
        if self.trace_enabled {
            record_syscall(
                &context.syscall_name,
                &context.identity,
                &context.args,
                result.allowed,
                result.reason.as_deref(),
            );
        }

        // Check if the syscall is allowed
        if !result.allowed {
            // Get the policy
            let policy = graph
                .policies
                .get(&context.syscall_name)
                .unwrap_or_else(|| {
                    panic!("Policy not found for syscall: {}", context.syscall_name)
                });

            // Handle the violation
            let action = self.violation_handler.handle_violation(
                context,
                policy,
                result.reason.as_deref().unwrap_or("Unknown reason"),
            );

            // Return the action
            return Err(action);
        }

        Ok(())
    }
}

/// Trace of a syscall
#[derive(Debug, Clone)]
pub struct SyscallTrace {
    pub id: u64,
    pub syscall: String,
    pub syscall_name: String,
    pub args: Vec<String>,
    pub identity: IdentityContext,
    pub trust_score: f64,
    pub allowed: bool,
    pub reason: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub result: String,
}

/// Enforce a syscall with the default enforcer
pub fn enforce_syscall(
    syscall: &str,
    args: &[&str],
    identity: &IdentityContext,
) -> Result<(), ViolationAction> {
    let enforcer = SyscallEnforcer::default();

    let context = SyscallContext {
        syscall_name: syscall.to_string(),
        syscall_type: crate::execution::syscall::SyscallType::System,
        args: args.iter().map(|s| s.to_string()).collect(),
        identity: Arc::new(identity.clone()),
        policy_decision: None,
        execution_time: None,
        result: Some(crate::execution::syscall::SyscallResult::Success),
    };

    enforcer.enforce(&context)
}
