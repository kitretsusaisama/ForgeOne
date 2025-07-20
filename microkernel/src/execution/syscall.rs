//! Syscall execution for the ForgeOne Microkernel
//!
//! Provides secure syscall execution with Zero Trust Architecture (ZTA) policy
//! enforcement, dynamic policy rewriting, audit logging, and performance telemetry.
//! Integrates with the telemetry module to track syscall metrics and performance.

use crate::syscall_bridge::ActiveSyscall;
use crate::telemetry;
use crate::trust::zta_policy::ZtaPolicyGraph;
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use common::observer::trace::ExecutionSpan;
use common::observer::SyscallContextTrait;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::time::Instant;

static SYSCALL: Lazy<ActiveSyscall> = Lazy::new(|| ActiveSyscall {});

/// Syscall types supported by the microkernel
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SyscallType {
    /// File operations
    File,
    /// Network operations
    Network,
    /// Process operations
    Process,
    /// Memory operations
    Memory,
    /// IPC operations
    Ipc,
    /// Time operations
    Time,
    /// Crypto operations
    Crypto,
    /// System operations
    System,
}

/// Syscall context for execution
#[derive(Debug, Clone)]
pub struct SyscallContext {
    /// Syscall name
    pub syscall_name: String,
    /// Syscall type
    pub syscall_type: SyscallType,
    /// Syscall arguments
    pub args: Vec<String>,
    /// Syscall identity context
    pub identity: std::sync::Arc<IdentityContext>,
    /// Syscall policy decision
    pub policy_decision: Option<bool>,
    /// Syscall execution time
    pub execution_time: Option<std::time::Duration>,
    /// Syscall result
    pub result: Option<SyscallResult>,
}

impl SyscallContextTrait for SyscallContext {
    fn name(&self) -> &str {
        &self.syscall_name
    }
    fn result_string(&self) -> String {
        match &self.result {
            Some(r) => format!("{:?}", r),
            None => "None".to_string(),
        }
    }
}

/// Syscall result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyscallResult {
    /// Syscall succeeded
    Success,
    /// Syscall failed with error
    Failure(String),
    /// Syscall was denied by policy
    Denied(String),
    /// Syscall was redirected
    Redirected(String),
}

/// Execute a secure syscall with ZTA enforcement
pub fn secure_syscall(
    syscall: &str,
    args: &[&str],
    identity: &IdentityContext,
    policy_graph: &ZtaPolicyGraph,
    span: &mut ExecutionSpan,
) -> Result<()> {
    // Parse the syscall type
    let syscall_type = parse_syscall_type(syscall)?;
    let syscall_type_str = format!("{:?}", syscall_type);

    // Create the syscall context
    let mut context = SyscallContext {
        syscall_name: syscall.to_string(),
        syscall_type,
        args: args.iter().map(|s| s.to_string()).collect(),
        identity: std::sync::Arc::new(identity.clone()),
        policy_decision: None,
        execution_time: None,
        result: None,
    };

    // Start timing
    let start_time = Instant::now();

    // Check policy
    let policy_decision = check_policy(syscall, args, identity, policy_graph)?;
    context.policy_decision = Some(policy_decision);

    if !policy_decision {
        // Policy denied the syscall
        context.result = Some(SyscallResult::Denied(format!(
            "Syscall {} denied by ZTA policy",
            syscall
        )));

        // Record the syscall in the span
        span.add_attribute("syscall.name", syscall.to_string());
        span.add_attribute("syscall.denied", format!("{}", true));

        // Record denied syscall in telemetry
        let mut telemetry_span = telemetry::execution_span_to_telemetry_span(span);
        telemetry::record_denied_syscall(&context, &mut telemetry_span);

        return Err(ForgeError::AuthorizationError {
            resource: syscall.to_string(),
            action: "execute".to_string(),
            policy_id: "zta".to_string(),
            required_permissions: vec![],
        });
    }

    // Execute the syscall
    let result = match execute_syscall(syscall, args) {
        Ok(_) => {
            context.result = Some(SyscallResult::Success);
            Ok(())
        }
        Err(e) => {
            context.result = Some(SyscallResult::Failure(e.to_string()));

            // Record the syscall in the span
            span.add_attribute("syscall.name", syscall.to_string());
            span.add_attribute("syscall.error", true.to_string());
            span.add_attribute("syscall.error_message", e.to_string());
            tracing::error!("Syscall error: {}", e);

            // // Record error syscall in telemetry
            // telemetry::record_error_syscall(&context, &e.to_string(), span);

            Err(e)
        }
    };

    // End timing
    let duration = start_time.elapsed();
    context.execution_time = Some(duration);

    // Record the syscall in the span
    span.add_attribute("syscall.name", syscall.to_string());
    span.add_attribute("syscall.type", syscall_type_str);
    span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
    span.add_metric("syscall.duration_ms", duration.as_millis() as f64);

    // Record successful syscall in telemetry if the result is Ok
    if result.is_ok() {
        // telemetry::get_syscall_metrics().record_syscall(&context, duration, span);
        tracing::info!("Syscall succeeded: {}", context.name());
    }

    tracing::debug!(syscall = %syscall, args = ?args, identity = ?identity, execution_time_us = %duration.as_micros(), "Syscall executed");

    result
}

/// Parse the syscall type from the syscall name
fn parse_syscall_type(syscall: &str) -> Result<SyscallType> {
    if syscall.starts_with("file_") {
        Ok(SyscallType::File)
    } else if syscall.starts_with("net_") {
        Ok(SyscallType::Network)
    } else if syscall.starts_with("proc_") {
        Ok(SyscallType::Process)
    } else if syscall.starts_with("mem_") {
        Ok(SyscallType::Memory)
    } else if syscall.starts_with("ipc_") {
        Ok(SyscallType::Ipc)
    } else if syscall.starts_with("time_") {
        Ok(SyscallType::Time)
    } else if syscall.starts_with("crypto_") {
        Ok(SyscallType::Crypto)
    } else if syscall.starts_with("sys_") {
        Ok(SyscallType::System)
    } else {
        Err(ForgeError::Execution(format!(
            "Unknown syscall type: {}",
            syscall
        )))
    }
}

/// Check if the syscall is allowed by the ZTA policy
fn check_policy(
    syscall: &str,
    args: &[&str],
    identity: &IdentityContext,
    policy_graph: &ZtaPolicyGraph,
) -> Result<bool> {
    // Build a SyscallContext for evaluation
    let context = SyscallContext {
        syscall_name: syscall.to_string(),
        syscall_type: parse_syscall_type(syscall)?,
        args: args.iter().map(|s| s.to_string()).collect(),
        identity: std::sync::Arc::new(identity.clone()),
        policy_decision: None,
        execution_time: None,
        result: None,
    };
    let result = policy_graph.evaluate(&context);
    let decision = result.allowed;
    tracing::debug!(syscall = %syscall, args = ?args, identity = ?identity, decision = %decision, "Policy decision");
    Ok(decision)
}

/// Execute a syscall
pub fn execute_syscall(syscall: &str, args: &[&str]) -> Result<()> {
    // Execute the syscall based on its type
    match syscall {
        "file_open" => execute_file_open(args),
        "file_read" => execute_file_read(args),
        "file_write" => execute_file_write(args),
        "file_close" => execute_file_close(args),
        "net_connect" => execute_net_connect(args),
        "net_send" => execute_net_send(args),
        "net_recv" => execute_net_recv(args),
        "net_close" => execute_net_close(args),
        "proc_create" => execute_proc_create(args),
        "proc_kill" => execute_proc_kill(args),
        "mem_alloc" => execute_mem_alloc(args),
        "mem_free" => execute_mem_free(args),
        "ipc_send" => execute_ipc_send(args),
        "ipc_recv" => execute_ipc_recv(args),
        "time_get" => execute_time_get(args),
        "time_sleep" => execute_time_sleep(args),
        "crypto_hash" => execute_crypto_hash(args),
        "crypto_sign" => execute_crypto_sign(args),
        "crypto_verify" => execute_crypto_verify(args),
        "sys_info" => execute_sys_info(args),
        _ => Err(ForgeError::Execution(format!(
            "Unknown syscall: {}",
            syscall
        ))),
    }
}

// Syscall implementations

fn execute_file_open(args: &[&str]) -> Result<()> {
    // TODO: Implement file_open syscall
    Ok(())
}

fn execute_file_read(args: &[&str]) -> Result<()> {
    // TODO: Implement file_read syscall
    Ok(())
}

fn execute_file_write(args: &[&str]) -> Result<()> {
    // TODO: Implement file_write syscall
    Ok(())
}

fn execute_file_close(args: &[&str]) -> Result<()> {
    // TODO: Implement file_close syscall
    Ok(())
}

fn execute_net_connect(args: &[&str]) -> Result<()> {
    // TODO: Implement net_connect syscall
    Ok(())
}

fn execute_net_send(args: &[&str]) -> Result<()> {
    // TODO: Implement net_send syscall
    Ok(())
}

fn execute_net_recv(args: &[&str]) -> Result<()> {
    // TODO: Implement net_recv syscall
    Ok(())
}

fn execute_net_close(args: &[&str]) -> Result<()> {
    // TODO: Implement net_close syscall
    Ok(())
}

fn execute_proc_create(args: &[&str]) -> Result<()> {
    // TODO: Implement proc_create syscall
    Ok(())
}

fn execute_proc_kill(args: &[&str]) -> Result<()> {
    // TODO: Implement proc_kill syscall
    Ok(())
}

fn execute_mem_alloc(args: &[&str]) -> Result<()> {
    // TODO: Implement mem_alloc syscall
    Ok(())
}

fn execute_mem_free(args: &[&str]) -> Result<()> {
    // TODO: Implement mem_free syscall
    Ok(())
}

fn execute_ipc_send(args: &[&str]) -> Result<()> {
    // TODO: Implement ipc_send syscall
    Ok(())
}

fn execute_ipc_recv(args: &[&str]) -> Result<()> {
    // TODO: Implement ipc_recv syscall
    Ok(())
}

fn execute_time_get(args: &[&str]) -> Result<()> {
    // TODO: Implement time_get syscall
    Ok(())
}

fn execute_time_sleep(args: &[&str]) -> Result<()> {
    // TODO: Implement time_sleep syscall
    Ok(())
}

fn execute_crypto_hash(args: &[&str]) -> Result<()> {
    // TODO: Implement crypto_hash syscall
    Ok(())
}

fn execute_crypto_sign(args: &[&str]) -> Result<()> {
    // TODO: Implement crypto_sign syscall
    Ok(())
}

fn execute_crypto_verify(args: &[&str]) -> Result<()> {
    // TODO: Implement crypto_verify syscall
    Ok(())
}

fn execute_sys_info(args: &[&str]) -> Result<()> {
    // TODO: Implement sys_info syscall
    Ok(())
}
