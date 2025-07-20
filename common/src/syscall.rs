//! Syscall implementation for the common crate
//!
//! This module provides the actual syscall implementation when the microkernel feature is enabled.
//! It serves as a compile-time bridge between the common crate and the microkernel.
//!
//! This module also integrates telemetry metrics for syscall performance monitoring.

use crate::error::Result;
use crate::observer::trace::ExecutionSpan;
use std::time::Instant;

/// Execute a mount_volume syscall
#[cfg(feature = "microkernel")]
pub fn mount_volume(name: &str) -> Result<()> {
    // This is a compile-time bridge to the microkernel implementation
    // When the microkernel feature is enabled, this will be linked to the actual implementation
    microkernel::syscall_engine::mount_volume(name)
}

/// Execute a ns_enter syscall
#[cfg(feature = "microkernel")]
pub fn ns_enter(pid: u32) -> Result<()> {
    // This is a compile-time bridge to the microkernel implementation
    microkernel::syscall_engine::ns_enter(pid)
}

/// Execute an audit_syscall syscall
#[cfg(feature = "microkernel")]
pub fn audit_syscall(action: &str) {
    // This is a compile-time bridge to the microkernel implementation
    microkernel::syscall_engine::audit_syscall(action);
}

/// Stub implementation for mount_volume when microkernel feature is not enabled
/// with telemetry metrics for performance monitoring
#[cfg(not(feature = "microkernel"))]
pub fn mount_volume(name: &str) -> Result<()> {
    // Start timing
    let start = Instant::now();
    
    // Create a span for this syscall
    let mut span = ExecutionSpan::new_system("mount_volume");
    span.add_attribute("syscall.name", "mount_volume".to_string());
    span.add_attribute("syscall.args", name.to_string());
    
    tracing::debug!("[MockSyscall] mount_volume (noop)");
    
    // Record execution time
    let duration = start.elapsed();
    span.add_attribute("syscall.duration_ns", duration.as_nanos() as u64);
    span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    
    #[cfg(feature = "telemetry")]
    {
        // If telemetry feature is enabled, record metrics
        if let Ok(metrics) = std::env::var("FORGE_TELEMETRY_ENABLED") {
            if metrics == "1" || metrics.to_lowercase() == "true" {
                tracing::debug!("Recording telemetry for mount_volume syscall");
            }
        }
    }
    
    Ok(())
}

/// Stub implementation for ns_enter when microkernel feature is not enabled
/// with telemetry metrics for performance monitoring
#[cfg(not(feature = "microkernel"))]
pub fn ns_enter(pid: u32) -> Result<()> {
    // Start timing
    let start = Instant::now();
    
    // Create a span for this syscall
    let mut span = ExecutionSpan::new_system("ns_enter");
    span.add_attribute("syscall.name", "ns_enter".to_string());
    span.add_attribute("syscall.args", pid.to_string());
    
    tracing::debug!("[MockSyscall] ns_enter (noop)");
    
    // Record execution time
    let duration = start.elapsed();
    span.add_attribute("syscall.duration_ns", duration.as_nanos() as u64);
    span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    
    #[cfg(feature = "telemetry")]
    {
        // If telemetry feature is enabled, record metrics
        if let Ok(metrics) = std::env::var("FORGE_TELEMETRY_ENABLED") {
            if metrics == "1" || metrics.to_lowercase() == "true" {
                tracing::debug!("Recording telemetry for ns_enter syscall");
            }
        }
    }
    
    Ok(())
}

/// Stub implementation for audit_syscall when microkernel feature is not enabled
/// with telemetry metrics for performance monitoring
#[cfg(not(feature = "microkernel"))]
pub fn audit_syscall(action: &str) {
    // Start timing
    let start = Instant::now();
    
    // Create a span for this syscall
    let mut span = ExecutionSpan::new_system("audit_syscall");
    span.add_attribute("syscall.name", "audit_syscall".to_string());
    span.add_attribute("syscall.args", action.to_string());
    
    tracing::debug!(action = %action, "[MockSyscall] audit_syscall (noop)");
    
    // Record execution time
    let duration = start.elapsed();
    span.add_attribute("syscall.duration_ns", duration.as_nanos() as u64);
    span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    
    #[cfg(feature = "telemetry")]
    {
        // If telemetry feature is enabled, record metrics
        if let Ok(metrics) = std::env::var("FORGE_TELEMETRY_ENABLED") {
            if metrics == "1" || metrics.to_lowercase() == "true" {
                tracing::debug!("Recording telemetry for audit_syscall syscall");
            }
        }
    }
}