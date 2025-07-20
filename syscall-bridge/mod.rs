//! Syscall Bridge Module (Standalone)
//!
//! This module provides a compile-time bridge between the common crate and the microkernel.
//! It allows for feature-gated syscall operations without direct dependency on the microkernel.
//! 
//! This is the standalone version of the syscall-bridge that can be used by external crates.
//! It provides the same functionality as the microkernel's syscall_bridge module.
//!
//! The bridge also integrates with telemetry metrics for syscall performance monitoring.

use common::syscall_client::SyscallAPI;
use common::error::Result;
use common::observer::trace::ExecutionSpan;
use std::time::Instant;

/// Use the actual SyscallEngine when the microkernel feature is enabled
#[cfg(feature = "microkernel")]
pub use microkernel::syscall_engine::SyscallEngine as ActiveSyscall;

/// MockSyscall implementation for when the microkernel feature is not enabled
#[cfg(not(feature = "microkernel"))]
pub struct MockSyscall;

#[cfg(not(feature = "microkernel"))]
impl common::syscall_client::SyscallAPI for MockSyscall {
    fn mount_volume(&self, name: &str) -> Result<()> {
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
    
    fn ns_enter(&self, pid: u32) -> Result<()> {
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
    
    fn audit_syscall(&self, action: &str) {
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
}

/// Use MockSyscall as ActiveSyscall when the microkernel feature is not enabled
#[cfg(not(feature = "microkernel"))]
pub use MockSyscall as ActiveSyscall;
