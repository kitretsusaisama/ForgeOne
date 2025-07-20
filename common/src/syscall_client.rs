use crate::error::Result;
use crate::observer::trace::ExecutionSpan;
use std::time::Instant;

/// Trait for abstracting syscall operations across boundaries.
pub trait SyscallAPI {
    fn mount_volume(&self, name: &str) -> Result<()>;
    fn ns_enter(&self, pid: u32) -> Result<()>;
    fn audit_syscall(&self, action: &str);
}

/// SyscallClient provides a compile-time abstraction for syscall operations.
/// This implementation allows for feature-gated syscall operations without
/// direct dependency on the microkernel or syscall-bridge.
pub struct SyscallClient;

impl SyscallClient {
    /// Create a new SyscallClient instance
    pub fn new() -> Self {
        Self {}
    }
}

/// Default implementation that does nothing when syscall-client feature is not enabled
/// but still records telemetry metrics for performance monitoring
#[cfg(not(feature = "microkernel"))]
impl SyscallAPI for SyscallClient {
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
        span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
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
        span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
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
        span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
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

/// When microkernel feature is enabled, forward to the actual implementation
/// while still recording telemetry metrics for performance monitoring
#[cfg(feature = "microkernel")]
impl SyscallAPI for SyscallClient {
    fn mount_volume(&self, name: &str) -> Result<()> {
        // Start timing
        let start = Instant::now();

        // Create a span for this syscall
        let mut span = ExecutionSpan::new_system("mount_volume");
        span.add_attribute("syscall.name", "mount_volume".to_string());
        span.add_attribute("syscall.args", name.to_string());

        // At compile time, this will be linked to the actual implementation
        // in the microkernel crate when the feature is enabled
        let result = crate::syscall::mount_volume(name);

        // Record execution time
        let duration = start.elapsed();
        span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
        span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
        span.add_attribute("syscall.result", format!("{:?}", result.is_ok()));

        if let Err(ref e) = result {
            span.add_attribute("syscall.error", format!("{:?}", e));
        }

        result
    }

    fn ns_enter(&self, pid: u32) -> Result<()> {
        // Start timing
        let start = Instant::now();

        // Create a span for this syscall
        let mut span = ExecutionSpan::new_system("ns_enter");
        span.add_attribute("syscall.name", "ns_enter".to_string());
        span.add_attribute("syscall.args", pid.to_string());

        // Forward to actual implementation
        let result = crate::syscall::ns_enter(pid);

        // Record execution time
        let duration = start.elapsed();
        span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
        span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
        span.add_attribute("syscall.result", format!("{:?}", result.is_ok()));

        if let Err(ref e) = result {
            span.add_attribute("syscall.error", format!("{:?}", e));
        }

        result
    }

    fn audit_syscall(&self, action: &str) {
        // Start timing
        let start = Instant::now();

        // Create a span for this syscall
        let mut span = ExecutionSpan::new_system("audit_syscall");
        span.add_attribute("syscall.name", "audit_syscall".to_string());
        span.add_attribute("syscall.args", action.to_string());

        // Forward to actual implementation
        crate::syscall::audit_syscall(action);

        // Record execution time
        let duration = start.elapsed();
        span.add_attribute("syscall.duration_ns", duration.as_nanos().to_string());
        span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    }
}
