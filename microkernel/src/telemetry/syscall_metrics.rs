//! Syscall performance and security metrics
//!
//! This module provides telemetry for syscall execution, including performance
//! metrics (latency, throughput) and security metrics (denied syscalls, policy violations).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use common::telemetry::{self, TelemetryManager};
use common::identity::IdentityContext;
use common::observer::trace::ExecutionSpan;

/// Metrics for syscall execution
pub struct SyscallMetrics {
    /// Total number of syscalls executed
    total_syscalls: AtomicU64,
    /// Total number of syscalls denied
    denied_syscalls: AtomicU64,
    /// Total number of syscalls that resulted in errors
    error_syscalls: AtomicU64,
    /// Total execution time of all syscalls (in nanoseconds)
    total_execution_time_ns: AtomicU64,
    /// Maximum execution time of a syscall (in nanoseconds)
    max_execution_time_ns: AtomicU64,
    /// Minimum execution time of a syscall (in nanoseconds)
    min_execution_time_ns: AtomicU64,
    /// Syscall counts by type
    syscall_counts: Arc<RwLock<HashMap<String, u64>>>,
    /// Syscall errors by type
    syscall_errors: Arc<RwLock<HashMap<String, u64>>>,
    /// Syscall denials by identity
    identity_denials: Arc<RwLock<HashMap<String, u64>>>,
}

impl SyscallMetrics {
    /// Create a new SyscallMetrics instance
    pub fn new() -> Self {
        Self {
            total_syscalls: AtomicU64::new(0),
            denied_syscalls: AtomicU64::new(0),
            error_syscalls: AtomicU64::new(0),
            total_execution_time_ns: AtomicU64::new(0),
            max_execution_time_ns: AtomicU64::new(0),
            min_execution_time_ns: AtomicU64::new(u64::MAX),
            syscall_counts: Arc::new(RwLock::new(HashMap::new())),
            syscall_errors: Arc::new(RwLock::new(HashMap::new())),
            identity_denials: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a successful syscall execution
    pub fn record_syscall(
        &self,
        syscall_type: &str,
        identity: &IdentityContext,
        duration: Duration,
        span: &mut ExecutionSpan,
    ) {
        // Increment total syscalls
        self.total_syscalls.fetch_add(1, Ordering::Relaxed);

        // Record execution time
        let duration_ns = duration.as_nanos() as u64;
        self.total_execution_time_ns.fetch_add(duration_ns, Ordering::Relaxed);

        // Update max execution time
        let mut current_max = self.max_execution_time_ns.load(Ordering::Relaxed);
        while duration_ns > current_max {
            match self.max_execution_time_ns.compare_exchange(
                current_max,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_max) => current_max = new_max,
            }
        }

        // Update min execution time
        let mut current_min = self.min_execution_time_ns.load(Ordering::Relaxed);
        while duration_ns < current_min {
            match self.min_execution_time_ns.compare_exchange(
                current_min,
                duration_ns,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(new_min) => current_min = new_min,
            }
        }

        // Increment syscall count by type
        {
            let mut counts = self.syscall_counts.write().unwrap();
            *counts.entry(syscall_type.to_string()).or_insert(0) += 1;
        }

        // Record telemetry metrics
        let telemetry = telemetry::get_telemetry_manager();
        
        // Record syscall count
        telemetry.increment_counter("syscall.count", 1, Some(vec![
            ("syscall_type".to_string(), syscall_type.to_string()),
            ("tenant".to_string(), identity.tenant.clone()),
        ]));
        
        // Record syscall duration
        telemetry.record_histogram("syscall.duration_ms", duration.as_millis() as f64, Some(vec![
            ("syscall_type".to_string(), syscall_type.to_string()),
            ("tenant".to_string(), identity.tenant.clone()),
        ]));

        // Record in the execution span
        span.add_attribute("syscall.type", syscall_type.to_string());
        span.add_attribute("syscall.duration_ns", duration_ns.to_string());
        span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    }

    /// Record a denied syscall
    pub fn record_denied_syscall(
        &self,
        syscall_type: &str,
        identity: &IdentityContext,
        span: &mut ExecutionSpan,
    ) {
        // Increment denied syscalls
        self.denied_syscalls.fetch_add(1, Ordering::Relaxed);

        // Increment identity denials
        {
            let mut denials = self.identity_denials.write().unwrap();
            let identity_key = format!("{}/{}", identity.tenant, identity.user);
            *denials.entry(identity_key).or_insert(0) += 1;
        }

        // Record telemetry metrics
        let telemetry = telemetry::get_telemetry_manager();
        
        // Record denied syscall
        telemetry.increment_counter("syscall.denied", 1, Some(vec![
            ("syscall_type".to_string(), syscall_type.to_string()),
            ("tenant".to_string(), identity.tenant.clone()),
            ("user".to_string(), identity.user.clone()),
            ("trust_vector".to_string(), format!("{:?}", identity.trust_vector)),
        ]));

        // Record in the execution span
        span.add_attribute("syscall.denied", "true".to_string());
        span.add_attribute("syscall.type", syscall_type.to_string());
        span.add_attribute("syscall.trust_vector", format!("{:?}", identity.trust_vector));
        span.add_metric("syscall.denied", 1.0);
    }

    /// Record a syscall that resulted in an error
    pub fn record_error_syscall(
        &self,
        syscall_type: &str,
        error: &str,
        identity: &IdentityContext,
        duration: Duration,
        span: &mut ExecutionSpan,
    ) {
        // Increment error syscalls
        self.error_syscalls.fetch_add(1, Ordering::Relaxed);

        // Record execution time
        let duration_ns = duration.as_nanos() as u64;
        self.total_execution_time_ns.fetch_add(duration_ns, Ordering::Relaxed);

        // Increment syscall errors by type
        {
            let mut errors = self.syscall_errors.write().unwrap();
            *errors.entry(syscall_type.to_string()).or_insert(0) += 1;
        }

        // Record telemetry metrics
        let telemetry = telemetry::get_telemetry_manager();
        
        // Record error syscall
        telemetry.increment_counter("syscall.error", 1, Some(vec![
            ("syscall_type".to_string(), syscall_type.to_string()),
            ("tenant".to_string(), identity.tenant.clone()),
            ("error".to_string(), error.to_string()),
        ]));
        
        // Record syscall duration
        telemetry.record_histogram("syscall.error_duration_ms", duration.as_millis() as f64, Some(vec![
            ("syscall_type".to_string(), syscall_type.to_string()),
            ("tenant".to_string(), identity.tenant.clone()),
        ]));

        // Record in the execution span
        span.add_attribute("syscall.error", "true".to_string());
        span.add_attribute("syscall.type", syscall_type.to_string());
        span.add_attribute("syscall.error_message", error.to_string());
        span.add_attribute("syscall.duration_ns", duration_ns.to_string());
        span.add_metric("syscall.error", 1.0);
        span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    }

    /// Get the average execution time of syscalls
    pub fn average_execution_time(&self) -> Duration {
        let total_syscalls = self.total_syscalls.load(Ordering::Relaxed);
        if total_syscalls == 0 {
            return Duration::from_nanos(0);
        }

        let total_time = self.total_execution_time_ns.load(Ordering::Relaxed);
        Duration::from_nanos(total_time / total_syscalls)
    }

    /// Get the maximum execution time of syscalls
    pub fn max_execution_time(&self) -> Duration {
        let max_time = self.max_execution_time_ns.load(Ordering::Relaxed);
        if max_time == u64::MAX {
            return Duration::from_nanos(0);
        }
        Duration::from_nanos(max_time)
    }

    /// Get the minimum execution time of syscalls
    pub fn min_execution_time(&self) -> Duration {
        let min_time = self.min_execution_time_ns.load(Ordering::Relaxed);
        if min_time == u64::MAX {
            return Duration::from_nanos(0);
        }
        Duration::from_nanos(min_time)
    }

    /// Get the total number of syscalls executed
    pub fn total_syscalls(&self) -> u64 {
        self.total_syscalls.load(Ordering::Relaxed)
    }

    /// Get the total number of syscalls denied
    pub fn denied_syscalls(&self) -> u64 {
        self.denied_syscalls.load(Ordering::Relaxed)
    }

    /// Get the total number of syscalls that resulted in errors
    pub fn error_syscalls(&self) -> u64 {
        self.error_syscalls.load(Ordering::Relaxed)
    }

    /// Get the syscall counts by type
    pub fn syscall_counts(&self) -> HashMap<String, u64> {
        self.syscall_counts.read().unwrap().clone()
    }

    /// Get the syscall errors by type
    pub fn syscall_errors(&self) -> HashMap<String, u64> {
        self.syscall_errors.read().unwrap().clone()
    }

    /// Get the identity denials
    pub fn identity_denials(&self) -> HashMap<String, u64> {
        self.identity_denials.read().unwrap().clone()
    }

    /// Register metrics with the telemetry manager
    pub fn register_metrics(&self) {
        let telemetry = telemetry::get_telemetry_manager();
        
        // Register gauges for current metrics
        telemetry.record_gauge("syscall.total", self.total_syscalls() as f64, None);
        telemetry.record_gauge("syscall.denied", self.denied_syscalls() as f64, None);
        telemetry.record_gauge("syscall.errors", self.error_syscalls() as f64, None);
        telemetry.record_gauge("syscall.avg_duration_ms", self.average_execution_time().as_millis() as f64, None);
        telemetry.record_gauge("syscall.max_duration_ms", self.max_execution_time().as_millis() as f64, None);
        telemetry.record_gauge("syscall.min_duration_ms", self.min_execution_time().as_millis() as f64, None);
    }
}

/// Global syscall metrics instance
static mut SYSCALL_METRICS: Option<SyscallMetrics> = None;

/// Initialize syscall metrics
pub fn init_syscall_metrics() {
    unsafe {
        if SYSCALL_METRICS.is_none() {
            SYSCALL_METRICS = Some(SyscallMetrics::new());
        }
    }
}

/// Get the global syscall metrics instance
pub fn get_syscall_metrics() -> &'static SyscallMetrics {
    unsafe {
        if SYSCALL_METRICS.is_none() {
            init_syscall_metrics();
        }
        SYSCALL_METRICS.as_ref().unwrap()
    }
}

/// Measure the execution time of a syscall and record metrics
pub fn measure_syscall<F, R>(
    syscall_type: &str,
    identity: &IdentityContext,
    span: &mut ExecutionSpan,
    f: F,
) -> R
where
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    // Record the syscall in the span
    span.record_syscall(syscall_type, &format!("{:?}", result));
    
    // Record metrics
    get_syscall_metrics().record_syscall(syscall_type, identity, duration, span);
    
    result
}

/// Record a denied syscall
pub fn record_denied_syscall(
    syscall_type: &str,
    identity: &IdentityContext,
    span: &mut ExecutionSpan,
) {
    get_syscall_metrics().record_denied_syscall(syscall_type, identity, span);
}

/// Record a syscall that resulted in an error
pub fn record_error_syscall(
    syscall_type: &str,
    error: &str,
    identity: &IdentityContext,
    duration: Duration,
    span: &mut ExecutionSpan,
) {
    get_syscall_metrics().record_error_syscall(syscall_type, error, identity, duration, span);
}