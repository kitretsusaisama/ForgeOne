//! Telemetry module for the microkernel
//!
//! This module provides telemetry functionality for the microkernel, including
//! performance metrics, syscall statistics, and integration with tracing.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use common::observer::trace::ExecutionSpan;
use common::error::Result;
use crate::execution::syscall::SyscallContext;

/// Global instance of syscall metrics
static mut SYSCALL_METRICS: Option<SyscallMetrics> = None;
static METRICS_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize the syscall metrics
pub fn init_syscall_metrics() {
    if !METRICS_INITIALIZED.load(Ordering::SeqCst) {
        unsafe {
            SYSCALL_METRICS = Some(SyscallMetrics::new());
        }
        METRICS_INITIALIZED.store(true, Ordering::SeqCst);
    }
}

/// Get the syscall metrics instance
pub fn get_syscall_metrics() -> &'static SyscallMetrics {
    if !METRICS_INITIALIZED.load(Ordering::SeqCst) {
        init_syscall_metrics();
    }
    
    unsafe {
        SYSCALL_METRICS.as_ref().unwrap()
    }
}

/// Record a denied syscall in telemetry
pub fn record_denied_syscall(context: &SyscallContext, span: &mut ExecutionSpan) {
    let metrics = get_syscall_metrics();
    metrics.increment_denied_syscalls();
    
    // Add span attributes for the denied syscall
    span.add_attribute("syscall.denied", true);
    span.add_attribute("syscall.name", context.syscall_name.clone());
    span.add_attribute("syscall.type", format!("{:?}", context.syscall_type));
    
    // Record the syscall in the metrics
    metrics.record_syscall_attempt(context.syscall_name.clone());
}

/// Record an error syscall in telemetry
pub fn record_error_syscall(context: &SyscallContext, error: &str, span: &mut ExecutionSpan) {
    let metrics = get_syscall_metrics();
    metrics.increment_error_syscalls();
    
    // Add span attributes for the error syscall
    span.add_attribute("syscall.error", true);
    span.add_attribute("syscall.error_message", error.to_string());
    span.add_attribute("syscall.name", context.syscall_name.clone());
    span.add_attribute("syscall.type", format!("{:?}", context.syscall_type));
    
    // Record the syscall in the metrics
    metrics.record_syscall_attempt(context.syscall_name.clone());
}

/// Measure the execution time of a syscall and return the result
pub fn measure_syscall<F, T>(context: &SyscallContext, span: &mut ExecutionSpan, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    // Record the syscall execution time
    let metrics = get_syscall_metrics();
    metrics.record_execution_time(duration);
    
    // Add span attributes for the syscall
    span.add_attribute("syscall.duration_ns", duration.as_nanos() as u64);
    span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
    
    result
}

/// Syscall metrics for the microkernel
#[derive(Debug)]
pub struct SyscallMetrics {
    /// Total number of syscalls
    total_syscalls: AtomicU64,
    
    /// Number of denied syscalls
    denied_syscalls: AtomicU64,
    
    /// Number of syscalls that resulted in an error
    error_syscalls: AtomicU64,
    
    /// Total execution time of all syscalls
    total_execution_time: Mutex<Duration>,
    
    /// Minimum execution time of any syscall
    min_execution_time: Mutex<Option<Duration>>,
    
    /// Maximum execution time of any syscall
    max_execution_time: Mutex<Option<Duration>>,
    
    /// Counts of each syscall type
    syscall_counts: RwLock<HashMap<String, u64>>,
    
    /// Execution times for each syscall type
    syscall_execution_times: RwLock<HashMap<String, Vec<Duration>>>,
}

impl SyscallMetrics {
    /// Create a new instance of syscall metrics
    pub fn new() -> Self {
        Self {
            total_syscalls: AtomicU64::new(0),
            denied_syscalls: AtomicU64::new(0),
            error_syscalls: AtomicU64::new(0),
            total_execution_time: Mutex::new(Duration::from_nanos(0)),
            min_execution_time: Mutex::new(None),
            max_execution_time: Mutex::new(None),
            syscall_counts: RwLock::new(HashMap::new()),
            syscall_execution_times: RwLock::new(HashMap::new()),
        }
    }
    
    /// Record a successful syscall
    pub fn record_syscall(&self, context: &SyscallContext, duration: Duration, span: &mut ExecutionSpan) {
        // Increment the total syscall count
        self.increment_total_syscalls();
        
        // Record the syscall execution time
        self.record_execution_time(duration);
        
        // Record the syscall type
        self.record_syscall_attempt(context.syscall_name.clone());
        
        // Add span attributes for the syscall
        span.add_attribute("syscall.name", context.syscall_name.clone());
        span.add_attribute("syscall.type", format!("{:?}", context.syscall_type));
        span.add_attribute("syscall.duration_ns", duration.as_nanos() as u64);
        span.add_metric("syscall.duration_ms", duration.as_millis() as f64);
        
        // Record the syscall execution time for this specific syscall type
        let mut execution_times = self.syscall_execution_times.write().unwrap();
        execution_times
            .entry(context.syscall_name.clone())
            .or_insert_with(Vec::new)
            .push(duration);
    }
    
    /// Record a syscall attempt (successful or not)
    pub fn record_syscall_attempt(&self, syscall_name: String) {
        let mut counts = self.syscall_counts.write().unwrap();
        *counts.entry(syscall_name).or_insert(0) += 1;
    }
    
    /// Record the execution time of a syscall
    pub fn record_execution_time(&self, duration: Duration) {
        // Update the total execution time
        let mut total_time = self.total_execution_time.lock().unwrap();
        *total_time += duration;
        
        // Update the minimum execution time
        let mut min_time = self.min_execution_time.lock().unwrap();
        match *min_time {
            Some(t) if duration < t => *min_time = Some(duration),
            None => *min_time = Some(duration),
            _ => {}
        }
        
        // Update the maximum execution time
        let mut max_time = self.max_execution_time.lock().unwrap();
        match *max_time {
            Some(t) if duration > t => *max_time = Some(duration),
            None => *max_time = Some(duration),
            _ => {}
        }
    }
    
    /// Increment the total syscall count
    pub fn increment_total_syscalls(&self) {
        self.total_syscalls.fetch_add(1, Ordering::SeqCst);
    }
    
    /// Increment the denied syscall count
    pub fn increment_denied_syscalls(&self) {
        self.denied_syscalls.fetch_add(1, Ordering::SeqCst);
    }
    
    /// Increment the error syscall count
    pub fn increment_error_syscalls(&self) {
        self.error_syscalls.fetch_add(1, Ordering::SeqCst);
    }
    
    /// Get the total number of syscalls
    pub fn total_syscalls(&self) -> u64 {
        self.total_syscalls.load(Ordering::SeqCst)
    }
    
    /// Get the number of denied syscalls
    pub fn denied_syscalls(&self) -> u64 {
        self.denied_syscalls.load(Ordering::SeqCst)
    }
    
    /// Get the number of syscalls that resulted in an error
    pub fn error_syscalls(&self) -> u64 {
        self.error_syscalls.load(Ordering::SeqCst)
    }
    
    /// Get the total execution time of all syscalls
    pub fn total_execution_time(&self) -> Duration {
        *self.total_execution_time.lock().unwrap()
    }
    
    /// Get the average execution time of all syscalls
    pub fn average_execution_time(&self) -> Option<Duration> {
        let total_syscalls = self.total_syscalls();
        if total_syscalls == 0 {
            return None;
        }
        
        let total_time = self.total_execution_time();
        Some(total_time / total_syscalls as u32)
    }
    
    /// Get the minimum execution time of any syscall
    pub fn min_execution_time(&self) -> Option<Duration> {
        *self.min_execution_time.lock().unwrap()
    }
    
    /// Get the maximum execution time of any syscall
    pub fn max_execution_time(&self) -> Option<Duration> {
        *self.max_execution_time.lock().unwrap()
    }
    
    /// Get the counts of each syscall type
    pub fn syscall_counts(&self) -> HashMap<String, u64> {
        self.syscall_counts.read().unwrap().clone()
    }
    
    /// Get the average execution time for a specific syscall type
    pub fn average_execution_time_for_syscall(&self, syscall_name: &str) -> Option<Duration> {
        let execution_times = self.syscall_execution_times.read().unwrap();
        let times = execution_times.get(syscall_name)?;
        
        if times.is_empty() {
            return None;
        }
        
        let total_time = times.iter().sum::<Duration>();
        Some(total_time / times.len() as u32)
    }
    
    /// Register metrics with the telemetry manager
    pub fn register_metrics(&self) {
        // In a real implementation, this would register metrics with a telemetry manager
        // such as Prometheus, OpenTelemetry, or a custom metrics system.
        // For now, we'll just log the metrics.
        println!("Registered syscall metrics with telemetry manager");
        println!("Total syscalls: {}", self.total_syscalls());
        println!("Denied syscalls: {}", self.denied_syscalls());
        println!("Error syscalls: {}", self.error_syscalls());
        
        if let Some(avg_time) = self.average_execution_time() {
            println!("Average execution time: {:?}", avg_time);
        }
        
        if let Some(min_time) = self.min_execution_time() {
            println!("Minimum execution time: {:?}", min_time);
        }
        
        if let Some(max_time) = self.max_execution_time() {
            println!("Maximum execution time: {:?}", max_time);
        }
        
        println!("Syscall counts: {:?}", self.syscall_counts());
    }
    
    /// Reset all metrics
    pub fn reset(&self) {
        self.total_syscalls.store(0, Ordering::SeqCst);
        self.denied_syscalls.store(0, Ordering::SeqCst);
        self.error_syscalls.store(0, Ordering::SeqCst);
        
        *self.total_execution_time.lock().unwrap() = Duration::from_nanos(0);
        *self.min_execution_time.lock().unwrap() = None;
        *self.max_execution_time.lock().unwrap() = None;
        
        self.syscall_counts.write().unwrap().clear();
        self.syscall_execution_times.write().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::syscall::{SyscallContext, SyscallType};
    
    #[test]
    fn test_syscall_metrics_initialization() {
        // Initialize syscall metrics
        init_syscall_metrics();
        
        // Get the syscall metrics instance
        let metrics = get_syscall_metrics();
        
        // Verify initial state
        assert_eq!(metrics.total_syscalls(), 0);
        assert_eq!(metrics.denied_syscalls(), 0);
        assert_eq!(metrics.error_syscalls(), 0);
        assert_eq!(metrics.total_execution_time(), Duration::from_nanos(0));
        assert_eq!(metrics.min_execution_time(), None);
        assert_eq!(metrics.max_execution_time(), None);
        assert!(metrics.syscall_counts().is_empty());
    }
    
    #[test]
    fn test_record_syscall() {
        // Initialize syscall metrics
        init_syscall_metrics();
        let metrics = get_syscall_metrics();
        metrics.reset();
        
        // Create a syscall context
        let context = SyscallContext {
            syscall_name: "test_syscall".to_string(),
            syscall_type: SyscallType::File,
            args: vec!["arg1".to_string(), "arg2".to_string()],
            identity: Arc::new(common::identity::IdentityContext::root()),
            policy_decision: None,
            execution_time: None,
            result: None,
        };
        
        // Create a span
        let mut span = ExecutionSpan::new(&context.identity, "test-span");
        
        // Record a syscall
        let duration = Duration::from_millis(10);
        metrics.record_syscall(&context, duration, &mut span);
        
        // Verify metrics
        assert_eq!(metrics.total_syscalls(), 1);
        assert_eq!(metrics.denied_syscalls(), 0);
        assert_eq!(metrics.error_syscalls(), 0);
        assert_eq!(metrics.total_execution_time(), duration);
        assert_eq!(metrics.min_execution_time(), Some(duration));
        assert_eq!(metrics.max_execution_time(), Some(duration));
        
        // Verify syscall counts
        let counts = metrics.syscall_counts();
        assert_eq!(counts.get("test_syscall"), Some(&1));
        
        // Verify span attributes
        assert_eq!(span.get_attribute("syscall.name"), Some(&"test_syscall".to_string()));
        assert_eq!(span.get_attribute("syscall.type"), Some(&"File".to_string()));
        assert_eq!(span.get_attribute("syscall.duration_ns"), Some(&(duration.as_nanos() as u64)));
        assert_eq!(span.get_metric("syscall.duration_ms"), Some(&(duration.as_millis() as f64)));
    }
    
    #[test]
    fn test_record_multiple_syscalls() {
        // Initialize syscall metrics
        init_syscall_metrics();
        let metrics = get_syscall_metrics();
        metrics.reset();
        
        // Create a syscall context
        let context1 = SyscallContext {
            syscall_name: "test_syscall1".to_string(),
            syscall_type: SyscallType::File,
            args: vec!["arg1".to_string(), "arg2".to_string()],
            identity: Arc::new(common::identity::IdentityContext::root()),
            policy_decision: None,
            execution_time: None,
            result: None,
        };
        
        let context2 = SyscallContext {
            syscall_name: "test_syscall2".to_string(),
            syscall_type: SyscallType::Network,
            args: vec!["arg1".to_string(), "arg2".to_string()],
            identity: Arc::new(common::identity::IdentityContext::root()),
            policy_decision: None,
            execution_time: None,
            result: None,
        };
        
        // Create a span
        let mut span = ExecutionSpan::new(&context1.identity, "test-span");
        
        // Record syscalls with different durations
        let duration1 = Duration::from_millis(10);
        let duration2 = Duration::from_millis(20);
        
        metrics.record_syscall(&context1, duration1, &mut span);
        metrics.record_syscall(&context2, duration2, &mut span);
        
        // Verify metrics
        assert_eq!(metrics.total_syscalls(), 2);
        assert_eq!(metrics.total_execution_time(), duration1 + duration2);
        assert_eq!(metrics.min_execution_time(), Some(duration1));
        assert_eq!(metrics.max_execution_time(), Some(duration2));
        
        // Verify syscall counts
        let counts = metrics.syscall_counts();
        assert_eq!(counts.get("test_syscall1"), Some(&1));
        assert_eq!(counts.get("test_syscall2"), Some(&1));
        
        // Verify average execution time
        assert_eq!(metrics.average_execution_time(), Some((duration1 + duration2) / 2));
        
        // Verify average execution time for specific syscalls
        assert_eq!(metrics.average_execution_time_for_syscall("test_syscall1"), Some(duration1));
        assert_eq!(metrics.average_execution_time_for_syscall("test_syscall2"), Some(duration2));
    }
    
    #[test]
    fn test_record_denied_syscall() {
        // Initialize syscall metrics
        init_syscall_metrics();
        let metrics = get_syscall_metrics();
        metrics.reset();
        
        // Create a syscall context
        let context = SyscallContext {
            syscall_name: "test_syscall".to_string(),
            syscall_type: SyscallType::File,
            args: vec!["arg1".to_string(), "arg2".to_string()],
            identity: Arc::new(common::identity::IdentityContext::root()),
            policy_decision: None,
            execution_time: None,
            result: None,
        };
        
        // Create a span
        let mut span = ExecutionSpan::new(&context.identity, "test-span");
        
        // Record a denied syscall
        record_denied_syscall(&context, &mut span);
        
        // Verify metrics
        assert_eq!(metrics.total_syscalls(), 0); // Total syscalls not incremented for denied
        assert_eq!(metrics.denied_syscalls(), 1);
        assert_eq!(metrics.error_syscalls(), 0);
        
        // Verify syscall counts
        let counts = metrics.syscall_counts();
        assert_eq!(counts.get("test_syscall"), Some(&1));
        
        // Verify span attributes
        assert_eq!(span.get_attribute("syscall.denied"), Some(&true));
        assert_eq!(span.get_attribute("syscall.name"), Some(&"test_syscall".to_string()));
        assert_eq!(span.get_attribute("syscall.type"), Some(&"File".to_string()));
    }
    
    #[test]
    fn test_record_error_syscall() {
        // Initialize syscall metrics
        init_syscall_metrics();
        let metrics = get_syscall_metrics();
        metrics.reset();
        
        // Create a syscall context
        let context = SyscallContext {
            syscall_name: "test_syscall".to_string(),
            syscall_type: SyscallType::File,
            args: vec!["arg1".to_string(), "arg2".to_string()],
            identity: Arc::new(common::identity::IdentityContext::root()),
            policy_decision: None,
            execution_time: None,
            result: None,
        };
        
        // Create a span
        let mut span = ExecutionSpan::new(&context.identity, "test-span");
        
        // Record an error syscall
        record_error_syscall(&context, "test error", &mut span);
        
        // Verify metrics
        assert_eq!(metrics.total_syscalls(), 0); // Total syscalls not incremented for errors
        assert_eq!(metrics.denied_syscalls(), 0);
        assert_eq!(metrics.error_syscalls(), 1);
        
        // Verify syscall counts
        let counts = metrics.syscall_counts();
        assert_eq!(counts.get("test_syscall"), Some(&1));
        
        // Verify span attributes
        assert_eq!(span.get_attribute("syscall.error"), Some(&true));
        assert_eq!(span.get_attribute("syscall.error_message"), Some(&"test error".to_string()));
        assert_eq!(span.get_attribute("syscall.name"), Some(&"test_syscall".to_string()));
        assert_eq!(span.get_attribute("syscall.type"), Some(&"File".to_string()));
    }
    
    #[test]
    fn test_measure_syscall() {
        // Initialize syscall metrics
        init_syscall_metrics();
        let metrics = get_syscall_metrics();
        metrics.reset();
        
        // Create a syscall context
        let context = SyscallContext {
            syscall_name: "test_syscall".to_string(),
            syscall_type: SyscallType::File,
            args: vec!["arg1".to_string(), "arg2".to_string()],
            identity: Arc::new(common::identity::IdentityContext::root()),
            policy_decision: None,
            execution_time: None,
            result: None,
        };
        
        // Create a span
        let mut span = ExecutionSpan::new(&context.identity, "test-span");
        
        // Measure a syscall
        let result: Result<i32> = measure_syscall(&context, &mut span, || {
            // Simulate some work
            std::thread::sleep(Duration::from_millis(1));
            Ok(42)
        });
        
        // Verify result
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        
        // Verify metrics
        assert!(metrics.total_execution_time() > Duration::from_nanos(0));
        assert!(metrics.min_execution_time().is_some());
        assert!(metrics.max_execution_time().is_some());
        
        // Verify span attributes
        assert!(span.get_attribute("syscall.duration_ns").is_some());
        assert!(span.get_metric("syscall.duration_ms").is_some());
    }
}