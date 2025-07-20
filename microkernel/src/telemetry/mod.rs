//! Telemetry for the microkernel
//!
//! This module provides telemetry for the microkernel, including performance
//! metrics, security metrics, and health checks.

pub mod syscall_metrics;

pub use syscall_metrics::{init_syscall_metrics, get_syscall_metrics, measure_syscall, record_denied_syscall, record_error_syscall};