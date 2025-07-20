//! # LLM-explainable observation system for ForgeOne
//! observer.rs
//! This module provides an LLM-explainable observation system for the ForgeOne platform.
//! It handles creating and formatting observations for LLM consumption.

use crate::identity::IdentityContext;
use crate::telemetry::TelemetrySpan;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Feature-gated syscall client integration
#[cfg(feature = "syscall-client")]
use crate::syscall_client::{SyscallAPI, SyscallClient};

// Use the SyscallClient abstraction instead of direct dependency on syscall-bridge
#[cfg(feature = "syscall-client")]
static SYSCALL: once_cell::sync::Lazy<SyscallClient> =
    once_cell::sync::Lazy::new(|| SyscallClient::new());

// Example usage in observer (if needed):
// #[cfg(feature = "syscall-client")]
// SYSCALL.audit_syscall("observer_event");

/// Trait for syscall context abstraction (to be implemented in microkernel)
pub trait SyscallContextTrait {
    fn name(&self) -> &str;
    fn result_string(&self) -> String;
}

/// The type of observation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationType {
    /// Informational observation
    Info,
    /// Warning observation
    Warning,
    /// Error observation
    Error,
    /// Debug observation
    Debug,
    /// Trace observation
    Trace,
    /// Security observation
    Security,
    /// Performance observation
    Performance,
    /// Policy observation
    Policy,
}

/// The severity of an observation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationSeverity {
    /// Informational severity
    Info,
    /// Warning severity
    Warning,
    /// Error severity
    Error,
    /// Critical severity
    Critical,
}

/// An observation for LLM consumption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// The identity context of this observation
    pub identity: IdentityContext,
    /// The type of this observation
    pub observation_type: ObservationType,
    /// The content of this observation
    pub content: String,
    /// The severity of this observation
    pub severity: ObservationSeverity,
    /// The timestamp of this observation
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Observation {
    /// Create a new observation
    pub fn new(
        identity: IdentityContext,
        observation_type: ObservationType,
        content: String,
        severity: ObservationSeverity,
    ) -> Self {
        Self {
            identity,
            observation_type,
            content,
            severity,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Convert this observation to a string for LLM consumption
    pub fn to_llm_string(&self) -> String {
        let severity_str = match self.severity {
            ObservationSeverity::Info => "INFO",
            ObservationSeverity::Warning => "WARNING",
            ObservationSeverity::Error => "ERROR",
            ObservationSeverity::Critical => "CRITICAL",
        };

        let type_str = match self.observation_type {
            ObservationType::Info => "INFO",
            ObservationType::Warning => "WARNING",
            ObservationType::Error => "ERROR",
            ObservationType::Debug => "DEBUG",
            ObservationType::Trace => "TRACE",
            ObservationType::Security => "SECURITY",
            ObservationType::Performance => "PERFORMANCE",
            ObservationType::Policy => "POLICY",
        };

        format!(
            "[{}] [{}] [{}] [{}] [{}]: {}",
            self.timestamp.to_rfc3339(),
            severity_str,
            type_str,
            self.identity.tenant_id,
            self.identity.user_id,
            self.content
        )
    }
}

/// Convert a telemetry span to an LLM-readable string
pub fn telemetry_span_to_llm_string(span: &TelemetrySpan) -> String {
    let mut result = format!(
        "Span: {} (ID: {}, Trace: {})",
        span.name, span.span_id, span.trace_id
    );

    if let Some(parent_id) = span.parent_span_id {
        result.push_str(&format!(", Parent: {}", parent_id));
    }

    result.push_str(&format!("\nStart: {}", span.start_time.to_rfc3339()));

    if let Some(end_time) = span.end_time {
        result.push_str(&format!("\nEnd: {}", end_time.to_rfc3339()));

        // Calculate duration
        let duration = end_time.signed_duration_since(span.start_time);
        result.push_str(&format!("\nDuration: {} ms", duration.num_milliseconds()));
    }

    result.push_str(&format!(
        "\nIdentity: Tenant={}, User={}",
        span.identity.tenant_id, span.identity.user_id
    ));

    if !span.attributes.is_empty() {
        result.push_str("\nAttributes:");
        for (key, value) in &span.attributes {
            result.push_str(&format!("\n  {}: {}", key, value));
        }
    }

    if !span.events.is_empty() {
        result.push_str("\nEvents:");
        for event in &span.events {
            result.push_str(&format!("\n  [{}] {}", event.time.to_rfc3339(), event.name));

            if !event.attributes.is_empty() {
                for (key, value) in &event.attributes {
                    result.push_str(&format!("\n    {}: {}", key, value));
                }
            }
        }
    }

    result
}

/// Convert a result to an LLM-readable string
pub fn result_to_llm_string<T>(
    identity: &IdentityContext,
    result: &Result<T, crate::error::ForgeError>,
) -> String
where
    T: std::fmt::Debug,
{
    match result {
        Ok(_) => format!(
            "Operation succeeded for tenant={}, user={}",
            identity.tenant_id, identity.user_id
        ),
        Err(e) => format!(
            "Operation failed for tenant={}, user={}: {:?}",
            identity.tenant_id, identity.user_id, e
        ),
    }
}

/// Record a syscall event (for tracing/audit)
pub fn record_syscall(
    syscall_name: &str,
    identity: &crate::identity::IdentityContext,
    args: &Vec<String>,
    allowed: bool,
    reason: Option<&str>,
) {
    // This is a simple implementation; expand as needed for audit/tracing
    tracing::info!(
        syscall = syscall_name,
        user_id = %identity.user_id,
        tenant_id = %identity.tenant_id,
        args = ?args,
        allowed = allowed,
        reason = ?reason,
        "Syscall record"
    );
}

pub mod trace {
    use crate::error::Result;
    use crate::identity::IdentityContext;
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecutionSpan {
        pub span_id: Uuid,
        pub trace_id: Uuid,
        pub parent_span_id: Option<Uuid>,
        pub name: String,
        pub start_time: DateTime<Utc>,
        pub end_time: Option<DateTime<Utc>>,
        pub identity: IdentityContext,
        pub attributes: HashMap<String, String>,
        pub events: Vec<SpanEvent>,
        pub metrics: HashMap<String, f64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SpanEvent {
        pub name: String,
        pub time: DateTime<Utc>,
        pub attributes: HashMap<String, String>,
    }

    impl ExecutionSpan {
        /// Create a new execution span with a system identity
        pub fn new_system(name: &str) -> Self {
            Self {
                span_id: Uuid::new_v4(),
                trace_id: Uuid::new_v4(),
                parent_span_id: None,
                name: name.to_string(),
                start_time: Utc::now(),
                end_time: None,
                identity: IdentityContext::system(),
                attributes: HashMap::new(),
                events: Vec::new(),
                metrics: HashMap::new(),
            }
        }

        /// Create a new execution span with the given identity
        pub fn new(name: &str, identity: IdentityContext) -> Self {
            Self {
                span_id: Uuid::new_v4(),
                trace_id: Uuid::new_v4(),
                parent_span_id: None,
                name: name.to_string(),
                start_time: Utc::now(),
                end_time: None,
                identity,
                attributes: HashMap::new(),
                events: Vec::new(),
                metrics: HashMap::new(),
            }
        }

        /// Add an attribute to this span
        pub fn add_attribute(&mut self, key: &str, value: String) {
            self.attributes.insert(key.to_string(), value);
        }

        /// Add a metric to this span
        pub fn add_metric(&mut self, key: &str, value: f64) {
            self.metrics.insert(key.to_string(), value);
        }

        /// Add an event to this span
        pub fn add_event(&mut self, name: &str) -> &mut SpanEvent {
            let event = SpanEvent {
                name: name.to_string(),
                time: Utc::now(),
                attributes: HashMap::new(),
            };
            self.events.push(event);
            self.events.last_mut().unwrap()
        }

        /// End this span
        pub fn end(&mut self) {
            self.end_time = Some(Utc::now());
        }

        /// Record a syscall in this span
        pub fn record_syscall<C: crate::observer::SyscallContextTrait>(&mut self, context: &C) {
            let mut attributes = HashMap::new();
            attributes.insert("syscall_name".to_string(), context.name().to_string());
            attributes.insert("result".to_string(), context.result_string());
            self.events.push(SpanEvent {
                name: format!("syscall: {}", context.name()),
                time: Utc::now(),
                attributes,
            });
        }
    }

    impl SpanEvent {
        /// Add an attribute to this event
        pub fn add_attribute(&mut self, key: &str, value: String) {
            self.attributes.insert(key.to_string(), value);
        }
    }
}
