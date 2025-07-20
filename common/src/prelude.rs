//! # Prelude for ForgeOne
//! prelaude.rs
//! This module provides a type-safe, controlled global interface for the ForgeOne platform.
//! It re-exports commonly used types and functions for easy access.

use crate::diagnostics::HealthStatus;

pub use crate::diagnostics::DiagnosticError;
// Re-export error types
pub use crate::error::{ForgeError, Result, TraceableError};

// Re-export identity types
pub use crate::identity::{IdentityContext, TrustVector};

// Re-export policy types
pub use crate::policy::{PolicyEffect, PolicyRule, PolicySet};

// Re-export trust types
pub use crate::trust::{ZtaNode, ZtaPolicyGraph};

// Re-export telemetry types
pub use crate::telemetry::{TelemetrySpan, TelemetryEvent};

// Re-export observer types
pub use crate::observer::{Observation, ObservationType, ObservationSeverity};

// Re-export diagnostics types
pub use crate::diagnostics::{DiagnosticReport};

// Re-export audit types
pub use crate::audit::{AuditEvent, AuditOutcome, AuditLog, AuditCategory, AuditSeverity};

// Re-export config types
pub use crate::config::{ForgeConfig, SignedConfig};

// Re-export macros
pub use crate::{autolog, trace_id, enforce_zta, telemetry_span, audit_event, observe};

// Re-export initialization functions
pub use crate::{init, init_with_config};

/// Initialize the common crate with default configuration
pub fn initialize() -> Result<()> {
    crate::init()
}

/// Initialize the common crate with custom configuration
pub fn initialize_with_config(config_path: &str) -> Result<()> {
    crate::init_with_config(config_path)
}

/// Run diagnostics on the system
pub async fn run_diagnostics(identity: &IdentityContext) -> std::result::Result<DiagnosticReport, DiagnosticError> {
    crate::diagnostics::run_system_diagnostics(identity).await
}

/// Check the health of the system
/// Returns `true` if the system is healthy, `false` otherwise
pub async fn check_health() -> bool {
    match crate::diagnostics::check_health().await {
        Ok(health_status) => health_status == HealthStatus::Healthy,
        Err(_) => false,  // Consider logging the error in a real implementation
    }
}

/// Generate a new trace ID
pub fn generate_trace_id() -> uuid::Uuid {
    crate::telemetry::generate_trace_id()
}

/// Explain a result for an agent
pub fn explain_for_agent(identity: &IdentityContext, outcome: Result<()>) -> String {
    crate::observer::result_to_llm_string(identity, &outcome)
}

/// Explain a telemetry span for an agent
pub fn explain_span_for_agent(span: &TelemetrySpan) -> String {
    crate::observer::telemetry_span_to_llm_string(span)
}

/// Create a new audit event
pub fn create_audit_event(
    identity: IdentityContext,
    action: String,
    resource: String,
    outcome: AuditOutcome,
    category: AuditCategory,
    severity: AuditSeverity,
    details: Option<serde_json::Value>,
) -> AuditEvent {
    crate::audit::create_audit_event(identity, action, resource, outcome, category, severity, details)
}
/// Verify the signature of an audit event
pub fn verify_event_signature(event: &AuditEvent, public_key: &[u8]) -> Result<bool> {
    crate::audit::verify_event_signature(event, public_key)
}

/// Generate a new key pair
pub fn generate_key_pair() -> Result<crate::crypto::KeyPair> {
    crate::crypto::generate_key_pair()
}

/// Sign data with a private key
pub fn sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    crate::crypto::sign(data, private_key)
}

/// Verify a signature
pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    crate::crypto::verify(data, signature, public_key)
}

/// Generate a device fingerprint
pub fn generate_device_fingerprint() -> String {
    crate::crypto::generate_device_fingerprint()
}

/// Generate a secure random token
pub fn generate_token(length: usize) -> String {
    crate::crypto::generate_token(length)
}

/// Hash data with SHA-256
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    crate::crypto::hash_sha256(data)
}