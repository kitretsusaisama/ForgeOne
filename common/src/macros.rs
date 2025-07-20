//! # Macros for ForgeOne
//!
//! This module provides macros for the ForgeOne platform.
//! It includes macros for logging, tracing, and policy enforcement.

/// Log a message with the current identity context
#[macro_export]
macro_rules! autolog {
    ($level:expr, $identity:expr, $($arg:tt)+) => {
        tracing::event!(
            $level,
            user_id = %$identity.user_id,
            tenant_id = %$identity.tenant_id,
            request_id = %$identity.request_id,
            trust_vector = ?$identity.trust_vector,
            $($arg)+
        );
    };
}

/// Generate a trace ID for the current context
#[macro_export]
macro_rules! trace_id {
    () => {
        uuid::Uuid::new_v4()
    };
}

/// Enforce a Zero Trust policy
#[macro_export]
macro_rules! enforce_zta {
    ($identity:expr, $action:expr, $resource:expr, $policy:expr) => {
        match $policy.evaluate($identity, $action, $resource) {
            $crate::policy::PolicyEffect::Allow => Ok(()),
            $crate::policy::PolicyEffect::Deny => {
                Err($crate::error::ForgeError::PolicyViolation(
                    format!("Access denied: {} cannot {} {}", $identity.user_id, $action, $resource)
                ))
            },
            $crate::policy::PolicyEffect::EscalateTo(role) => {
                tracing::warn!(
                    user_id = %$identity.user_id,
                    tenant_id = %$identity.tenant_id,
                    request_id = %$identity.request_id,
                    "Escalating action {} on {} to role {}",
                    $action,
                    $resource,
                    role
                );
                Err($crate::error::ForgeError::PolicyViolation(
                    format!("Action requires escalation to {}", role)
                ))
            },
        }
    };
}

/// Create a new telemetry span
#[macro_export]
macro_rules! telemetry_span {
    ($name:expr, $identity:expr) => {
        $crate::telemetry::TelemetrySpan::new($name.to_string(), $identity.clone())
    };
}

/// Create a new audit event
#[macro_export]
macro_rules! audit_event {
    ($identity:expr, $action:expr, $resource:expr, $outcome:expr) => {
        $crate::audit::create_audit_event(
            $identity.clone(),
            $action.to_string(),
            $resource.to_string(),
            $outcome,
            None
        )
    };
    ($identity:expr, $action:expr, $resource:expr, $outcome:expr, $details:expr) => {
        $crate::audit::create_audit_event(
            $identity.clone(),
            $action.to_string(),
            $resource.to_string(),
            $outcome,
            Some($details)
        )
    };
}

/// Create a new observation
#[macro_export]
macro_rules! observe {
    ($identity:expr, $type:expr, $content:expr, $severity:expr) => {
        $crate::observer::Observation::new(
            $identity.clone(),
            $type,
            $content.to_string(),
            $severity
        )
    };
}