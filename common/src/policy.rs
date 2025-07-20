//! # Policy engine for ForgeOne
//!policy.rs
//! This module provides a DSL and runtime policy matcher for the ForgeOne platform.
//! It handles role-based access control and policy evaluation.

use serde::{Deserialize, Serialize};
use crate::identity::IdentityContext;
use crate::identity::TrustVector;

/// Policy effect representing the result of a policy evaluation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyEffect {
    /// Allow the action
    Allow,
    /// Deny the action
    Deny,
    /// Escalate to another role
    EscalateTo(String),
}

/// Policy rule representing a single policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// The role this policy applies to
    pub role: String,
    /// The action this policy applies to
    pub action: String,
    /// The resource this policy applies to
    pub resource: String,
    /// The effect of this policy
    pub effect: PolicyEffect,
}

/// Policy set representing a collection of policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    /// The name of this policy set
    pub name: String,
    /// The version of this policy set
    pub version: String,
    /// The rules in this policy set
    pub rules: Vec<PolicyRule>,
}

impl PolicySet {
    /// Create a new policy set
    pub fn new(name: String, version: String) -> Self {
        Self {
            name,
            version,
            rules: Vec::new(),
        }
    }

    /// Add a rule to this policy set
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Remove a rule from this policy set
    pub fn remove_rule(&mut self, role: &str, action: &str, resource: &str) {
        self.rules.retain(|rule| {
            !(rule.role == role && rule.action == action && rule.resource == resource)
        });
    }

    /// Evaluate a policy for a given identity and action
    pub fn evaluate(&self, identity: &IdentityContext, action: &str, resource: &str) -> PolicyEffect {
        // Root always has access
        if identity.trust_vector == TrustVector::Root {
            return PolicyEffect::Allow;
        }

        // Compromised never has access
        if identity.trust_vector == TrustVector::Compromised {
            return PolicyEffect::Deny;
        }

        // Find matching rules
        for rule in &self.rules {
            if (rule.role == "*" || rule.role == identity.user_id) &&
               (rule.action == "*" || rule.action == action) &&
               (rule.resource == "*" || rule.resource == resource) {
                return rule.effect.clone();
            }
        }

        // Default deny
        PolicyEffect::Deny
    }
}

/// Evaluate a policy for a given identity and action
pub fn evaluate_policy(identity: &IdentityContext, action: &str) -> PolicyEffect {
    if identity.trust_vector == TrustVector::Root {
        return PolicyEffect::Allow;
    }

    if identity.trust_vector == TrustVector::Compromised {
        return PolicyEffect::Deny;
    }

    if action == "shutdown" && identity.trust_vector != TrustVector::Enclave {
        return PolicyEffect::EscalateTo("compliance_auditor".into());
    }

    PolicyEffect::Allow
}