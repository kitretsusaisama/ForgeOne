//! # ZTA Policy Module for ForgeOne Microkernel
//!
//! This module provides Zero Trust Architecture (ZTA) policy evaluation for the ForgeOne microkernel.
//! It maintains a real-time graph of security policies and evaluates them based on identity, syscall,
//! and arguments.

use crate::execution::syscall::SyscallContext;
use chrono::{DateTime, Utc};
use common::identity::{IdentityContext, TrustVector};
use common::trust::{Action, ZtaNode, ZtaPolicyGraph as CommonZtaPolicyGraph};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// A policy graph for Zero Trust Architecture (ZTA) policy evaluation
#[derive(Debug, Clone)]
pub struct ZtaPolicyGraph {
    /// Policies for specific syscalls
    pub policies: HashMap<String, SyscallPolicy>,
    /// Trust thresholds for different operations
    pub trust_thresholds: HashMap<String, f64>,
    /// Rules for identity-based trust adjustments
    pub identity_rules: Vec<IdentityRule>,
    /// Version of the policy graph
    pub version: String,
    /// Last update time of the policy graph
    pub last_updated: DateTime<Utc>,
    /// Common ZTA policy graph for basic trust evaluation
    pub common_graph: CommonZtaPolicyGraph,
}

/// A policy for a specific syscall
#[derive(Debug, Clone)]
pub struct SyscallPolicy {
    /// The syscall name
    pub syscall: String,
    /// Minimum trust score required for this syscall
    pub min_trust_score: f64,
    /// Identities explicitly allowed to perform this syscall
    pub allowed_identities: Option<HashSet<String>>,
    /// Identities explicitly denied from performing this syscall
    pub denied_identities: Option<HashSet<String>>,
    /// Constraints on syscall arguments
    pub arg_constraints: HashMap<usize, String>,
    /// Custom validator function for complex policy checks
    pub custom_validator: Option<fn(&SyscallContext) -> bool>,
}

/// A rule for adjusting trust based on identity
#[derive(Debug, Clone)]
pub struct IdentityRule {
    /// Pattern to match identity
    pub identity_pattern: String,
    /// Trust adjustment value
    pub trust_adjustment: f64,
    /// Patterns of syscalls this rule applies to
    pub syscall_patterns: Option<Vec<String>>,
    /// Description of the rule
    pub description: String,
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Reason for the decision
    pub reason: Option<String>,
    /// Trust score after evaluation
    pub trust_score: f64,
    /// Version of the policy used for evaluation
    pub policy_version: String,
    /// Timestamp of the evaluation
    pub timestamp: DateTime<Utc>,
}

impl Default for ZtaPolicyGraph {
    fn default() -> Self {
        ZtaPolicyGraph {
            policies: std::collections::HashMap::new(),
            trust_thresholds: std::collections::HashMap::new(),
            identity_rules: Vec::new(),
            version: "1.0.0".to_string(),
            last_updated: chrono::Utc::now(),
            common_graph: CommonZtaPolicyGraph::new(),
        }
    }
}

// Global policy graph instance
static mut POLICY_GRAPH: Option<Arc<RwLock<ZtaPolicyGraph>>> = None;

/// Initialize the ZTA policy graph
pub fn init() -> Result<(), String> {
    let graph = ZtaPolicyGraph {
        policies: HashMap::new(),
        trust_thresholds: HashMap::new(),
        identity_rules: Vec::new(),
        version: "1.0.0".to_string(),
        last_updated: Utc::now(),
        common_graph: CommonZtaPolicyGraph::new(),
    };

    // Initialize with default policies
    let mut initialized_graph = graph.clone();
    initialize_default_policies(&mut initialized_graph);

    unsafe {
        POLICY_GRAPH = Some(Arc::new(RwLock::new(initialized_graph)));
    }

    Ok(())
}

/// Get the ZTA policy graph
pub fn get_policy_graph() -> Arc<RwLock<ZtaPolicyGraph>> {
    unsafe {
        match &POLICY_GRAPH {
            Some(graph) => graph.clone(),
            None => {
                // Initialize if not already done
                let _ = init();
                POLICY_GRAPH.as_ref().unwrap().clone()
            }
        }
    }
}

/// Initialize default policies
fn initialize_default_policies(graph: &mut ZtaPolicyGraph) {
    // Add default syscall policies
    add_default_syscall_policies(graph);

    // Add default trust thresholds
    add_default_trust_thresholds(graph);

    // Add default identity rules
    add_default_identity_rules(graph);

    // Initialize common graph with basic nodes and edges
    initialize_common_graph(&mut graph.common_graph);
}

/// Add default syscall policies
fn add_default_syscall_policies(graph: &mut ZtaPolicyGraph) {
    // File operations
    graph.policies.insert(
        "file_open".to_string(),
        SyscallPolicy {
            syscall: "file_open".to_string(),
            min_trust_score: 0.5,
            allowed_identities: None,
            denied_identities: None,
            arg_constraints: {
                let mut constraints = HashMap::new();
                constraints.insert(0, "^((?!(/etc|/var/log|/root)).)*$".to_string()); // Disallow sensitive paths
                constraints
            },
            custom_validator: None,
        },
    );

    graph.policies.insert(
        "file_read".to_string(),
        SyscallPolicy {
            syscall: "file_read".to_string(),
            min_trust_score: 0.3,
            allowed_identities: None,
            denied_identities: None,
            arg_constraints: HashMap::new(),
            custom_validator: None,
        },
    );

    graph.policies.insert(
        "file_write".to_string(),
        SyscallPolicy {
            syscall: "file_write".to_string(),
            min_trust_score: 0.7,
            allowed_identities: None,
            denied_identities: None,
            arg_constraints: {
                let mut constraints = HashMap::new();
                constraints.insert(0, "^((?!(/etc|/var/log|/root)).)*$".to_string()); // Disallow sensitive paths
                constraints
            },
            custom_validator: None,
        },
    );

    // Network operations
    graph.policies.insert(
        "net_connect".to_string(),
        SyscallPolicy {
            syscall: "net_connect".to_string(),
            min_trust_score: 0.6,
            allowed_identities: None,
            denied_identities: None,
            arg_constraints: {
                let mut constraints = HashMap::new();
                constraints.insert(
                    0,
                    "^((?!(127\\.0\\.0\\.1|0\\.0\\.0\\.0|10\\.0\\.0\\.0/8)).)*$".to_string(),
                ); // Restrict local network
                constraints
            },
            custom_validator: None,
        },
    );

    // Process operations
    graph.policies.insert(
        "proc_create".to_string(),
        SyscallPolicy {
            syscall: "proc_create".to_string(),
            min_trust_score: 0.8,
            allowed_identities: None,
            denied_identities: None,
            arg_constraints: HashMap::new(),
            custom_validator: None,
        },
    );
}

/// Add default trust thresholds
fn add_default_trust_thresholds(graph: &mut ZtaPolicyGraph) {
    graph
        .trust_thresholds
        .insert("file_operations".to_string(), 0.5);
    graph
        .trust_thresholds
        .insert("network_operations".to_string(), 0.6);
    graph
        .trust_thresholds
        .insert("process_operations".to_string(), 0.8);
    graph
        .trust_thresholds
        .insert("memory_operations".to_string(), 0.7);
    graph
        .trust_thresholds
        .insert("system_operations".to_string(), 0.9);
}

/// Add default identity rules
fn add_default_identity_rules(graph: &mut ZtaPolicyGraph) {
    graph.identity_rules.push(IdentityRule {
        identity_pattern: "system:.*".to_string(),
        trust_adjustment: 0.2,
        syscall_patterns: None,
        description: "System users get a trust boost".to_string(),
    });

    graph.identity_rules.push(IdentityRule {
        identity_pattern: "guest:.*".to_string(),
        trust_adjustment: -0.3,
        syscall_patterns: None,
        description: "Guest users get a trust penalty".to_string(),
    });

    graph.identity_rules.push(IdentityRule {
        identity_pattern: ".*".to_string(),
        trust_adjustment: -0.5,
        syscall_patterns: Some(vec!["proc_.*".to_string()]),
        description: "All users get a trust penalty for process operations".to_string(),
    });
}

/// Initialize the common graph with basic nodes and edges
fn initialize_common_graph(graph: &mut CommonZtaPolicyGraph) {
    // Add system node
    graph.add_node(ZtaNode {
        id: "system".to_string(),
        trust_vector: TrustVector::Root,
        allowed_actions: [
            Action::Read,
            Action::Write,
            Action::Execute,
            Action::Connect,
        ]
        .iter()
        .cloned()
        .collect(),
        denied_actions: HashSet::new(),
    });

    // Add user node
    graph.add_node(ZtaNode {
        id: "user".to_string(),
        trust_vector: TrustVector::Unverified,
        allowed_actions: [Action::Read].iter().cloned().collect(),
        denied_actions: [Action::Execute].iter().cloned().collect(),
    });

    // Add edge from system to user
    graph.add_edge(
        "system",
        "user",
        [Action::Read, Action::Write].iter().cloned().collect(),
    );
}

impl ZtaPolicyGraph {
    /// Evaluate a syscall against the policy graph
    pub fn evaluate(&self, context: &SyscallContext) -> PolicyEvaluationResult {
        // Get the syscall policy
        let policy = match self.policies.get(&context.syscall_name) {
            Some(policy) => policy,
            None => {
                return PolicyEvaluationResult {
                    allowed: false,
                    reason: Some(format!(
                        "No policy found for syscall: {}",
                        context.syscall_name
                    )),
                    trust_score: 0.0,
                    policy_version: self.version.clone(),
                    timestamp: Utc::now(),
                };
            }
        };

        // Check identity allowlist/denylist
        if let Some(denied_identities) = &policy.denied_identities {
            if denied_identities.contains(&context.identity.user_id) {
                return PolicyEvaluationResult {
                    allowed: false,
                    reason: Some(format!(
                        "Identity {} is explicitly denied",
                        context.identity.user_id
                    )),
                    trust_score: 0.0,
                    policy_version: self.version.clone(),
                    timestamp: Utc::now(),
                };
            }
        }

        // Calculate trust score
        let mut trust_score = match context.identity.trust_vector {
            TrustVector::Root => 1.0,
            TrustVector::Signed(_) => 0.8,
            TrustVector::Enclave => 0.9,
            TrustVector::EdgeGateway => 0.7,
            TrustVector::Unverified => 0.3,
            TrustVector::Compromised => 0.0,
        };

        // Apply identity rules
        for rule in &self.identity_rules {
            if context.identity.user_id.contains(&rule.identity_pattern) {
                // Check if rule applies to this syscall
                let applies = match &rule.syscall_patterns {
                    Some(patterns) => patterns.iter().any(|p| context.syscall_name.contains(p)),
                    None => true,
                };

                if applies {
                    trust_score += rule.trust_adjustment;
                }
            }
        }

        // Clamp trust score between 0 and 1
        trust_score = trust_score.max(0.0).min(1.0);

        // Check minimum trust score
        if trust_score < policy.min_trust_score {
            return PolicyEvaluationResult {
                allowed: false,
                reason: Some(format!(
                    "Trust score too low: {} < {}",
                    trust_score, policy.min_trust_score
                )),
                trust_score,
                policy_version: self.version.clone(),
                timestamp: Utc::now(),
            };
        }

        // Check argument constraints
        for (arg_index, constraint) in &policy.arg_constraints {
            if let Some(arg) = context.args.get(*arg_index) {
                // Simple contains check for now, could be extended to regex
                if !arg.contains(constraint) {
                    return PolicyEvaluationResult {
                        allowed: false,
                        reason: Some(format!(
                            "Argument {} violates constraint: {}",
                            arg_index, constraint
                        )),
                        trust_score,
                        policy_version: self.version.clone(),
                        timestamp: Utc::now(),
                    };
                }
            }
        }

        // Run custom validator if present
        if let Some(validator) = policy.custom_validator {
            if !validator(context) {
                return PolicyEvaluationResult {
                    allowed: false,
                    reason: Some("Custom validator rejected syscall".to_string()),
                    trust_score,
                    policy_version: self.version.clone(),
                    timestamp: Utc::now(),
                };
            }
        }

        // All checks passed
        PolicyEvaluationResult {
            allowed: true,
            reason: None,
            trust_score,
            policy_version: self.version.clone(),
            timestamp: Utc::now(),
        }
    }

    /// Update the policy graph with a new policy
    pub fn update_policy(&mut self, syscall: String, policy: SyscallPolicy) {
        self.policies.insert(syscall, policy);
        self.last_updated = Utc::now();
    }

    /// Add a new identity rule
    pub fn add_identity_rule(&mut self, rule: IdentityRule) {
        self.identity_rules.push(rule);
        self.last_updated = Utc::now();
    }

    /// Set a trust threshold
    pub fn set_trust_threshold(&mut self, category: String, threshold: f64) {
        self.trust_thresholds.insert(category, threshold);
        self.last_updated = Utc::now();
    }
}

/// Validate an identity against a syscall and arguments
pub fn validate(
    identity: &IdentityContext,
    syscall: &str,
    args: &[String],
) -> Result<bool, String> {
    let graph = get_policy_graph();
    let graph = graph
        .read()
        .map_err(|e| format!("Failed to read policy graph: {}", e))?;

    let context = SyscallContext {
        syscall_name: syscall.to_string(),
        syscall_type: crate::execution::syscall::SyscallType::System,
        args: args.to_vec(),
        identity: std::sync::Arc::new(identity.clone()),
        policy_decision: None,
        execution_time: None,
        result: Some(crate::execution::syscall::SyscallResult::Success),
    };

    let result = graph.evaluate(&context);
    Ok(result.allowed)
}
