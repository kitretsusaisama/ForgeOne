//! # Trust engine for ForgeOne
//! This module provides a Zero Trust Policy and graph engine for the ForgeOne platform.
//! //common\src\trust.rs
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::identity::{IdentityContext, TrustVector};

/// Actions allowed in the system
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Connect,
    Execute,
    Custom(String),
}

impl From<&str> for Action {
    fn from(s: &str) -> Self {
        match s {
            "read" => Action::Read,
            "write" => Action::Write,
            "connect" => Action::Connect,
            "execute" => Action::Execute,
            other => Action::Custom(other.to_string()),
        }
    }
}

/// A node in the Zero Trust Policy graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtaNode {
    pub id: String,
    pub trust_vector: TrustVector,
    pub allowed_actions: HashSet<Action>,
    pub denied_actions: HashSet<Action>,
}

/// A Zero Trust Policy graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtaPolicyGraph {
    pub nodes: HashMap<String, ZtaNode>,
    pub edges: HashMap<String, HashMap<String, HashSet<Action>>>, // from -> to -> actions
    pub bidirectional: bool,
}

impl ZtaPolicyGraph {
    /// Create a new graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            bidirectional: true, // default to bidirectional for connect-type edges
        }
    }

    /// Add a node
    pub fn add_node(&mut self, node: ZtaNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    /// Add an edge between two nodes
    pub fn add_edge(&mut self, from: &str, to: &str, actions: HashSet<Action>) {
        self.edges
            .entry(from.to_string())
            .or_insert_with(HashMap::new)
            .entry(to.to_string())
            .or_insert_with(HashSet::new)
            .extend(actions.clone());

        if self.bidirectional {
            self.edges
                .entry(to.to_string())
                .or_insert_with(HashMap::new)
                .entry(from.to_string())
                .or_insert_with(HashSet::new)
                .extend(actions);
        }
    }

    /// Evaluate if an action is allowed
    pub fn evaluate(&self, identity: &IdentityContext, action: &str, _args: &[&str]) -> bool {
        let action_enum: Action = action.into();

        // System root access
        if identity.trust_vector == TrustVector::Root {
            return true;
        }

        // Compromised entities are blocked
        if identity.trust_vector == TrustVector::Compromised {
            return false;
        }

        // User must exist in the graph
        let user_node = match self.nodes.get(&identity.user_id) {
            Some(node) => node,
            None => return false,
        };

        if user_node.denied_actions.contains(&action_enum) {
            return false;
        }

        // Explicit allow
        if user_node.allowed_actions.contains(&action_enum) {
            return true;
        }

        // Edge-based allow
        if let Some(targets) = self.edges.get(&identity.user_id) {
            for (_target, actions) in targets {
                if actions.contains(&action_enum) {
                    return true;
                }
            }
        }
        false
    }
}

/// Trust vector verification logic
pub fn verify_trust_vector(identity: &IdentityContext) -> bool {
    match &identity.trust_vector {
        TrustVector::Root => identity.user_id == "root" && identity.tenant_id == "system",
        TrustVector::Signed(signature) => !signature.is_empty(),
        TrustVector::Enclave => identity.cryptographic_attestation.is_some(),
        TrustVector::EdgeGateway => identity.device_fingerprint.is_some(),
        TrustVector::Unverified => true,
        TrustVector::Compromised => false,
    }
}
