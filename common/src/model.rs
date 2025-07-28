//! Common data models for the ForgeOne microkernel

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

/// Trust vector representing the trust level of an identity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustVector {
    /// Fully trusted identity
    Trusted,
    /// Partially trusted identity
    Partial,
    /// Untrusted identity
    Untrusted,
    /// Compromised identity
    Compromised,
}

/// Identity context for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    /// Unique identifier for the user
    pub user_id: String,
    /// Container ID
    pub container_id: Uuid,
    /// Trust vector for the identity
    pub trust_vector: TrustVector,
    /// Roles assigned to the identity
    pub roles: Vec<String>,
    /// Additional attributes for the identity
    pub attributes: std::collections::HashMap<String, String>,
}

impl IdentityContext {
    /// Create a new identity context
    pub fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            trust_vector: TrustVector::Untrusted,
            container_id: Uuid::new_v4(),
            roles: Vec::new(),
            attributes: std::collections::HashMap::new(),
        }
    }
    
    /// Set the trust vector for this identity
    pub fn with_trust_vector(mut self, trust_vector: TrustVector) -> Self {
        self.trust_vector = trust_vector;
        self
    }
    
    /// Add a role to this identity
    pub fn with_role(mut self, role: &str) -> Self {
        self.roles.push(role.to_string());
        self
    }
    
    /// Add an attribute to this identity
    pub fn with_attribute(mut self, key: &str, value: &str) -> Self {
        self.attributes.insert(key.to_string(), value.to_string());
        self
    }
}

/// Record of a syscall execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallRecord {
    /// Name of the syscall
    pub name: String,
    /// Arguments passed to the syscall
    pub args: Vec<String>,
    /// Whether the syscall was allowed
    pub allowed: bool,
    /// Timestamp of the syscall
    pub timestamp: DateTime<Utc>,
}

impl SyscallRecord {
    /// Create a new syscall record
    pub fn new(name: &str, args: &[impl AsRef<str>], allowed: bool) -> Self {
        Self {
            name: name.to_string(),
            args: args.iter().map(|s| s.as_ref().to_string()).collect(),
            allowed,
            timestamp: Utc::now(),
        }
    }
}

/// DNA-style container trace log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionDNA {
    /// Container ID
    pub container_id: Uuid,
    /// Trace ID
    pub trace_id: Uuid,
    /// Identity context
    pub identity: IdentityContext,
    /// Syscall log
    pub syscall_log: Vec<SyscallRecord>,
    /// Integrity score
    pub integrity_score: f64,
    /// Red flags
    pub red_flags: Vec<String>,
}

impl ExecutionDNA {
    /// Create a new execution DNA
    pub fn new(container_id: Uuid, identity: IdentityContext) -> Self {
        Self {
            container_id,
            trace_id: Uuid::new_v4(),
            identity,
            syscall_log: Vec::new(),
            integrity_score: 100.0,
            red_flags: Vec::new(),
        }
    }
    
    /// Log a message
    pub fn log(&mut self, message: &str) {
        tracing::info!(container_id = %self.container_id, trace_id = %self.trace_id, "DNA: {}", message);
    }
    
    /// Record a syscall
    pub fn record_syscall(&mut self, syscall: &str, args: &[impl AsRef<str>], allowed: bool) {
        let record = SyscallRecord::new(syscall, args, allowed);
        self.syscall_log.push(record);
    }
    
    /// Flag a risk
    pub fn flag_risk(&mut self, reason: &str) {
        self.red_flags.push(reason.to_string());
        self.integrity_score -= 10.0;
        self.integrity_score = self.integrity_score.max(0.0);
        
        tracing::warn!(
            container_id = %self.container_id,
            trace_id = %self.trace_id,
            reason = reason,
            integrity_score = self.integrity_score,
            "🚩 Risk flagged"
        );
    }
}

/// Execution context for a container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Container ID
    pub container_id: Uuid,
    /// Runtime path
    pub runtime_path: PathBuf,
    /// Identity context
    pub identity_context: IdentityContext,
    /// Execution DNA
    pub dna: ExecutionDNA,
    /// Resource limits
    pub resource_limits: ResourceLimits,
}

/// Resource limits for a container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum memory usage in bytes
    pub max_memory: u64,
    /// Maximum CPU time
    pub max_cpu_time: Duration,
    /// Maximum number of file descriptors
    pub max_file_descriptors: u32,
    /// Maximum number of processes
    pub max_processes: u32,
    /// Maximum network bandwidth in bytes per second
    pub max_network_bandwidth: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory: 1024 * 1024 * 1024, // 1GB
            max_cpu_time: Duration::from_secs(60), // 60 seconds
            max_file_descriptors: 1024,
            max_processes: 100,
            max_network_bandwidth: 10 * 1024 * 1024, // 10MB/s
        }
    }
}

impl ExecutionContext {
    /// Create a new execution context
    pub fn new(container_id: Uuid, runtime_path: PathBuf, identity_context: IdentityContext) -> Self {
        let dna = ExecutionDNA::new(container_id, identity_context.clone());
        
        Self {
            container_id,
            runtime_path,
            identity_context,
            dna,
            resource_limits: ResourceLimits::default(),
        }
    }
    
    /// Create an execution context from a syscall context
    pub fn from_syscall_context<T>(container_id_str: &str, identity: IdentityContext, resource_limits: ResourceLimits) -> Self {
        let container_id = Uuid::parse_str(container_id_str).unwrap_or_else(|_| Uuid::nil());
        let runtime_path = PathBuf::from("/runtime"); // Default path, would be configured properly
        let dna = ExecutionDNA::new(container_id, identity.clone());
        
        Self {
            container_id,
            runtime_path,
            identity_context: identity,
            dna,
            resource_limits,
        }
    }
    
    /// Get the identity context
    pub fn identity(&self) -> &IdentityContext {
        &self.identity_context
    }
}

/// ForgeOne package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgePkg {
    /// Package manifest
    pub manifest: ForgePkgManifest,
    /// Package signature
    pub signature: String,
}

/// ForgeOne package manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgePkgManifest {
    /// Package name
    pub name: String,
    /// Package version
    pub version: String,
    /// Package description
    pub description: String,
    /// Package author
    pub author: String,
    /// Package hash
    pub hash: String,
    /// Package dependencies
    pub dependencies: Vec<String>,
    /// Package permissions
    pub permissions: Vec<String>,
}

/// Zero Trust Architecture policy graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtaPolicyGraph {
    /// Policy rules
    pub rules: Vec<ZtaRule>,
}

impl ZtaPolicyGraph {
    /// Create a new ZTA policy graph
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
        }
    }
    
    /// Add a rule to the graph
    pub fn add_rule(&mut self, rule: ZtaRule) {
        self.rules.push(rule);
    }
    
    /// Evaluate the policy graph for a given identity, syscall, and arguments
    pub fn evaluate(&self, identity: &IdentityContext, syscall: &str, args: &[impl AsRef<str>]) -> bool {
        // Default deny if no rules match
        if self.rules.is_empty() {
            return false;
        }
        
        // Check if any rule allows this syscall
        self.rules.iter().any(|rule| rule.matches(identity, syscall, args))
    }
}

/// Zero Trust Architecture rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtaRule {
    /// Rule name
    pub name: String,
    /// Syscalls allowed by this rule
    pub syscalls: Vec<String>,
    /// Required roles for this rule
    pub required_roles: Vec<String>,
    /// Required trust vector for this rule
    pub required_trust: Option<TrustVector>,
}

impl ZtaRule {
    /// Create a new ZTA rule
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            syscalls: Vec::new(),
            required_roles: Vec::new(),
            required_trust: None,
        }
    }
    
    /// Add a syscall to this rule
    pub fn with_syscall(mut self, syscall: &str) -> Self {
        self.syscalls.push(syscall.to_string());
        self
    }
    
    /// Add a required role to this rule
    pub fn with_required_role(mut self, role: &str) -> Self {
        self.required_roles.push(role.to_string());
        self
    }
    
    /// Set the required trust vector for this rule
    pub fn with_required_trust(mut self, trust: TrustVector) -> Self {
        self.required_trust = Some(trust);
        self
    }
    
    /// Check if this rule matches the given identity, syscall, and arguments
    pub fn matches(&self, identity: &IdentityContext, syscall: &str, _args: &[impl AsRef<str>]) -> bool {
        // Check if syscall is allowed by this rule
        if !self.syscalls.iter().any(|s| s == syscall || s == "*") {
            return false;
        }
        
        // Check if identity has required roles
        if !self.required_roles.is_empty() {
            let has_required_role = self.required_roles.iter().any(|role| identity.roles.contains(role));
            if !has_required_role {
                return false;
            }
        }
        
        // Check if identity has required trust vector
        if let Some(required_trust) = &self.required_trust {
            match (required_trust, &identity.trust_vector) {
                (TrustVector::Trusted, TrustVector::Trusted) => true,
                (TrustVector::Partial, TrustVector::Trusted | TrustVector::Partial) => true,
                (TrustVector::Untrusted, TrustVector::Trusted | TrustVector::Partial | TrustVector::Untrusted) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}