//! # Database access control module for ForgeOne
//!
//! This module provides access control mechanisms for database operations,
//! including permission checking, audit logging, and rate limiting.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::error::{ForgeError, Result};
use crate::identity::{IdentityContext, TrustVector};
use crate::observer::{Observation, ObservationType, ObservationSeverity};
use crate::policy::{PolicyEffect, PolicyRule, PolicySet};

/// Database access manager
pub struct DbAccessManager {
    /// Access control policies
    policies: RwLock<PolicySet>,
    
    /// Rate limiters
    rate_limiters: RwLock<HashMap<String, RateLimiter>>,
    
    /// Access logs
    access_logs: RwLock<Vec<AccessLog>>,
    
    /// Maximum access logs
    max_access_logs: usize,
}

/// Global database access manager
static DB_ACCESS_MANAGER: RwLock<Option<Arc<DbAccessManager>>> = RwLock::new(None);

/// Initialize database access manager
pub fn init_access_manager() -> Result<()> {
    let manager = DbAccessManager {
        policies: RwLock::new(PolicySet::new("default".to_string(), "1.0".to_string())),
        rate_limiters: RwLock::new(HashMap::new()),
        access_logs: RwLock::new(Vec::new()),
        max_access_logs: 1000,
    };
    
    // Add default policies
    {
        let mut policies = manager.policies.write().unwrap();
        
        // Root can do anything
        policies.add_rule(PolicyRule {
            role: "Root".to_string(),
            action: "*".to_string(),
            resource: "*".to_string(),
            effect: PolicyEffect::Allow,
        });
        
        // Admins can access all data
        policies.add_rule(PolicyRule {
            role: "Admin".to_string(),
            action: "*".to_string(),
            resource: "data:*".to_string(),
            effect: PolicyEffect::Allow,
        });
        
        // Users can only access their own data
        policies.add_rule(PolicyRule {
            role: "User".to_string(),
            action: "read".to_string(),
            resource: "data:user:{user_id}:*".to_string(),
            effect: PolicyEffect::Allow,
        });
        
        policies.add_rule(PolicyRule {
            role: "User".to_string(),
            action: "write".to_string(),
            resource: "data:user:{user_id}:*".to_string(),
            effect: PolicyEffect::Allow,
        });
        
        // Deny access to compromised identities
        policies.add_rule(PolicyRule {
            role: "Compromised".to_string(),
            action: "*".to_string(),
            resource: "*".to_string(),
            effect: PolicyEffect::Deny,
        });
    }
    
    // Store manager
    *DB_ACCESS_MANAGER.write().unwrap() = Some(Arc::new(manager));
    
    Ok(())
}

/// Get database access manager
pub fn get_access_manager() -> Result<Arc<DbAccessManager>> {
    match DB_ACCESS_MANAGER.read().unwrap().as_ref() {
        Some(manager) => Ok(manager.clone()),
        None => Err(ForgeError::ConfigError("Database access manager not initialized".to_string())),
    }
}

/// Database operation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbOperation {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Delete operation
    Delete,
    /// List operation
    List,
    /// Create operation
    Create,
    /// Update operation
    Update,
    /// Query operation
    Query,
    /// Admin operation
    Admin,
}

impl DbOperation {
    /// Convert to string
    pub fn to_string(&self) -> String {
        match self {
            DbOperation::Read => "read".to_string(),
            DbOperation::Write => "write".to_string(),
            DbOperation::Delete => "delete".to_string(),
            DbOperation::List => "list".to_string(),
            DbOperation::Create => "create".to_string(),
            DbOperation::Update => "update".to_string(),
            DbOperation::Query => "query".to_string(),
            DbOperation::Admin => "admin".to_string(),
        }
    }
}

/// Database resource
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DbResource {
    /// Resource type
    pub resource_type: String,
    
    /// Resource owner
    pub owner: Option<String>,
    
    /// Resource ID
    pub id: Option<String>,
    
    /// Resource path
    pub path: Option<String>,
}

impl DbResource {
    /// Create a new database resource
    pub fn new(resource_type: &str) -> Self {
        DbResource {
            resource_type: resource_type.to_string(),
            owner: None,
            id: None,
            path: None,
        }
    }
    
    /// Set resource owner
    pub fn with_owner(mut self, owner: &str) -> Self {
        self.owner = Some(owner.to_string());
        self
    }
    
    /// Set resource ID
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_string());
        self
    }
    
    /// Set resource path
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }
    
    /// Convert to string
    pub fn to_string(&self) -> String {
        let mut parts = vec![format!("data:{}", self.resource_type)];
        
        if let Some(owner) = &self.owner {
            parts.push(format!("user:{}", owner));
        }
        
        if let Some(id) = &self.id {
            parts.push(id.clone());
        }
        
        if let Some(path) = &self.path {
            parts.push(path.clone());
        }
        
        parts.join(":")
    }
}

/// Access log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLog {
    /// Log ID
    pub id: String,
    
    /// Timestamp
    pub timestamp: String,
    
    /// Identity context
    pub identity: IdentityContext,
    
    /// Operation
    pub operation: DbOperation,
    
    /// Resource
    pub resource: DbResource,
    
    /// Success
    pub success: bool,
    
    /// Error message
    pub error: Option<String>,
    
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Rate limiter
#[derive(Debug)]
struct RateLimiter {
    /// Maximum requests per window
    max_requests: usize,
    
    /// Window duration
    window: Duration,
    
    /// Request timestamps
    requests: Vec<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter
    fn new(max_requests: usize, window_seconds: u64) -> Self {
        RateLimiter {
            max_requests,
            window: Duration::from_secs(window_seconds),
            requests: Vec::new(),
        }
    }
    
    /// Check if a request is allowed
    fn is_allowed(&mut self) -> bool {
        let now = Instant::now();
        
        // Remove expired requests
        let cutoff = now - self.window;
        self.requests.retain(|&t| t > cutoff);
        
        // Check if we're under the limit
        if self.requests.len() < self.max_requests {
            self.requests.push(now);
            true
        } else {
            false
        }
    }
}

impl DbAccessManager {
    /// Check if an operation is allowed
    pub fn check_access(
        &self,
        identity: &IdentityContext,
        operation: &DbOperation,
        resource: &DbResource,
    ) -> Result<()> {
        // Check rate limits
        self.check_rate_limits(identity, operation)?;
        
        // Get user roles
        let roles = self.get_user_roles(identity);
        
        // Check policies
        let resource_str = resource.to_string();
        let operation_str = operation.to_string();
        
        // Create variable substitutions
        let mut vars = HashMap::new();
        vars.insert("user_id".to_string(), identity.user_id.clone());
        vars.insert("tenant_id".to_string(), identity.tenant_id.clone());
        
        // Check each role
        let policies = self.policies.read().unwrap();
        
        // Special handling for Root and Compromised trust vectors
        match identity.trust_vector {
            TrustVector::Root => return Ok(()),
            TrustVector::Compromised => return Err(ForgeError::AuthorizationError {
                resource: resource.to_string(),
                action: operation.to_string(),
                policy_id: "compromised_identity".to_string(),
                required_permissions: vec![],
            }),
            _ => {}
        }
        
        // Check policies for each role
        for role in &roles {
            let effect = policies.evaluate(identity, &operation_str, &resource_str);
            match effect {
                PolicyEffect::Allow => return Ok(()),
                PolicyEffect::Deny => return Err(ForgeError::AuthorizationError {
                    resource: resource_str.clone(),
                    action: operation_str.clone(),
                    policy_id: format!("deny_{}_{}", role, resource_str),
                    required_permissions: vec![],
                }),
                PolicyEffect::EscalateTo(ref escalate_role) => {
                    let _observation = Observation {
                        identity: identity.clone(),
                        observation_type: ObservationType::Security,
                        content: format!("Access escalated from {} to {} for operation {} on resource {}", role, escalate_role, operation_str, resource_str),
                        severity: ObservationSeverity::Warning,
                        timestamp: chrono::Utc::now(),
                    };
                    continue;
                }
            }
        }
        
        // Default deny
        Err(ForgeError::AuthorizationError {
            resource: resource_str,
            action: operation_str,
            policy_id: "no_matching_policy".to_string(),
            required_permissions: vec![],
        })
    }
    
    /// Log database access
    pub fn log_access(
        &self,
        identity: &IdentityContext,
        operation: &DbOperation,
        resource: &DbResource,
        success: bool,
        error: Option<String>,
        duration_ms: u64,
    ) {
        let log = AccessLog {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            identity: identity.clone(),
            operation: operation.clone(),
            resource: resource.clone(),
            success,
            error,
            duration_ms,
        };
        
        // Add log to list
        let mut logs = self.access_logs.write().unwrap();
        logs.push(log);
        
        // Trim logs if needed
        let max_logs = self.max_access_logs;
        if logs.len() > max_logs {
            let drain_count = logs.len() - max_logs;
            logs.drain(0..drain_count);
        }
    }
    
    /// Get access logs
    pub fn get_access_logs(&self, limit: usize) -> Vec<AccessLog> {
        let logs = self.access_logs.read().unwrap();
        let start = if logs.len() > limit {
            logs.len() - limit
        } else {
            0
        };
        
        logs[start..].to_vec()
    }
    
    pub fn add_policy_rule(&self, rule: PolicyRule) {
        let mut policies = self.policies.write().unwrap();
        policies.add_rule(rule);
    }
    
    pub fn remove_policy_rule(&self, role: &str, action: &str, resource: &str) {
        let mut policies = self.policies.write().unwrap();
        policies.remove_rule(role, action, resource);
    }
    
    /// Configure rate limiting
    pub fn configure_rate_limit(&self, key: &str, max_requests: usize, window_seconds: u64) {
        let mut rate_limiters = self.rate_limiters.write().unwrap();
        rate_limiters.insert(key.to_string(), RateLimiter::new(max_requests, window_seconds));
    }
    
    /// Check rate limits
    fn check_rate_limits(&self, identity: &IdentityContext, operation: &DbOperation) -> Result<()> {
        let mut rate_limiters = self.rate_limiters.write().unwrap();
        
        // Check global rate limit
        if let Some(limiter) = rate_limiters.get_mut("global") {
            if !limiter.is_allowed() {
                return Err(ForgeError::RateLimitError {
                    resource: "global".to_string(),
                    limit: limiter.max_requests as u32,
                    window_ms: limiter.window.as_millis() as u64,
                    burst_size: limiter.max_requests as u32,
                    algorithm: crate::error::RateLimitAlgorithm::FixedWindow,
                });
            }
        }
        
        // Check user-specific rate limit
        let user_id = &identity.user_id;
        let user_key = format!("user:{}", user_id);
        
        if let Some(limiter) = rate_limiters.get_mut(&user_key) {
            if !limiter.is_allowed() {
                return Err(ForgeError::RateLimitError {
                    resource: user_key,
                    limit: limiter.max_requests as u32,
                    window_ms: limiter.window.as_millis() as u64,
                    burst_size: limiter.max_requests as u32,
                    algorithm: crate::error::RateLimitAlgorithm::FixedWindow,
                });
            }
        }
        
        // Check operation-specific rate limit
        let op_key = format!("operation:{}", operation.to_string());
        
        if let Some(limiter) = rate_limiters.get_mut(&op_key) {
            if !limiter.is_allowed() {
                return Err(ForgeError::RateLimitError {
                    resource: op_key,
                    limit: limiter.max_requests as u32,
                    window_ms: limiter.window.as_millis() as u64,
                    burst_size: limiter.max_requests as u32,
                    algorithm: crate::error::RateLimitAlgorithm::FixedWindow,
                });
            }
        }
        
        Ok(())
    }
    
    /// Get user roles
    fn get_user_roles(&self, identity: &IdentityContext) -> Vec<String> {
        let mut roles = Vec::new();
        // Add trust vector as role
        match &identity.trust_vector {
            TrustVector::Root => roles.push("Root".to_string()),
            TrustVector::Signed(_) => roles.push("Signed".to_string()),
            TrustVector::Enclave => roles.push("Enclave".to_string()),
            TrustVector::EdgeGateway => roles.push("EdgeGateway".to_string()),
            TrustVector::Unverified => roles.push("Unverified".to_string()),
            TrustVector::Compromised => roles.push("Compromised".to_string()),
        }
        // Add user role
        roles.push("User".to_string());
        // TODO: Add roles from user profile or other sources
        roles
    }
}

/// Database access guard
pub struct DbAccessGuard<'a> {
    /// Access manager
    manager: Arc<DbAccessManager>,
    
    /// Identity context
    identity: &'a IdentityContext,
    
    /// Operation
    operation: DbOperation,
    
    /// Resource
    resource: DbResource,
    
    /// Start time
    start_time: Instant,
}

impl<'a> DbAccessGuard<'a> {
    /// Create a new database access guard
    pub fn new(
        identity: &'a IdentityContext,
        operation: DbOperation,
        resource: DbResource,
    ) -> Result<Self> {
        let manager = get_access_manager()?;
        
        // Check access
        manager.check_access(identity, &operation, &resource)?;
        
        Ok(DbAccessGuard {
            manager,
            identity,
            operation,
            resource,
            start_time: Instant::now(),
        })
    }
    
    /// Complete the operation successfully
    pub fn complete(self) {
        let duration = self.start_time.elapsed().as_millis() as u64;
        
        self.manager.log_access(
            self.identity,
            &self.operation,
            &self.resource,
            true,
            None,
            duration,
        );
    }
    
    /// Complete the operation with an error
    pub fn complete_with_error(self, error: &str) {
        let duration = self.start_time.elapsed().as_millis() as u64;
        
        self.manager.log_access(
            self.identity,
            &self.operation,
            &self.resource,
            false,
            Some(error.to_string()),
            duration,
        );
    }
}

impl<'a> Drop for DbAccessGuard<'a> {
    fn drop(&mut self) {
        // If the guard is dropped without calling complete or complete_with_error,
        // log an error
        let duration = self.start_time.elapsed().as_millis() as u64;
        
        self.manager.log_access(
            self.identity,
            &self.operation,
            &self.resource,
            false,
            Some("Operation aborted".to_string()),
            duration,
        );
    }
}

/// Check database access
pub fn check_db_access(
    identity: &IdentityContext,
    operation: DbOperation,
    resource: DbResource,
) -> Result<DbAccessGuard> {
    DbAccessGuard::new(identity, operation, resource)
}