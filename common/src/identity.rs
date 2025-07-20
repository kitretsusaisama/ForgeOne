//! # Identity management for ForgeOne
//!
//! This module provides identity context and trust vectors for the ForgeOne platform.
//! It handles tenant, user, agent, and device lineage tracking.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TrustVector {
    /// Root level trust (system level)
    Root,
    /// Cryptographically signed trust with signature
    Signed(String),
    /// Secure enclave trust
    Enclave,
    /// Edge gateway trust
    EdgeGateway,
    /// Unverified trust
    #[default]
    Unverified,
    /// Compromised trust (known bad)
    Compromised,
}

/// Identity context for a request or operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    /// The unique ID for this request
    pub request_id: Uuid,
    /// The session ID for this request
    pub session_id: Uuid,
    /// The tenant ID for this request
    pub tenant_id: String,
    /// The user ID for this request
    pub user_id: String,
    /// The agent ID for this request (LLM, runtime, CLI, API)
    pub agent_id: Option<String>,
    /// The device fingerprint for this request
    pub device_fingerprint: Option<String>,
    /// The geo IP for this request
    pub geo_ip: Option<String>,
    /// The trust vector for this request
    pub trust_vector: TrustVector,
    /// Cryptographic attestation for this request
    pub cryptographic_attestation: Option<String>,
}

impl IdentityContext {
    /// Create a new identity context with default values
    pub fn new(tenant_id: String, user_id: String) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id,
            user_id,
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Unverified,
            cryptographic_attestation: None,
        }
    }

    /// Create a new root identity context
    pub fn root() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "system".to_string(),
            user_id: "root".to_string(),
            agent_id: Some("system".to_string()),
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Root,
            cryptographic_attestation: None,
        }
    }

    /// Set the agent ID for this identity
    pub fn with_agent(mut self, agent_id: String) -> Self {
        self.agent_id = Some(agent_id);
        self
    }

    /// Set the device fingerprint for this identity
    pub fn with_device(mut self, fingerprint: String) -> Self {
        self.device_fingerprint = Some(fingerprint);
        self
    }

    /// Set the geo IP for this identity
    pub fn with_geo_ip(mut self, geo_ip: String) -> Self {
        self.geo_ip = Some(geo_ip);
        self
    }

    /// Set the trust vector for this identity
    pub fn with_trust(mut self, trust: TrustVector) -> Self {
        self.trust_vector = trust;
        self
    }

    /// Set the cryptographic attestation for this identity
    pub fn with_attestation(mut self, attestation: String) -> Self {
        self.cryptographic_attestation = Some(attestation);
        self
    }

    pub fn system() -> Self {
        Self {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "system".to_string(),
            user_id: "system".to_string(),
            agent_id: Some("system".to_string()),
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Root,
            cryptographic_attestation: None,
        }
    }
}
