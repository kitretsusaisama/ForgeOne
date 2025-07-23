//! # Container DNA Module
//!
//! This module provides functionality for creating and managing container DNA,
//! which is a unique fingerprint that identifies a container and its runtime characteristics.
//! The DNA is used for policy matching, snapshot delta consistency, and fingerprinting for rehydration.

use common::crypto::hash;
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Resource limits for a container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum CPU usage in millicores
    pub cpu_millicores: u32,
    /// Maximum memory usage in bytes
    pub memory_bytes: u64,
    /// Maximum disk usage in bytes
    pub disk_bytes: u64,
    /// Maximum network bandwidth in bytes per second
    pub network_bps: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_millicores: 1000, // 1 core
            memory_bytes: 256 * 1024 * 1024, // 256 MB
            disk_bytes: 1024 * 1024 * 1024, // 1 GB
            network_bps: 10 * 1024 * 1024, // 10 MB/s
        }
    }
}

/// Container DNA represents the unique fingerprint of a container
#[derive(Clone, Serialize, Deserialize)]
pub struct ContainerDNA {
    /// Unique identifier for the container
    pub id: String,
    /// Cryptographic hash of the container image
    pub hash: String,
    /// Entity that signed the container image
    pub signer: String,
    /// Resource limits for the container
    pub resource_limits: ResourceLimits,
    /// Trust label for the container
    pub trust_label: String,
    /// Runtime entropy for the container
    pub runtime_entropy: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Identity context
    pub identity: IdentityContext,
}

impl fmt::Debug for ContainerDNA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContainerDNA")
            .field("id", &self.id)
            .field("hash", &self.hash)
            .field("signer", &self.signer)
            .field("resource_limits", &self.resource_limits)
            .field("trust_label", &self.trust_label)
            .field("runtime_entropy", &self.runtime_entropy)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl ContainerDNA {
    /// Create a new container DNA
    pub fn new(
        image_hash: &str,
        signer: &str,
        resource_limits: ResourceLimits,
        trust_label: &str,
        identity: IdentityContext,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let runtime_entropy = generate_entropy();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id,
            hash: image_hash.to_string(),
            signer: signer.to_string(),
            resource_limits,
            trust_label: trust_label.to_string(),
            runtime_entropy,
            created_at,
            identity,
        }
    }

    /// Create a new container DNA with a specific ID
    pub fn with_id(
        id: &str,
        image_hash: &str,
        signer: &str,
        resource_limits: ResourceLimits,
        trust_label: &str,
        identity: IdentityContext,
    ) -> Result<Self> {
        // Validate the ID
        if id.is_empty() {
            return Err(ForgeError::ValidationError {
                field: "id".to_string(),
                message: "Container ID cannot be empty".to_string(),
            });
        }

        let runtime_entropy = generate_entropy();
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(Self {
            id: id.to_string(),
            hash: image_hash.to_string(),
            signer: signer.to_string(),
            resource_limits,
            trust_label: trust_label.to_string(),
            runtime_entropy,
            created_at,
            identity,
        })
    }

    /// Get the container ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get the container hash
    pub fn hash(&self) -> &str {
        &self.hash
    }

    /// Get the container signer
    pub fn signer(&self) -> &str {
        &self.signer
    }

    /// Get the container resource limits
    pub fn resource_limits(&self) -> &ResourceLimits {
        &self.resource_limits
    }

    /// Get the container trust label
    pub fn trust_label(&self) -> &str {
        &self.trust_label
    }

    /// Get the container runtime entropy
    pub fn runtime_entropy(&self) -> &str {
        &self.runtime_entropy
    }

    /// Get the container creation timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the container identity context
    pub fn identity(&self) -> &IdentityContext {
        &self.identity
    }

    /// Generate a fingerprint for the container
    pub fn fingerprint(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}:{}",
            self.id,
            self.hash,
            self.signer,
            self.trust_label,
            self.runtime_entropy,
            self.created_at
        );
        hash::sha256(&data)
    }
}

/// Generate entropy for the container
fn generate_entropy() -> String {
    let uuid = Uuid::new_v4();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let data = format!("{}{}", uuid, timestamp);
    hash::sha256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::identity::IdentityContext;

    #[test]
    fn test_container_dna_creation() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let dna = ContainerDNA::new(
            "test-hash",
            "test-signer",
            resource_limits,
            "test-label",
            identity,
        );

        assert_eq!(dna.hash(), "test-hash");
        assert_eq!(dna.signer(), "test-signer");
        assert_eq!(dna.trust_label(), "test-label");
    }

    #[test]
    fn test_container_dna_with_id() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let dna = ContainerDNA::with_id(
            "test-id",
            "test-hash",
            "test-signer",
            resource_limits,
            "test-label",
            identity,
        )
        .unwrap();

        assert_eq!(dna.id(), "test-id");
        assert_eq!(dna.hash(), "test-hash");
        assert_eq!(dna.signer(), "test-signer");
        assert_eq!(dna.trust_label(), "test-label");
    }

    #[test]
    fn test_container_dna_fingerprint() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let dna = ContainerDNA::with_id(
            "test-id",
            "test-hash",
            "test-signer",
            resource_limits,
            "test-label",
            identity,
        )
        .unwrap();

        let fingerprint = dna.fingerprint();
        assert!(!fingerprint.is_empty());
    }

    #[test]
    fn test_container_dna_with_empty_id() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let result = ContainerDNA::with_id(
            "",
            "test-hash",
            "test-signer",
            resource_limits,
            "test-label",
            identity,
        );

        assert!(result.is_err());
    }
}