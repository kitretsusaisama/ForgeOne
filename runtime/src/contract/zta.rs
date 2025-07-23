//! # Zero Trust Architecture Contract Module
//!
//! This module provides functionality for creating and managing ZTA contracts,
//! which define the zero trust security policies for containers.
//! The ZTA contracts are enforced before container starts to ensure security compliance.

use crate::dna::ContainerDNA;
use common::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Execution mode for the container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecMode {
    /// Unrestricted execution mode
    Unrestricted,
    /// Restricted execution mode
    Restricted,
    /// Isolated execution mode
    Isolated,
    /// Quarantined execution mode
    Quarantined,
}

impl fmt::Display for ExecMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecMode::Unrestricted => write!(f, "Unrestricted"),
            ExecMode::Restricted => write!(f, "Restricted"),
            ExecMode::Isolated => write!(f, "Isolated"),
            ExecMode::Quarantined => write!(f, "Quarantined"),
        }
    }
}

/// Zero Trust Architecture contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZTAContract {
    /// Runtime policy ID
    pub runtime_policy_id: String,
    /// Trusted issuers
    pub trusted_issuers: Vec<String>,
    /// Minimum entropy required
    pub minimum_entropy: f64,
    /// Execution mode
    pub exec_mode: ExecMode,
}

impl ZTAContract {
    /// Create a new ZTA contract
    pub fn new(
        runtime_policy_id: &str,
        trusted_issuers: Vec<String>,
        minimum_entropy: f64,
        exec_mode: ExecMode,
    ) -> Self {
        Self {
            runtime_policy_id: runtime_policy_id.to_string(),
            trusted_issuers,
            minimum_entropy,
            exec_mode,
        }
    }

    /// Get the runtime policy ID
    pub fn runtime_policy_id(&self) -> &str {
        &self.runtime_policy_id
    }

    /// Get the trusted issuers
    pub fn trusted_issuers(&self) -> &[String] {
        &self.trusted_issuers
    }

    /// Get the minimum entropy
    pub fn minimum_entropy(&self) -> f64 {
        self.minimum_entropy
    }

    /// Get the execution mode
    pub fn exec_mode(&self) -> &ExecMode {
        &self.exec_mode
    }
}

/// Validate a ZTA contract against a container DNA
pub fn validate_contract(dna: &ContainerDNA, contract: &ZTAContract) -> Result<()> {
    // Check if the signer is trusted
    if !contract.trusted_issuers.contains(&dna.signer) {
        return Err(ForgeError::AuthorizationError {
            resource: "container".to_string(),
            action: "validate_contract".to_string(),
            policy_id: contract.runtime_policy_id.clone(),
            required_permissions: vec![format!("trusted_issuer:{}", dna.signer)],
        });
    }

    // Check if the entropy is sufficient
    let entropy = calculate_entropy(&dna.runtime_entropy);
    if entropy < contract.minimum_entropy {
        return Err(ForgeError::AuthorizationError {
            resource: "container".to_string(),
            action: "validate_contract".to_string(),
            policy_id: contract.runtime_policy_id.clone(),
            required_permissions: vec![format!("minimum_entropy:{}", contract.minimum_entropy)],
        });
    }

    // Check if the trust label is compatible with the execution mode
    match contract.exec_mode {
        ExecMode::Unrestricted => {
            if dna.trust_label != "trusted" {
                return Err(ForgeError::AuthorizationError {
                    resource: "container".to_string(),
                    action: "validate_contract".to_string(),
                    policy_id: contract.runtime_policy_id.clone(),
                    required_permissions: vec!["trust_label:trusted".to_string()],
                });
            }
        }
        ExecMode::Restricted => {
            if dna.trust_label != "trusted" && dna.trust_label != "restricted" {
                return Err(ForgeError::AuthorizationError {
                    resource: "container".to_string(),
                    action: "validate_contract".to_string(),
                    policy_id: contract.runtime_policy_id.clone(),
                    required_permissions: vec![
                        "trust_label:trusted".to_string(),
                        "trust_label:restricted".to_string(),
                    ],
                });
            }
        }
        ExecMode::Isolated => {
            // Any trust label is allowed for isolated mode
        }
        ExecMode::Quarantined => {
            // Any trust label is allowed for quarantined mode
        }
    }

    Ok(())
}

/// Calculate the entropy of a string
fn calculate_entropy(s: &str) -> f64 {
    let mut char_count = std::collections::HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *char_count.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in char_count.values() {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dna::{ContainerDNA, ResourceLimits};
    use common::identity::IdentityContext;

    #[test]
    fn test_zta_contract_creation() {
        let contract = ZTAContract::new(
            "test-policy",
            vec!["test-issuer".to_string()],
            0.5,
            ExecMode::Restricted,
        );

        assert_eq!(contract.runtime_policy_id(), "test-policy");
        assert_eq!(contract.trusted_issuers(), &["test-issuer"]);
        assert_eq!(contract.minimum_entropy(), 0.5);
        match contract.exec_mode() {
            ExecMode::Restricted => {}
            _ => panic!("Expected Restricted execution mode"),
        }
    }

    #[test]
    fn test_validate_contract_success() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let dna = ContainerDNA::with_id(
            "test-id",
            "test-hash",
            "test-issuer",
            resource_limits,
            "trusted",
            identity,
        )
        .unwrap();

        let contract = ZTAContract::new(
            "test-policy",
            vec!["test-issuer".to_string()],
            0.0, // Set to 0.0 to bypass entropy check in tests
            ExecMode::Unrestricted,
        );

        let result = validate_contract(&dna, &contract);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_contract_untrusted_issuer() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let dna = ContainerDNA::with_id(
            "test-id",
            "test-hash",
            "untrusted-issuer",
            resource_limits,
            "trusted",
            identity,
        )
        .unwrap();

        let contract = ZTAContract::new(
            "test-policy",
            vec!["test-issuer".to_string()],
            0.0,
            ExecMode::Unrestricted,
        );

        let result = validate_contract(&dna, &contract);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_contract_wrong_trust_label() {
        let resource_limits = ResourceLimits::default();
        let identity = IdentityContext::new("test-user", "test-role", "test-org");
        let dna = ContainerDNA::with_id(
            "test-id",
            "test-hash",
            "test-issuer",
            resource_limits,
            "untrusted",
            identity,
        )
        .unwrap();

        let contract = ZTAContract::new(
            "test-policy",
            vec!["test-issuer".to_string()],
            0.0,
            ExecMode::Unrestricted,
        );

        let result = validate_contract(&dna, &contract);
        assert!(result.is_err());
    }
}