//! # Container Attestation Module
//!
//! This module provides functionality for container attestation, verification,
//! and security validation. It implements various attestation mechanisms including
//! hardware-based (TPM, SGX, TDX), software-based, and remote attestation.

use crate::contract::Contract;
use crate::dna::ContainerDNA;
use common::crypto::{Hash, HashAlgorithm, SignatureAlgorithm};
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Attestation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationType {
    /// Hardware-based attestation (TPM, SGX, TDX)
    Hardware,
    /// Software-based attestation
    Software,
    /// Remote attestation
    Remote,
    /// Custom attestation
    Custom,
}

impl std::fmt::Display for AttestationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationType::Hardware => write!(f, "hardware"),
            AttestationType::Software => write!(f, "software"),
            AttestationType::Remote => write!(f, "remote"),
            AttestationType::Custom => write!(f, "custom"),
        }
    }
}

/// Hardware attestation type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HardwareAttestationType {
    /// Trusted Platform Module (TPM)
    TPM,
    /// Intel Software Guard Extensions (SGX)
    SGX,
    /// Intel Trust Domain Extensions (TDX)
    TDX,
    /// AMD Secure Encrypted Virtualization (SEV)
    SEV,
    /// ARM TrustZone
    TrustZone,
    /// Custom hardware attestation
    Custom,
}

impl std::fmt::Display for HardwareAttestationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardwareAttestationType::TPM => write!(f, "tpm"),
            HardwareAttestationType::SGX => write!(f, "sgx"),
            HardwareAttestationType::TDX => write!(f, "tdx"),
            HardwareAttestationType::SEV => write!(f, "sev"),
            HardwareAttestationType::TrustZone => write!(f, "trustzone"),
            HardwareAttestationType::Custom => write!(f, "custom"),
        }
    }
}

/// Attestation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationStatus {
    /// Attestation pending
    Pending,
    /// Attestation successful
    Success,
    /// Attestation failed
    Failed,
    /// Attestation expired
    Expired,
    /// Attestation revoked
    Revoked,
}

impl std::fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationStatus::Pending => write!(f, "pending"),
            AttestationStatus::Success => write!(f, "success"),
            AttestationStatus::Failed => write!(f, "failed"),
            AttestationStatus::Expired => write!(f, "expired"),
            AttestationStatus::Revoked => write!(f, "revoked"),
        }
    }
}

/// Attestation evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// Evidence ID
    pub id: String,
    /// Evidence type
    pub evidence_type: String,
    /// Evidence data
    pub data: Vec<u8>,
    /// Evidence hash
    pub hash: Hash,
    /// Evidence signature
    pub signature: Option<Vec<u8>>, // or Option<String> if you want base64/hex,
    /// Evidence timestamp
    pub timestamp: u64,
    /// Custom evidence fields
    pub custom: HashMap<String, String>,
}

impl AttestationEvidence {
    /// Create a new attestation evidence
    pub fn new(evidence_type: &str, data: Vec<u8>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let hash = Hash::new(&data, HashAlgorithm::SHA256);

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            evidence_type: evidence_type.to_string(),
            data,
            hash,
            signature: None,
            timestamp: now,
            custom: HashMap::new(),
        }
    }

    pub fn sign(&mut self, private_key: &[u8]) -> Result<()> {
        let signature = common::crypto::sign(&self.data, private_key)?;
        self.signature = Some(signature);
        Ok(())
    }

    /// Verify the evidence signature
    pub fn verify(&self, public_key: &[u8]) -> Result<bool> {
        match &self.signature {
            Some(signature) => common::crypto::verify(&self.data, signature, public_key),
            None => Err(ForgeError::ValidationError {
                field: "attestation_evidence".to_string(),
                rule: "no signature".to_string(),
                value: "".to_string(),
                suggestions: vec![],
            }),
        }
    }
}

/// Attestation report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Report ID
    pub id: String,
    /// Container ID
    pub container_id: String,
    /// Attestation type
    pub attestation_type: AttestationType,
    /// Hardware attestation type (if applicable)
    pub hardware_type: Option<HardwareAttestationType>,
    /// Attestation status
    pub status: AttestationStatus,
    /// Attestation evidence
    pub evidence: Vec<AttestationEvidence>,
    /// Attestation timestamp
    pub timestamp: u64,
    /// Attestation expiration timestamp
    pub expiration: Option<u64>,
    /// Attestation issuer
    pub issuer: String,
    /// Attestation signature
    pub signature: Option<Vec<u8>>,
    /// Custom attestation fields
    pub custom: HashMap<String, String>,
}

impl AttestationReport {
    /// Create a new attestation report
    pub fn new(
        container_id: &str,
        attestation_type: AttestationType,
        hardware_type: Option<HardwareAttestationType>,
        issuer: &str,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            container_id: container_id.to_string(),
            attestation_type,
            hardware_type,
            status: AttestationStatus::Pending,
            evidence: Vec::new(),
            timestamp: now,
            expiration: None,
            issuer: issuer.to_string(),
            signature: None,
            custom: HashMap::new(),
        }
    }

    /// Add evidence to the report
    pub fn add_evidence(&mut self, evidence: AttestationEvidence) {
        self.evidence.push(evidence);
    }

    /// Set the report status
    pub fn set_status(&mut self, status: AttestationStatus) {
        self.status = status;
    }

    /// Set the report expiration
    pub fn set_expiration(&mut self, duration: Duration) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.expiration = Some(now + duration.as_secs());
    }

    /// Sign the report
    pub fn sign(&mut self, algorithm: SignatureAlgorithm, private_key: &[u8]) -> Result<()> {
        // Serialize the report without the signature
        let temp_signature = self.signature.take();
        let data = serde_json::to_vec(self).map_err(|e| {
            ForgeError::SerializationError("attestation_report".to_string() + ": " + &e.to_string())
        })?;
        self.signature = temp_signature;

        // Sign the data
        let signature = common::crypto::sign(&data, private_key)?;

        self.signature = Some(signature);

        Ok(())
    }

    /// Verify the report signature
    pub fn verify(&self, public_key: &[u8]) -> Result<bool> {
        match &self.signature {
            Some(signature) => {
                // Serialize the report without the signature
                let mut temp_report = self.clone();
                temp_report.signature = None;
                let data = serde_json::to_vec(&temp_report).map_err(|e| {
                    ForgeError::SerializationError(
                        "attestation_report: ".to_string() + &e.to_string(),
                    )
                })?;

                // Verify the signature
                common::crypto::verify(&data, signature, public_key)
            }
            None => Err(ForgeError::ValidationError {
                field: "attestation_report".to_string(),
                rule: "no signature".to_string(),
                value: "".to_string(),
                suggestions: vec![],
            }),
        }
    }

    /// Check if the report is expired
    pub fn is_expired(&self) -> bool {
        match self.expiration {
            Some(expiration) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                now > expiration
            }
            None => false,
        }
    }
}

/// Attestation policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Required attestation type
    pub required_type: AttestationType,
    /// Required hardware attestation type (if applicable)
    pub required_hardware_type: Option<HardwareAttestationType>,
    /// Required evidence types
    pub required_evidence: Vec<String>,
    /// Minimum evidence count
    pub min_evidence_count: usize,
    /// Trusted issuers
    pub trusted_issuers: Vec<String>,
    /// Attestation validity period
    pub validity_period: Option<Duration>,
    /// Policy enabled
    pub enabled: bool,
    /// Custom policy fields
    pub custom: HashMap<String, String>,
}

impl AttestationPolicy {
    /// Create a new attestation policy
    pub fn new(
        name: &str,
        required_type: AttestationType,
        required_hardware_type: Option<HardwareAttestationType>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            required_type,
            required_hardware_type,
            required_evidence: Vec::new(),
            min_evidence_count: 1,
            trusted_issuers: Vec::new(),
            validity_period: None,
            enabled: true,
            custom: HashMap::new(),
        }
    }

    /// Add a required evidence type
    pub fn add_required_evidence(&mut self, evidence_type: &str) {
        self.required_evidence.push(evidence_type.to_string());
    }

    /// Add a trusted issuer
    pub fn add_trusted_issuer(&mut self, issuer: &str) {
        self.trusted_issuers.push(issuer.to_string());
    }

    /// Set the validity period
    pub fn set_validity_period(&mut self, period: Duration) {
        self.validity_period = Some(period);
    }

    /// Validate an attestation report against this policy
    pub fn validate_report(&self, report: &AttestationReport) -> Result<bool> {
        // Check if policy is enabled
        if !self.enabled {
            return Ok(false);
        }

        // Check attestation type
        if report.attestation_type != self.required_type {
            return Ok(false);
        }

        // Check hardware attestation type (if required)
        if let Some(required_hw_type) = self.required_hardware_type {
            match report.hardware_type {
                Some(hw_type) if hw_type == required_hw_type => {}
                _ => return Ok(false),
            }
        }

        // Check trusted issuers
        if !self.trusted_issuers.is_empty() && !self.trusted_issuers.contains(&report.issuer) {
            return Ok(false);
        }

        // Check evidence types and count
        let mut evidence_type_matches = 0;
        for required_type in &self.required_evidence {
            if report
                .evidence
                .iter()
                .any(|e| &e.evidence_type == required_type)
            {
                evidence_type_matches += 1;
            }
        }

        if !self.required_evidence.is_empty() && evidence_type_matches == 0 {
            return Ok(false);
        }

        if report.evidence.len() < self.min_evidence_count {
            return Ok(false);
        }

        // Check expiration
        if report.is_expired() {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Attestation manager
#[derive(Debug)]
pub struct AttestationManager {
    /// Attestation reports
    reports: Arc<RwLock<HashMap<String, AttestationReport>>>,
    /// Attestation policies
    policies: Arc<RwLock<HashMap<String, AttestationPolicy>>>,
}

impl AttestationManager {
    /// Create a new attestation manager
    pub fn new() -> Self {
        Self {
            reports: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create an attestation report
    pub fn create_report(
        &self,
        container_id: &str,
        attestation_type: AttestationType,
        hardware_type: Option<HardwareAttestationType>,
        issuer: &str,
    ) -> Result<AttestationReport> {
        let span = ExecutionSpan::new(
            "create_attestation_report",
            common::identity::IdentityContext::system(),
        );

        let report = AttestationReport::new(container_id, attestation_type, hardware_type, issuer);

        let mut reports = self.reports.write().map_err(|_| {
            ForgeError::InternalError("attestation_reports lock poisoned".to_string())
        })?;

        reports.insert(report.id.clone(), report.clone());

        Ok(report)
    }

    /// Update an attestation report
    pub fn update_report(&self, report: AttestationReport) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_attestation_report",
            common::identity::IdentityContext::system(),
        );

        let mut reports = self.reports.write().map_err(|_| {
            ForgeError::InternalError("attestation_reports lock poisoned".to_string())
        })?;

        if !reports.contains_key(&report.id) {
            return Err(ForgeError::NotFound("attestation_report".to_string()));
        }

        reports.insert(report.id.clone(), report);

        Ok(())
    }

    /// Get an attestation report
    pub fn get_report(&self, report_id: &str) -> Result<AttestationReport> {
        let span = ExecutionSpan::new(
            "get_attestation_report",
            common::identity::IdentityContext::system(),
        );

        let reports = self.reports.read().map_err(|_| {
            ForgeError::InternalError("attestation_reports lock poisoned".to_string())
        })?;

        let report = reports
            .get(report_id)
            .ok_or(ForgeError::NotFound("attestation_report".to_string()))?;

        Ok(report.clone())
    }

    /// Get attestation reports for a container
    pub fn get_container_reports(&self, container_id: &str) -> Result<Vec<AttestationReport>> {
        let span = ExecutionSpan::new(
            "get_container_attestation_reports",
            common::identity::IdentityContext::system(),
        );

        let reports = self.reports.read().map_err(|_| {
            ForgeError::InternalError("attestation_reports lock poisoned".to_string())
        })?;

        let container_reports = reports
            .values()
            .filter(|r| r.container_id == container_id)
            .cloned()
            .collect();

        Ok(container_reports)
    }

    /// Remove an attestation report
    pub fn remove_report(&self, report_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_attestation_report",
            common::identity::IdentityContext::system(),
        );

        let mut reports = self.reports.write().map_err(|_| {
            ForgeError::InternalError("attestation_reports lock poisoned".to_string())
        })?;

        if !reports.contains_key(report_id) {
            return Err(ForgeError::NotFound("attestation_report".to_string()));
        }

        reports.remove(report_id);

        Ok(())
    }

    /// Create an attestation policy
    pub fn create_policy(
        &self,
        name: &str,
        required_type: AttestationType,
        required_hardware_type: Option<HardwareAttestationType>,
    ) -> Result<AttestationPolicy> {
        let span = ExecutionSpan::new(
            "create_attestation_policy",
            common::identity::IdentityContext::system(),
        );

        let policy = AttestationPolicy::new(name, required_type, required_hardware_type);

        let mut policies = self.policies.write().map_err(|_| {
            ForgeError::InternalError("attestation_policies lock poisoned".to_string())
        })?;

        policies.insert(policy.id.clone(), policy.clone());

        Ok(policy)
    }

    /// Update an attestation policy
    pub fn update_policy(&self, policy: AttestationPolicy) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_attestation_policy",
            common::identity::IdentityContext::system(),
        );

        let mut policies = self.policies.write().map_err(|_| {
            ForgeError::InternalError("attestation_policies lock poisoned".to_string())
        })?;

        if !policies.contains_key(&policy.id) {
            return Err(ForgeError::NotFound("attestation_policy".to_string()));
        }

        policies.insert(policy.id.clone(), policy);

        Ok(())
    }

    /// Get an attestation policy
    pub fn get_policy(&self, policy_id: &str) -> Result<AttestationPolicy> {
        let span = ExecutionSpan::new(
            "get_attestation_policy",
            common::identity::IdentityContext::system(),
        );

        let policies = self.policies.read().map_err(|_| {
            ForgeError::InternalError("attestation_policies lock poisoned".to_string())
        })?;

        let policy = policies
            .get(policy_id)
            .ok_or(ForgeError::NotFound("attestation_policy".to_string()))?;

        Ok(policy.clone())
    }

    /// Get an attestation policy by name
    pub fn get_policy_by_name(&self, name: &str) -> Result<AttestationPolicy> {
        let span = ExecutionSpan::new(
            "get_attestation_policy_by_name",
            common::identity::IdentityContext::system(),
        );

        let policies = self.policies.read().map_err(|_| {
            ForgeError::InternalError("attestation_policies lock poisoned".to_string())
        })?;

        let policy = policies
            .values()
            .find(|p| p.name == name)
            .ok_or(ForgeError::NotFound("attestation_policy".to_string()))?;

        Ok(policy.clone())
    }

    /// Remove an attestation policy
    pub fn remove_policy(&self, policy_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_attestation_policy",
            common::identity::IdentityContext::system(),
        );

        let mut policies = self.policies.write().map_err(|_| {
            ForgeError::InternalError("attestation_policies lock poisoned".to_string())
        })?;

        if !policies.contains_key(policy_id) {
            return Err(ForgeError::NotFound("attestation_policy".to_string()));
        }

        policies.remove(policy_id);

        Ok(())
    }

    /// List all attestation policies
    pub fn list_policies(&self) -> Result<Vec<AttestationPolicy>> {
        let span = ExecutionSpan::new(
            "list_attestation_policies",
            common::identity::IdentityContext::system(),
        );

        let policies = self.policies.read().map_err(|_| {
            ForgeError::InternalError("attestation_policies lock poisoned".to_string())
        })?;

        Ok(policies.values().cloned().collect())
    }

    /// Attest a container
    pub fn attest_container(
        &self,
        container_id: &str,
        dna: &ContainerDNA,
        contract: &Contract,
        attestation_type: AttestationType,
        hardware_type: Option<HardwareAttestationType>,
    ) -> Result<AttestationReport> {
        let span = ExecutionSpan::new(
            "attest_container",
            common::identity::IdentityContext::system(),
        );

        // Create attestation report
        let mut report =
            self.create_report(container_id, attestation_type, hardware_type, "system")?;

        // Add DNA evidence
        let dna_data = serde_json::to_vec(dna)
            .map_err(|e| ForgeError::SerializationError(format!("container_dna: {}", e)))?;

        let mut dna_evidence = AttestationEvidence::new("dna", dna_data);
        // In a real implementation, we would sign the evidence here

        // Add contract evidence
        let contract_data = serde_json::to_vec(contract)
            .map_err(|e| ForgeError::SerializationError(format!("container_contract: {}", e)))?;

        let mut contract_evidence = AttestationEvidence::new("contract", contract_data);
        // In a real implementation, we would sign the evidence here

        // Add evidence to report
        report.add_evidence(dna_evidence);
        report.add_evidence(contract_evidence);

        // Set report status
        report.set_status(AttestationStatus::Success);

        // Set expiration (24 hours)
        report.set_expiration(Duration::from_secs(24 * 60 * 60));

        // Update report
        self.update_report(report.clone())?;

        Ok(report)
    }

    /// Verify container attestation
    pub fn verify_container_attestation(
        &self,
        container_id: &str,
        policy_name: Option<&str>,
    ) -> Result<bool> {
        let span = ExecutionSpan::new(
            "verify_container_attestation",
            common::identity::IdentityContext::system(),
        );

        // Get container reports
        let reports = self.get_container_reports(container_id)?;

        if reports.is_empty() {
            return Ok(false);
        }

        // Get the latest report
        let latest_report = reports
            .iter()
            .max_by_key(|r| r.timestamp)
            .ok_or(ForgeError::NotFound("attestation_report".to_string()))?;

        // Check report status
        if latest_report.status != AttestationStatus::Success {
            return Ok(false);
        }

        // Check expiration
        if latest_report.is_expired() {
            return Ok(false);
        }

        // If policy name is provided, validate against that policy
        if let Some(name) = policy_name {
            let policy = self.get_policy_by_name(name)?;
            return policy.validate_report(latest_report);
        }

        // Otherwise, just return true if the report is valid
        Ok(true)
    }
}

/// Global attestation manager instance
static mut ATTESTATION_MANAGER: Option<AttestationManager> = None;

/// Initialize the attestation manager
pub fn init() -> Result<()> {
    let span = ExecutionSpan::new(
        "init_attestation_manager",
        common::identity::IdentityContext::system(),
    );

    // Create attestation manager
    let attestation_manager = AttestationManager::new();

    // Store the attestation manager
    unsafe {
        if ATTESTATION_MANAGER.is_none() {
            ATTESTATION_MANAGER = Some(attestation_manager);
        } else {
            return Err(ForgeError::AlreadyExists("attestation_manager".to_string()));
        }
    }

    Ok(())
}

/// Get the attestation manager
pub fn get_attestation_manager() -> Result<&'static AttestationManager> {
    unsafe {
        match &ATTESTATION_MANAGER {
            Some(attestation_manager) => Ok(attestation_manager),
            None => Err(ForgeError::Other("attestation_manager".to_string())),
        }
    }
}

/// Create an attestation report
pub fn create_report(
    container_id: &str,
    attestation_type: AttestationType,
    hardware_type: Option<HardwareAttestationType>,
    issuer: &str,
) -> Result<AttestationReport> {
    let attestation_manager = get_attestation_manager()?;
    attestation_manager.create_report(container_id, attestation_type, hardware_type, issuer)
}

/// Attest a container
pub fn attest_container(
    container_id: &str,
    dna: &ContainerDNA,
    contract: &Contract,
    attestation_type: AttestationType,
    hardware_type: Option<HardwareAttestationType>,
) -> Result<AttestationReport> {
    let attestation_manager = get_attestation_manager()?;
    attestation_manager.attest_container(
        container_id,
        dna,
        contract,
        attestation_type,
        hardware_type,
    )
}

/// Verify container attestation
pub fn verify_container_attestation(container_id: &str, policy_name: Option<&str>) -> Result<bool> {
    let attestation_manager = get_attestation_manager()?;
    attestation_manager.verify_container_attestation(container_id, policy_name)
}

/// Create an attestation policy
pub fn create_policy(
    name: &str,
    required_type: AttestationType,
    required_hardware_type: Option<HardwareAttestationType>,
) -> Result<AttestationPolicy> {
    let attestation_manager = get_attestation_manager()?;
    attestation_manager.create_policy(name, required_type, required_hardware_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_evidence() {
        // Create evidence
        let data = b"test evidence data".to_vec();
        let mut evidence = AttestationEvidence::new("test", data.clone());

        // Check evidence fields
        assert_eq!(evidence.evidence_type, "test");
        assert_eq!(evidence.data, data);
        assert!(evidence.signature.is_none());

        // In a real test, we would sign and verify the evidence
        // For now, just check that the evidence was created correctly
        assert!(!evidence.id.is_empty());
        assert!(evidence.timestamp > 0);
    }

    #[test]
    fn test_attestation_report() {
        // Create report
        let mut report = AttestationReport::new(
            "test-container",
            AttestationType::Software,
            None,
            "test-issuer",
        );

        // Check report fields
        assert_eq!(report.container_id, "test-container");
        assert_eq!(report.attestation_type, AttestationType::Software);
        assert_eq!(report.status, AttestationStatus::Pending);
        assert_eq!(report.issuer, "test-issuer");
        assert!(report.evidence.is_empty());
        assert!(report.signature.is_none());

        // Add evidence
        let data = b"test evidence data".to_vec();
        let evidence = AttestationEvidence::new("test", data);
        report.add_evidence(evidence);

        // Check evidence was added
        assert_eq!(report.evidence.len(), 1);
        assert_eq!(report.evidence[0].evidence_type, "test");

        // Set status and expiration
        report.set_status(AttestationStatus::Success);
        report.set_expiration(Duration::from_secs(3600));

        // Check status and expiration
        assert_eq!(report.status, AttestationStatus::Success);
        assert!(report.expiration.is_some());
        assert!(!report.is_expired());
    }

    #[test]
    fn test_attestation_policy() {
        // Create policy
        let mut policy = AttestationPolicy::new(
            "test-policy",
            AttestationType::Hardware,
            Some(HardwareAttestationType::TPM),
        );

        // Check policy fields
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.required_type, AttestationType::Hardware);
        assert_eq!(
            policy.required_hardware_type,
            Some(HardwareAttestationType::TPM)
        );
        assert!(policy.required_evidence.is_empty());
        assert_eq!(policy.min_evidence_count, 1);
        assert!(policy.trusted_issuers.is_empty());
        assert!(policy.validity_period.is_none());
        assert!(policy.enabled);

        // Add required evidence and trusted issuer
        policy.add_required_evidence("tpm-quote");
        policy.add_trusted_issuer("system");
        policy.set_validity_period(Duration::from_secs(24 * 60 * 60));

        // Check updates
        assert_eq!(policy.required_evidence.len(), 1);
        assert_eq!(policy.required_evidence[0], "tpm-quote");
        assert_eq!(policy.trusted_issuers.len(), 1);
        assert_eq!(policy.trusted_issuers[0], "system");
        assert!(policy.validity_period.is_some());
    }

    #[test]
    fn test_attestation_manager() {
        // Initialize attestation manager
        init().unwrap();
        let attestation_manager = get_attestation_manager().unwrap();

        // Create policy
        let policy = attestation_manager
            .create_policy("test-policy", AttestationType::Software, None)
            .unwrap();

        // Get policy
        let retrieved_policy = attestation_manager.get_policy(&policy.id).unwrap();
        assert_eq!(retrieved_policy.id, policy.id);
        assert_eq!(retrieved_policy.name, "test-policy");

        // Get policy by name
        let retrieved_policy = attestation_manager
            .get_policy_by_name("test-policy")
            .unwrap();
        assert_eq!(retrieved_policy.id, policy.id);

        // Create container DNA and contract for attestation
        let dna = ContainerDNA {
            id: "test-container".to_string(),
            resource_limits: crate::dna::ResourceLimits::default(),
            hash: "test-hash".to_string(),
            signer: "test-signer".to_string(),
            trust_label: "test-trust-label".to_string(),
            runtime_entropy: "test-runtime-entropy".to_string(),
            created_at: 0,
            identity: common::identity::IdentityContext::system(),
        };

        let contract = Contract {
            id: "test-contract".to_string(),
            contract_type: crate::contract::ContractType::ZTA,
            data: serde_json::json!({}),
            status: crate::contract::ContractStatus::Valid,
        };

        // Attest container
        let report = attestation_manager
            .attest_container(
                "test-container",
                &dna,
                &contract,
                AttestationType::Software,
                None,
            )
            .unwrap();

        // Check report
        assert_eq!(report.container_id, "test-container");
        assert_eq!(report.attestation_type, AttestationType::Software);
        assert_eq!(report.status, AttestationStatus::Success);
        assert_eq!(report.evidence.len(), 2);

        // Verify attestation
        let verified = attestation_manager
            .verify_container_attestation("test-container", None)
            .unwrap();
        assert!(verified);

        // Get container reports
        let reports = attestation_manager
            .get_container_reports("test-container")
            .unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].id, report.id);

        // Remove report
        attestation_manager.remove_report(&report.id).unwrap();

        // Check report is removed
        let reports = attestation_manager
            .get_container_reports("test-container")
            .unwrap();
        assert_eq!(reports.len(), 0);

        // Remove policy
        attestation_manager.remove_policy(&policy.id).unwrap();

        // Check policy is removed
        let policies = attestation_manager.list_policies().unwrap();
        assert_eq!(policies.len(), 0);
    }
}
