//! # Container Registry Module
//!
//! This module provides functionality for registering, tracking, and querying
//! containers and their associated metadata, including DNA and contracts.

mod create;

use crate::contract::Contract;
use crate::dna::ContainerDNA;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Container registration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRegistration {
    /// Container ID
    pub id: String,
    /// Container name
    pub name: String,
    /// Container DNA
    pub dna: ContainerDNA,
    /// Container contract
    pub contract: Contract,
    /// Registration time in seconds since epoch
    pub registered_at: u64,
    /// Last updated time in seconds since epoch
    pub updated_at: u64,
    /// Container labels
    pub labels: HashMap<String, String>,
    /// Container annotations
    pub annotations: HashMap<String, String>,
}

impl ContainerRegistration {
    /// Create a new container registration
    pub fn new(id: &str, name: &str, dna: ContainerDNA, contract: Contract) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: id.to_string(),
            name: name.to_string(),
            dna,
            contract,
            registered_at: now,
            updated_at: now,
            labels: HashMap::new(),
            annotations: HashMap::new(),
        }
    }

    /// Add a label
    pub fn add_label(&mut self, key: &str, value: &str) {
        self.labels.insert(key.to_string(), value.to_string());
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Remove a label
    pub fn remove_label(&mut self, key: &str) -> Option<String> {
        let result = self.labels.remove(key);
        if result.is_some() {
            self.updated_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        result
    }

    /// Add an annotation
    pub fn add_annotation(&mut self, key: &str, value: &str) {
        self.annotations.insert(key.to_string(), value.to_string());
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Remove an annotation
    pub fn remove_annotation(&mut self, key: &str) -> Option<String> {
        let result = self.annotations.remove(key);
        if result.is_some() {
            self.updated_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
        result
    }
}

/// Container registry
#[derive(Debug)]
pub struct ContainerRegistry {
    /// Map of container ID to container registration
    registrations: Arc<RwLock<HashMap<String, ContainerRegistration>>>,
    /// Map of container name to container ID
    name_to_id: Arc<RwLock<HashMap<String, String>>>,
}

impl ContainerRegistry {
    /// Create a new container registry
    pub fn new() -> Self {
        Self {
            registrations: Arc::new(RwLock::new(HashMap::new())),
            name_to_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a container
    pub fn register_container(
        &self,
        id: &str,
        name: &str,
        dna: ContainerDNA,
        contract: Contract,
    ) -> Result<()> {
        let span = ExecutionSpan::new(
            "register_container",
            common::identity::IdentityContext::system(),
        );

        // Create container registration
        let registration = ContainerRegistration::new(id, name, dna, contract);

        // Add to registrations
        let mut registrations = self.registrations.write().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        // Check if container with the same ID already exists
        if registrations.contains_key(id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "container".to_string(),
                id: id.to_string(),
            });
        }

        // Add to name to ID map
        let mut name_to_id = self.name_to_id.write().map_err(|_| {
            ForgeError::InternalError("container_name_to_id lock poisoned".to_string())
        })?;

        // Check if container with the same name already exists
        if name_to_id.contains_key(name) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "container".to_string(),
                id: name.to_string(),
            });
        }

        // Add to maps
        registrations.insert(id.to_string(), registration);
        name_to_id.insert(name.to_string(), id.to_string());

        Ok(())
    }

    /// Unregister a container
    pub fn unregister_container(&self, id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unregister_container",
            common::identity::IdentityContext::system(),
        );

        // Get container registration
        let mut registrations = self.registrations.write().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        let registration = registrations
            .get(id)
            .ok_or(ForgeError::NotFound(format!("container: {}", id)))?;

        // Remove from name to ID map
        let mut name_to_id = self.name_to_id.write().map_err(|_| {
            ForgeError::InternalError("container_name_to_id lock poisoned".to_string())
        })?;

        name_to_id.remove(&registration.name);

        // Remove from registrations
        registrations.remove(id);

        Ok(())
    }

    /// Get container registration by ID
    pub fn get_container(&self, id: &str) -> Result<ContainerRegistration> {
        let span = ExecutionSpan::new("get_container", common::identity::IdentityContext::system());

        // Get container registration
        let registrations = self.registrations.read().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        let registration = registrations
            .get(id)
            .ok_or(ForgeError::NotFound(format!("container: {}", id)))?;

        Ok(registration.clone())
    }

    /// Get container registration by name
    pub fn get_container_by_name(&self, name: &str) -> Result<ContainerRegistration> {
        let span = ExecutionSpan::new(
            "get_container_by_name",
            common::identity::IdentityContext::system(),
        );

        // Get container ID from name
        let name_to_id = self.name_to_id.read().map_err(|_| {
            ForgeError::InternalError("container_name_to_id lock poisoned".to_string())
        })?;

        let id = name_to_id
            .get(name)
            .ok_or(ForgeError::NotFound(format!("container: {}", name)))?;

        // Get container registration
        self.get_container(id)
    }

    /// Get container DNA
    pub fn get_container_dna(&self, id: &str) -> Result<ContainerDNA> {
        let span = ExecutionSpan::new(
            "get_container_dna",
            common::identity::IdentityContext::system(),
        );

        // Get container registration
        let registration = self.get_container(id)?;

        Ok(registration.dna)
    }

    /// Get container contract
    pub fn get_container_contract(&self, id: &str) -> Result<Contract> {
        let span = ExecutionSpan::new(
            "get_container_contract",
            common::identity::IdentityContext::system(),
        );

        // Get container registration
        let registration = self.get_container(id)?;

        Ok(registration.contract)
    }

    /// List all containers
    pub fn list_containers(&self) -> Result<Vec<ContainerRegistration>> {
        let span = ExecutionSpan::new(
            "list_containers",
            common::identity::IdentityContext::system(),
        );

        // Get all container registrations
        let registrations = self.registrations.read().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        Ok(registrations.values().cloned().collect())
    }

    /// List containers by label
    pub fn list_containers_by_label(
        &self,
        key: &str,
        value: &str,
    ) -> Result<Vec<ContainerRegistration>> {
        let span = ExecutionSpan::new(
            "list_containers_by_label",
            common::identity::IdentityContext::system(),
        );

        // Get all container registrations
        let registrations = self.registrations.read().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        // Filter by label
        let filtered = registrations
            .values()
            .filter(|r| r.labels.get(key).map_or(false, |v| v == value))
            .cloned()
            .collect();

        Ok(filtered)
    }

    /// Update container labels
    pub fn update_container_labels(&self, id: &str, labels: HashMap<String, String>) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_container_labels",
            common::identity::IdentityContext::system(),
        );

        // Get container registration
        let mut registrations = self.registrations.write().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        let registration = registrations
            .get_mut(id)
            .ok_or(ForgeError::NotFound(format!("container: {}", id)))?;

        // Update labels
        registration.labels = labels;
        registration.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }

    /// Update container annotations
    pub fn update_container_annotations(
        &self,
        id: &str,
        annotations: HashMap<String, String>,
    ) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_container_annotations",
            common::identity::IdentityContext::system(),
        );

        // Get container registration
        let mut registrations = self.registrations.write().map_err(|_| {
            ForgeError::InternalError("container_registrations lock poisoned".to_string())
        })?;

        let registration = registrations
            .get_mut(id)
            .ok_or(ForgeError::NotFound(format!("container: {}", id)))?;

        // Update annotations
        registration.annotations = annotations;
        registration.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(())
    }
}

/// Global container registry instance
static mut CONTAINER_REGISTRY: Option<ContainerRegistry> = None;

/// Initialize the container registry
pub fn init() -> Result<()> {
    let span = ExecutionSpan::new(
        "init_container_registry",
        common::identity::IdentityContext::system(),
    );

    // Create container registry
    let registry = ContainerRegistry::new();

    // Store the container registry
    unsafe {
        if CONTAINER_REGISTRY.is_none() {
            CONTAINER_REGISTRY = Some(registry);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "container_registry".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the container registry
pub fn get_container_registry() -> Result<&'static ContainerRegistry> {
    unsafe {
        match &CONTAINER_REGISTRY {
            Some(registry) => Ok(registry),
            None => Err(ForgeError::InternalError(
                "container_registry not initialized".to_string(),
            )),
        }
    }
}

/// Register a container
pub fn register_container(
    id: &str,
    name: &str,
    dna: ContainerDNA,
    contract: Contract,
) -> Result<()> {
    let registry = get_container_registry()?;
    registry.register_container(id, name, dna, contract)
}

/// Unregister a container
pub fn unregister_container(id: &str) -> Result<()> {
    let registry = get_container_registry()?;
    registry.unregister_container(id)
}

/// Get container registration
pub fn get_container(id: &str) -> Result<ContainerRegistration> {
    let registry = get_container_registry()?;
    registry.get_container(id)
}

/// Get container registration by name
pub fn get_container_by_name(name: &str) -> Result<ContainerRegistration> {
    let registry = get_container_registry()?;
    registry.get_container_by_name(name)
}

/// Get container DNA
pub fn get_container_dna(id: &str) -> Result<ContainerDNA> {
    let registry = get_container_registry()?;
    registry.get_container_dna(id)
}

/// Get container contract
pub fn get_container_contract(id: &str) -> Result<Contract> {
    let registry = get_container_registry()?;
    registry.get_container_contract(id)
}

/// List all containers
pub fn list_containers() -> Result<Vec<ContainerRegistration>> {
    let registry = get_container_registry()?;
    registry.list_containers()
}

/// List containers by label
pub fn list_containers_by_label(key: &str, value: &str) -> Result<Vec<ContainerRegistration>> {
    let registry = get_container_registry()?;
    registry.list_containers_by_label(key, value)
}

/// Update container labels
pub fn update_container_labels(id: &str, labels: HashMap<String, String>) -> Result<()> {
    let registry = get_container_registry()?;
    registry.update_container_labels(id, labels)
}

/// Get container annotations
pub fn update_container_annotations(id: &str, annotations: HashMap<String, String>) -> Result<()> {
    let registry = get_container_registry()?;
    registry.update_container_annotations(id, annotations)
}

/// Create a new container from an image
pub fn create_container(
    image_path: &str,
    container_id: Option<&str>,
    config: Option<&crate::config::ContainerConfig>,
) -> Result<String> {
    create::create_container(image_path, container_id, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::{ContractStatus, ContractType};

    #[test]
    fn test_container_registry() {
        // Initialize container registry
        init().unwrap();
        let registry = get_container_registry().unwrap();

        // Create container DNA
        let dna = ContainerDNA::new(
            "test-image",
            "test-signer",
            crate::dna::ResourceLimits::default(),
            "trusted",
            common::identity::IdentityContext::system(),
        );

        // Create container contract
        let zta_contract = crate::contract::zta::ZTAContract::new(
            "default-policy",
            vec!["test-signer".to_string()],
            0.0,
            crate::contract::zta::ExecMode::Restricted,
        );
        let contract = Contract::new(
            "test-contract",
            ContractType::ZTA,
            serde_json::to_value(zta_contract).unwrap(),
        );

        // Register container
        registry
            .register_container("test-id", "test-container", dna.clone(), contract.clone())
            .unwrap();

        // Get container
        let registration = registry.get_container("test-id").unwrap();
        assert_eq!(registration.id, "test-id");
        assert_eq!(registration.name, "test-container");
        assert_eq!(registration.dna.hash, "test-image");
        assert_eq!(registration.dna.signer, "test-signer");
        assert_eq!(registration.dna.trust_label, "trusted");
        assert!(matches!(
            registration.contract.contract_type(),
            ContractType::ZTA
        ));
        // Get container by name
        let registration = registry.get_container_by_name("test-container").unwrap();
        assert_eq!(registration.id, "test-id");

        // Get container DNA
        let container_dna = registry.get_container_dna("test-id").unwrap();
        assert_eq!(container_dna.hash, "test-image");
        assert_eq!(container_dna.signer, "test-signer");
        assert_eq!(container_dna.trust_label, "trusted");

        // Get container contract
        let container_contract = registry.get_container_contract("test-id").unwrap();
        assert!(matches!(
            container_contract.contract_type(),
            ContractType::ZTA
        ));

        // Update container labels
        let mut labels = HashMap::new();
        labels.insert("key1".to_string(), "value1".to_string());
        labels.insert("key2".to_string(), "value2".to_string());
        registry.update_container_labels("test-id", labels).unwrap();

        // Get container with updated labels
        let registration = registry.get_container("test-id").unwrap();
        assert_eq!(registration.labels.len(), 2);
        assert_eq!(registration.labels.get("key1"), Some(&"value1".to_string()));

        // List containers
        let containers = registry.list_containers().unwrap();
        assert_eq!(containers.len(), 1);

        // List containers by label
        let containers = registry.list_containers_by_label("key1", "value1").unwrap();
        assert_eq!(containers.len(), 1);

        // Unregister container
        registry.unregister_container("test-id").unwrap();

        // Check container is unregistered
        let result = registry.get_container("test-id");
        assert!(result.is_err());
    }
}
