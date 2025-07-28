//! # Container Creation Module
//!
//! This module provides functionality for creating containers from images
//! and registering them in the container registry.

use crate::config::ContainerConfig;
use crate::contract::{Contract, ContractType};
use crate::dna::ContainerDNA;
use crate::dna::ResourceLimits;
use crate::fs;
use crate::lifecycle;
use crate::metrics;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use std::path::Path;
use uuid::Uuid;

/// Create a new container from an image
pub fn create_container(
    image_path: &str,
    container_id: Option<&str>,
    config: Option<&ContainerConfig>,
) -> Result<String> {
    let span = ExecutionSpan::new(
        "create_container",
        common::identity::IdentityContext::system(),
    );

    // Generate container ID if not provided
    let id = match container_id {
        Some(id) => id.to_string(),
        None => Uuid::new_v4().to_string(),
    };

    // Extract container name from config or use ID
    let name = match config {
        Some(cfg) => match &cfg.name {
            Some(name) => name.clone(),
            None => id.clone(),
        },
        None => id.clone(),
    };

    // Create container DNA
    let dna = match config {
        Some(cfg) => {
            ContainerDNA::new(
                &cfg.image,
                "test-signer", // Replace with actual signer if available
                cfg.resource_limits.clone().unwrap_or_default(),
                "trusted", // Replace with actual trust_label if available
                common::identity::IdentityContext::system(),
            )
        }
        None => {
            // Extract image name and tag from path
            let image_name = Path::new(image_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");

            ContainerDNA::new(
                image_name,
                "test-signer",
                ResourceLimits::default(),
                "trusted",
                common::identity::IdentityContext::system(),
            )
        }
    };

    // Create container contract
    let zta_contract = crate::contract::zta::ZTAContract::new(
        "default-policy",                           // runtime_policy_id
        vec!["test-signer".to_string()],            // trusted_issuers
        0.0,                                        // minimum_entropy
        crate::contract::zta::ExecMode::Restricted, // exec_mode
    );
    let contract = Contract::new(
        &id,
        ContractType::ZTA,
        serde_json::to_value(zta_contract).unwrap(),
    );

    // (No-op: contract config fields are not settable post-creation in this model)

    // Create container filesystem
    fs::create_container_fs(&id, &dna)?;

    // Register container
    super::register_container(&id, &name, dna, contract)?;

    // Register container metrics
    metrics::register_container(&id)?;

    // Apply additional configuration if provided
    if let Some(cfg) = config {
        // Apply labels if provided
        if let Some(labels) = &cfg.labels {
            super::update_container_labels(&id, labels.clone())?;
        }

        // Apply annotations if provided
        if let Some(annotations) = &cfg.annotations {
            super::update_container_annotations(&id, annotations.clone())?;
        }

        // TODO: Apply network configuration
        // TODO: Apply volume configuration
        // TODO: Apply mount configuration
    }

    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;
    use std::collections::HashMap;

    #[test]
    fn test_create_container_with_config() {
        // Initialize registry
        registry::init().unwrap();

        // Create container configuration
        let mut config = ContainerConfig::new("test-image");
        config.name = Some("test-container".to_string());
        config.command = Some("test-command".to_string());
        config.args = Some(vec!["arg1".to_string(), "arg2".to_string()]);

        let mut labels = HashMap::new();
        labels.insert("key1".to_string(), "value1".to_string());
        config.labels = Some(labels);

        // Create container
        let container_id = create_container("test-image", None, Some(&config)).unwrap();

        // Get container
        let container = registry::get_container(&container_id).unwrap();

        // Verify container properties
        assert_eq!(container.name, "test-container");
        assert_eq!(container.dna.hash, "test-image");
        assert_eq!(container.dna.signer, "test-signer");
        assert_eq!(container.dna.trust_label, "trusted");
        assert_eq!(container.labels.get("key1"), Some(&"value1".to_string()));

        // Clean up
        registry::unregister_container(&container_id).unwrap();
    }

    #[test]
    fn test_create_container_without_config() {
        // Initialize registry
        registry::init().unwrap();

        // Create container
        let container_id = create_container("test-image", Some("test-id"), None).unwrap();

        // Get container
        let container = registry::get_container("test-id").unwrap();

        // Verify container properties
        assert_eq!(container.id, "test-id");
        assert_eq!(container.name, "test-id");
        assert_eq!(container.dna.hash, "test-image");

        // Clean up
        registry::unregister_container("test-id").unwrap();
    }
}
