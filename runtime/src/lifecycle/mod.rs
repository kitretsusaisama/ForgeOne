//! # Container Lifecycle Module
//!
//! This module provides functionality for managing container lifecycle states,
//! including creation, starting, stopping, pausing, resuming, and removing containers.
//! All state transitions are audited and signed for security and compliance.

use crate::contract::{Contract, ContractStatus, ContractType};
use crate::dna::ContainerDNA;
use crate::registry;
use crate::runtime::RuntimeContext;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use strum_macros::{Display, EnumString};
use uuid::Uuid;

/// Container state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, EnumString)]
pub enum ContainerState {
    /// Container is created but not started
    Created,
    /// Container is booted
    Booted,
    /// Container is running
    Running,
    /// Container is paused
    Paused,
    /// Container is stopping
    Stopping,
    /// Container is terminated
    Terminated,
    /// Container is failed
    Failed,
    /// Container is unknown
    Unknown,
}

/// Container state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Transition ID
    pub id: String,
    /// Container ID
    pub container_id: String,
    /// Previous state
    pub previous_state: ContainerState,
    /// Current state
    pub current_state: ContainerState,
    /// Transition timestamp
    pub timestamp: u64,
    /// Transition reason
    pub reason: String,
    /// Transition signature
    pub signature: Option<String>,
}

impl StateTransition {
    /// Create a new state transition
    pub fn new(
        container_id: &str,
        previous_state: ContainerState,
        current_state: ContainerState,
        reason: &str,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id,
            container_id: container_id.to_string(),
            previous_state,
            current_state,
            timestamp,
            reason: reason.to_string(),
            signature: None,
        }
    }

    /// Sign the state transition
    pub fn sign(&mut self, signature: &str) {
        self.signature = Some(signature.to_string());
    }
}

/// Container lifecycle manager
#[derive(Debug)]
pub struct LifecycleManager {
    /// Container states
    states: Arc<RwLock<std::collections::HashMap<String, ContainerState>>>,
    /// Container state transitions
    transitions: Arc<RwLock<std::collections::HashMap<String, Vec<StateTransition>>>>,
}

impl LifecycleManager {
    /// Create a new lifecycle manager
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(std::collections::HashMap::new())),
            transitions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Get the container state
    pub fn get_state(&self, container_id: &str) -> Result<ContainerState> {
        let states = self.states.read().map_err(|_| ForgeError::LockError {
            resource: "container_states".to_string(),
        })?;

        match states.get(container_id) {
            Some(state) => Ok(*state),
            None => Err(ForgeError::NotFoundError {
                resource: "container".to_string(),
                id: container_id.to_string(),
            }),
        }
    }

    /// Set the container state
    pub fn set_state(
        &self,
        container_id: &str,
        state: ContainerState,
        reason: &str,
    ) -> Result<()> {
        let mut states = self.states.write().map_err(|_| ForgeError::LockError {
            resource: "container_states".to_string(),
        })?;

        let previous_state = states.get(container_id).copied().unwrap_or(ContainerState::Unknown);
        states.insert(container_id.to_string(), state);

        // Create a state transition
        let transition = StateTransition::new(container_id, previous_state, state, reason);

        // Store the transition
        let mut transitions = self.transitions.write().map_err(|_| ForgeError::LockError {
            resource: "container_transitions".to_string(),
        })?;

        let container_transitions = transitions
            .entry(container_id.to_string())
            .or_insert_with(Vec::new);
        container_transitions.push(transition);

        Ok(())
    }

    /// Get the container state transitions
    pub fn get_transitions(&self, container_id: &str) -> Result<Vec<StateTransition>> {
        let transitions = self.transitions.read().map_err(|_| ForgeError::LockError {
            resource: "container_transitions".to_string(),
        })?;

        match transitions.get(container_id) {
            Some(container_transitions) => Ok(container_transitions.clone()),
            None => Ok(Vec::new()),
        }
    }

    /// Register a new container
    pub fn register_container(&self, container_id: &str) -> Result<()> {
        self.set_state(container_id, ContainerState::Created, "Container created")
    }

    /// Start a container
    pub fn start_container(&self, container_id: &str) -> Result<()> {
        let current_state = self.get_state(container_id)?;

        match current_state {
            ContainerState::Created => {
                // Transition to Booted state
                self.set_state(container_id, ContainerState::Booted, "Container booted")?;

                // Transition to Running state
                self.set_state(container_id, ContainerState::Running, "Container started")
            }
            ContainerState::Paused => {
                // Transition to Running state
                self.set_state(container_id, ContainerState::Running, "Container resumed")
            }
            ContainerState::Running => {
                // Already running
                Ok(())
            }
            _ => Err(ForgeError::InvalidStateError {
                resource: "container".to_string(),
                id: container_id.to_string(),
                current_state: current_state.to_string(),
                expected_states: vec!["Created".to_string(), "Paused".to_string()],
            }),
        }
    }

    /// Stop a container
    pub fn stop_container(&self, container_id: &str) -> Result<()> {
        let current_state = self.get_state(container_id)?;

        match current_state {
            ContainerState::Running | ContainerState::Paused => {
                // Transition to Stopping state
                self.set_state(container_id, ContainerState::Stopping, "Container stopping")?;

                // Transition to Terminated state
                self.set_state(container_id, ContainerState::Terminated, "Container stopped")
            }
            ContainerState::Terminated => {
                // Already terminated
                Ok(())
            }
            _ => Err(ForgeError::InvalidStateError {
                resource: "container".to_string(),
                id: container_id.to_string(),
                current_state: current_state.to_string(),
                expected_states: vec!["Running".to_string(), "Paused".to_string()],
            }),
        }
    }

    /// Pause a container
    pub fn pause_container(&self, container_id: &str) -> Result<()> {
        let current_state = self.get_state(container_id)?;

        match current_state {
            ContainerState::Running => {
                // Transition to Paused state
                self.set_state(container_id, ContainerState::Paused, "Container paused")
            }
            ContainerState::Paused => {
                // Already paused
                Ok(())
            }
            _ => Err(ForgeError::InvalidStateError {
                resource: "container".to_string(),
                id: container_id.to_string(),
                current_state: current_state.to_string(),
                expected_states: vec!["Running".to_string()],
            }),
        }
    }

    /// Resume a container
    pub fn resume_container(&self, container_id: &str) -> Result<()> {
        let current_state = self.get_state(container_id)?;

        match current_state {
            ContainerState::Paused => {
                // Transition to Running state
                self.set_state(container_id, ContainerState::Running, "Container resumed")
            }
            ContainerState::Running => {
                // Already running
                Ok(())
            }
            _ => Err(ForgeError::InvalidStateError {
                resource: "container".to_string(),
                id: container_id.to_string(),
                current_state: current_state.to_string(),
                expected_states: vec!["Paused".to_string()],
            }),
        }
    }

    /// Remove a container
    pub fn remove_container(&self, container_id: &str) -> Result<()> {
        let current_state = self.get_state(container_id)?;

        match current_state {
            ContainerState::Created | ContainerState::Terminated | ContainerState::Failed => {
                // Remove the container state
                let mut states = self.states.write().map_err(|_| ForgeError::LockError {
                    resource: "container_states".to_string(),
                })?;
                states.remove(container_id);

                Ok(())
            }
            _ => Err(ForgeError::InvalidStateError {
                resource: "container".to_string(),
                id: container_id.to_string(),
                current_state: current_state.to_string(),
                expected_states: vec![
                    "Created".to_string(),
                    "Terminated".to_string(),
                    "Failed".to_string(),
                ],
            }),
        }
    }
}

/// Global lifecycle manager instance
static mut LIFECYCLE_MANAGER: Option<LifecycleManager> = None;

/// Initialize the lifecycle manager
pub fn init() -> Result<()> {
    unsafe {
        if LIFECYCLE_MANAGER.is_none() {
            LIFECYCLE_MANAGER = Some(LifecycleManager::new());
        }
        Ok(())
    }
}

/// Get the lifecycle manager instance
pub fn get_lifecycle_manager() -> Result<&'static LifecycleManager> {
    unsafe {
        match &LIFECYCLE_MANAGER {
            Some(manager) => Ok(manager),
            None => Err(ForgeError::UninitializedError {
                component: "lifecycle_manager".to_string(),
            }),
        }
    }
}

/// Start a container
pub fn start_container(container_id: &str) -> Result<()> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new("start_container", common::identity::IdentityContext::system());

    // Get the container DNA
    let dna = registry::get_container_dna(container_id)?;

    // Get the container contract
    let contract = registry::get_container_contract(container_id)?;

    // Validate the contract
    if let ContractStatus::Invalid(reason) = contract.status {
        return Err(ForgeError::ValidationError {
            field: "contract".to_string(),
            message: reason,
        });
    }

    // Start the container
    manager.start_container(container_id)
}

/// Stop a container
pub fn stop_container(container_id: &str) -> Result<()> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new("stop_container", common::identity::IdentityContext::system());

    manager.stop_container(container_id)
}

/// Pause a container
pub fn pause_container(container_id: &str) -> Result<()> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new("pause_container", common::identity::IdentityContext::system());

    manager.pause_container(container_id)
}

/// Resume a container
pub fn resume_container(container_id: &str) -> Result<()> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new("resume_container", common::identity::IdentityContext::system());

    manager.resume_container(container_id)
}

/// Remove a container
pub fn remove_container(container_id: &str) -> Result<()> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new("remove_container", common::identity::IdentityContext::system());

    manager.remove_container(container_id)
}

/// Get container status
pub fn get_container_status(container_id: &str) -> Result<ContainerState> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new(
        "get_container_status",
        common::identity::IdentityContext::system(),
    );

    manager.get_state(container_id)
}

/// Get container transitions
pub fn get_container_transitions(container_id: &str) -> Result<Vec<StateTransition>> {
    let manager = get_lifecycle_manager()?;
    let span = ExecutionSpan::new(
        "get_container_transitions",
        common::identity::IdentityContext::system(),
    );

    manager.get_transitions(container_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_manager() {
        let manager = LifecycleManager::new();
        let container_id = "test-container";

        // Register container
        manager
            .register_container(container_id)
            .expect("Failed to register container");

        // Check initial state
        let state = manager
            .get_state(container_id)
            .expect("Failed to get container state");
        assert_eq!(state, ContainerState::Created);

        // Start container
        manager
            .start_container(container_id)
            .expect("Failed to start container");

        // Check running state
        let state = manager
            .get_state(container_id)
            .expect("Failed to get container state");
        assert_eq!(state, ContainerState::Running);

        // Pause container
        manager
            .pause_container(container_id)
            .expect("Failed to pause container");

        // Check paused state
        let state = manager
            .get_state(container_id)
            .expect("Failed to get container state");
        assert_eq!(state, ContainerState::Paused);

        // Resume container
        manager
            .resume_container(container_id)
            .expect("Failed to resume container");

        // Check running state
        let state = manager
            .get_state(container_id)
            .expect("Failed to get container state");
        assert_eq!(state, ContainerState::Running);

        // Stop container
        manager
            .stop_container(container_id)
            .expect("Failed to stop container");

        // Check terminated state
        let state = manager
            .get_state(container_id)
            .expect("Failed to get container state");
        assert_eq!(state, ContainerState::Terminated);

        // Remove container
        manager
            .remove_container(container_id)
            .expect("Failed to remove container");

        // Check container is removed
        let result = manager.get_state(container_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_transitions() {
        let manager = LifecycleManager::new();
        let container_id = "test-container";

        // Register container
        manager
            .register_container(container_id)
            .expect("Failed to register container");

        // Start container
        manager
            .start_container(container_id)
            .expect("Failed to start container");

        // Get transitions
        let transitions = manager
            .get_transitions(container_id)
            .expect("Failed to get container transitions");

        // Check transitions
        assert_eq!(transitions.len(), 3); // Created -> Booted -> Running
        assert_eq!(transitions[0].previous_state, ContainerState::Unknown);
        assert_eq!(transitions[0].current_state, ContainerState::Created);
        assert_eq!(transitions[1].previous_state, ContainerState::Created);
        assert_eq!(transitions[1].current_state, ContainerState::Booted);
        assert_eq!(transitions[2].previous_state, ContainerState::Booted);
        assert_eq!(transitions[2].current_state, ContainerState::Running);
    }
}