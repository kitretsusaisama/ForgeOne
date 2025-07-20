//! Runtime subsystem for the ForgeOne Microkernel
//!
//! Provides runtime orchestration, container management, and workload execution.

use crate::core::boot::BootContext;
use common::config::runtime::RuntimeConfig;
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Runtime context for the microkernel
#[derive(Debug)]
pub struct RuntimeContext {
    /// Unique identifier for this runtime session
    pub id: Uuid,
    /// Boot context reference
    pub boot_context: Arc<BootContext>,
    /// Active containers
    pub containers: Mutex<HashMap<Uuid, ContainerContext>>,
    /// Runtime state
    pub state: Mutex<RuntimeState>,
    /// Runtime metrics
    pub metrics: Mutex<RuntimeMetrics>,
}

/// Container context for workload execution
#[derive(Debug, Clone)]
pub struct ContainerContext {
    /// Unique identifier for this container
    pub id: Uuid,
    /// Container name
    pub name: String,
    /// Container state
    pub state: ContainerState,
    /// Container workload
    pub workload: Workload,
    /// Container creation time
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Container identity context
    pub identity: IdentityContext,
    /// Container resource limits
    pub resource_limits: ResourceLimits,
}

/// Workload definition
#[derive(Debug, Clone)]
pub struct Workload {
    /// Workload type
    pub workload_type: WorkloadType,
    /// Workload source
    pub source: String,
    /// Workload arguments
    pub args: Vec<String>,
    /// Workload environment variables
    pub env: HashMap<String, String>,
    /// Workload entry point
    pub entry_point: String,
}

/// Resource limits for containers
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// CPU limit in millicores
    pub cpu_millicores: u32,
    /// Memory limit in megabytes
    pub memory_mb: u32,
    /// Disk limit in megabytes
    pub disk_mb: u32,
    /// Network bandwidth limit in kilobits per second
    pub network_kbps: u32,
}

/// Runtime state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeState {
    /// Runtime is initializing
    Initializing,
    /// Runtime is running
    Running,
    /// Runtime is shutting down
    ShuttingDown,
    /// Runtime is in error state
    Error(String),
}

/// Container state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerState {
    /// Container is creating
    Creating,
    /// Container is running
    Running,
    /// Container is paused
    Paused,
    /// Container is stopping
    Stopping,
    /// Container is stopped
    Stopped,
    /// Container is in error state
    Error(String),
}

/// Workload type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadType {
    /// WebAssembly workload
    Wasm,
    /// Native workload
    Native,
    /// Container workload
    Container,
    /// Function workload
    Function,
}

/// Runtime metrics
#[derive(Debug, Clone)]
pub struct RuntimeMetrics {
    /// Number of active containers
    pub active_containers: usize,
    /// Number of completed containers
    pub completed_containers: usize,
    /// Number of failed containers
    pub failed_containers: usize,
    /// CPU usage in percentage
    pub cpu_usage_percent: f64,
    /// Memory usage in megabytes
    pub memory_usage_mb: u64,
    /// Disk usage in megabytes
    pub disk_usage_mb: u64,
    /// Network usage in kilobits per second
    pub network_usage_kbps: u64,
}

// Global runtime context
static mut RUNTIME_CONTEXT: Option<Arc<RuntimeContext>> = None;

/// Initialize the runtime subsystem
pub fn init(boot_context: &BootContext) -> Result<()> {
    let runtime_context = RuntimeContext {
        id: Uuid::new_v4(),
        boot_context: Arc::new(boot_context.clone()),
        containers: Mutex::new(HashMap::new()),
        state: Mutex::new(RuntimeState::Initializing),
        metrics: Mutex::new(RuntimeMetrics {
            active_containers: 0,
            completed_containers: 0,
            failed_containers: 0,
            cpu_usage_percent: 0.0,
            memory_usage_mb: 0,
            disk_usage_mb: 0,
            network_usage_kbps: 0,
        }),
    };

    tracing::info!(runtime_id = %runtime_context.id, "Runtime initialized");
    unsafe {
        RUNTIME_CONTEXT = Some(Arc::new(runtime_context));
    }

    // Set the runtime state to Running
    if let Some(context) = unsafe { RUNTIME_CONTEXT.as_ref() } {
        let mut state = context.state.lock().unwrap();
        *state = RuntimeState::Running;
    }
    Ok(())
}

/// Initialize the runtime subsystem with custom configuration
pub fn init_with_config(boot_context: &BootContext, config: &RuntimeConfig) -> Result<()> {
    let runtime_context = RuntimeContext {
        id: Uuid::new_v4(),
        boot_context: Arc::new(boot_context.clone()),
        containers: Mutex::new(HashMap::new()),
        state: Mutex::new(RuntimeState::Initializing),
        metrics: Mutex::new(RuntimeMetrics {
            active_containers: 0,
            completed_containers: 0,
            failed_containers: 0,
            cpu_usage_percent: 0.0,
            memory_usage_mb: 0,
            disk_usage_mb: 0,
            network_usage_kbps: 0,
        }),
    };

    tracing::info!(runtime_id = %runtime_context.id, "Runtime initialized with custom config");
    unsafe {
        RUNTIME_CONTEXT = Some(Arc::new(runtime_context));
    }

    // Set the runtime state to Running
    if let Some(context) = unsafe { RUNTIME_CONTEXT.as_ref() } {
        let mut state = context.state.lock().unwrap();
        *state = RuntimeState::Running;
    }

    Ok(())
}

/// Shutdown the runtime subsystem
pub fn shutdown() -> Result<()> {
    if let Some(context) = unsafe { RUNTIME_CONTEXT.as_ref() } {
        // Set the runtime state to ShuttingDown
        {
            let mut state = context.state.lock().unwrap();
            *state = RuntimeState::ShuttingDown;
        }

        // Stop all containers
        let container_ids: Vec<Uuid> = {
            let containers = context.containers.lock().unwrap();
            containers.keys().cloned().collect()
        };

        for container_id in container_ids {
            stop_container(&container_id)?;
        }

        // Clear the global runtime context
        unsafe {
            RUNTIME_CONTEXT = None;
        }

        tracing::info!(runtime_id = %context.id, "Runtime shutdown complete");
    }

    Ok(())
}

/// Get the runtime context
pub fn get_runtime_context() -> Result<Arc<RuntimeContext>> {
    unsafe {
        RUNTIME_CONTEXT
            .as_ref()
            .cloned()
            .ok_or_else(|| ForgeError::InvalidStateTransition {
                message: "Runtime context not initialized".to_string(),
            })
    }
}

/// Launch a new container
pub fn launch_container(workload: Workload, identity: &IdentityContext) -> Result<Uuid> {
    let context = get_runtime_context()?;

    let container_id = Uuid::new_v4();
    let container_name = format!(
        "container-{}",
        container_id.to_string().split('-').next().unwrap()
    );

    let container = ContainerContext {
        id: container_id,
        name: container_name,
        state: ContainerState::Creating,
        workload,
        created_at: chrono::Utc::now(),
        identity: identity.clone(),
        resource_limits: ResourceLimits {
            cpu_millicores: 1000, // 1 CPU core
            memory_mb: 512,       // 512 MB
            disk_mb: 1024,        // 1 GB
            network_kbps: 10240,  // 10 Mbps
        },
    };

    // Add the container to the runtime context
    {
        let mut containers = context.containers.lock().unwrap();
        containers.insert(container_id, container.clone());
    }

    // Update metrics
    {
        let mut metrics = context.metrics.lock().unwrap();
        metrics.active_containers += 1;
    }

    // Start the container
    start_container(&container_id)?;

    tracing::info!(container_id = %container_id, container_name = %container.name, workload_type = ?container.workload.workload_type, "Container launched");

    Ok(container_id)
}

/// Start a container
pub fn start_container(container_id: &Uuid) -> Result<()> {
    let context = get_runtime_context()?;

    // Get the container
    let mut container = {
        let mut containers = context.containers.lock().unwrap();
        containers.get_mut(container_id).cloned().ok_or_else(|| {
            ForgeError::InvalidStateTransition {
                message: format!("Container {} not found", container_id),
            }
        })?
    };

    // Update the container state
    container.state = ContainerState::Running;

    // Update the container in the runtime context
    {
        let mut containers = context.containers.lock().unwrap();
        containers.insert(*container_id, container.clone());
    }

    tracing::info!(container_id = %container_id, container_name = %container.name, "Container started");

    Ok(())
}

/// Stop a container
pub fn stop_container(container_id: &Uuid) -> Result<()> {
    let context = get_runtime_context()?;

    // Get the container
    let mut container = {
        let mut containers = context.containers.lock().unwrap();
        containers.get_mut(container_id).cloned().ok_or_else(|| {
            ForgeError::InvalidStateTransition {
                message: format!("Container {} not found", container_id),
            }
        })?
    };

    // Update the container state
    container.state = ContainerState::Stopping;

    // Update the container in the runtime context
    {
        let mut containers = context.containers.lock().unwrap();
        containers.insert(*container_id, container.clone());
    }

    // Perform the actual stop operation
    // This would typically involve stopping the workload execution

    // Update the container state to Stopped
    container.state = ContainerState::Stopped;

    // Update the container in the runtime context
    {
        let mut containers = context.containers.lock().unwrap();
        containers.insert(*container_id, container.clone());
    }

    // Update metrics
    {
        let mut metrics = context.metrics.lock().unwrap();
        metrics.active_containers -= 1;
        metrics.completed_containers += 1;
    }

    tracing::info!(container_id = %container_id, container_name = %container.name, "Container stopped");

    Ok(())
}

/// Get a container by ID
pub fn get_container(container_id: &Uuid) -> Result<ContainerContext> {
    let context = get_runtime_context()?;

    let containers = context.containers.lock().unwrap();
    containers
        .get(container_id)
        .cloned()
        .ok_or_else(|| ForgeError::InvalidStateTransition {
            message: format!("Container {} not found", container_id),
        })
}

/// List all containers
pub fn list_containers() -> Result<Vec<ContainerContext>> {
    let context = get_runtime_context()?;

    let containers = context.containers.lock().unwrap();
    Ok(containers.values().cloned().collect())
}

/// Get runtime metrics
pub fn get_metrics() -> Result<RuntimeMetrics> {
    let context = get_runtime_context()?;

    let metrics = context.metrics.lock().unwrap();
    Ok(metrics.clone())
}
