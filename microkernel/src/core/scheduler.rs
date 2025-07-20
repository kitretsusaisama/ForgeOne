//! Scheduler subsystem for the ForgeOne Microkernel
//!
//! Provides intelligent workload scheduling with priority-based execution,
//! resource allocation, and adaptive scheduling based on workload characteristics.

use crate::core::boot::BootContext;
use crate::core::runtime::{get_container, get_runtime_context, ContainerContext};
use common::config::runtime::RuntimeConfig;
use common::error::{ForgeError, Result};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Scheduler context for the microkernel
#[derive(Debug)]
pub struct SchedulerContext {
    /// Unique identifier for this scheduler session
    pub id: Uuid,
    /// Boot context reference
    pub boot_context: Arc<BootContext>,
    /// Scheduler queues
    pub queues: Mutex<HashMap<Priority, VecDeque<Uuid>>>,
    /// Scheduler state
    pub state: Mutex<SchedulerState>,
    /// Scheduler metrics
    pub metrics: Mutex<SchedulerMetrics>,
}

/// Priority levels for scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Priority {
    /// Critical priority
    Critical,
    /// High priority
    High,
    /// Normal priority
    Normal,
    /// Low priority
    Low,
    /// Background priority
    Background,
}

/// Scheduler state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerState {
    /// Scheduler is initializing
    Initializing,
    /// Scheduler is running
    Running,
    /// Scheduler is paused
    Paused,
    /// Scheduler is shutting down
    ShuttingDown,
    /// Scheduler is in error state
    Error(String),
}

/// Scheduler metrics
#[derive(Debug, Clone)]
pub struct SchedulerMetrics {
    /// Number of scheduled containers
    pub scheduled_containers: usize,
    /// Number of running containers
    pub running_containers: usize,
    /// Number of waiting containers
    pub waiting_containers: usize,
    /// Average wait time in milliseconds
    pub avg_wait_time_ms: u64,
    /// Average execution time in milliseconds
    pub avg_execution_time_ms: u64,
    /// Scheduler throughput in containers per second
    pub throughput_containers_per_sec: f64,
}

// Global scheduler context
static mut SCHEDULER_CONTEXT: Option<Arc<SchedulerContext>> = None;

/// Initialize the scheduler subsystem
pub fn init(boot_context: &BootContext) -> Result<()> {
    let mut queues = HashMap::new();
    queues.insert(Priority::Critical, VecDeque::new());
    queues.insert(Priority::High, VecDeque::new());
    queues.insert(Priority::Normal, VecDeque::new());
    queues.insert(Priority::Low, VecDeque::new());
    queues.insert(Priority::Background, VecDeque::new());

    let scheduler_context = SchedulerContext {
        id: Uuid::new_v4(),
        boot_context: Arc::new(boot_context.clone()),
        queues: Mutex::new(queues),
        state: Mutex::new(SchedulerState::Initializing),
        metrics: Mutex::new(SchedulerMetrics {
            scheduled_containers: 0,
            running_containers: 0,
            waiting_containers: 0,
            avg_wait_time_ms: 0,
            avg_execution_time_ms: 0,
            throughput_containers_per_sec: 0.0,
        }),
    };

    tracing::info!(scheduler_id = %scheduler_context.id, "Scheduler initialized");
    unsafe {
        SCHEDULER_CONTEXT = Some(Arc::new(scheduler_context));
    }

    // Set the scheduler state to Running
    if let Some(context) = unsafe { SCHEDULER_CONTEXT.as_ref() } {
        let mut state = context.state.lock().unwrap();
        *state = SchedulerState::Running;
    }

    Ok(())
}

/// Initialize the scheduler subsystem with custom configuration
pub fn init_with_config(boot_context: &BootContext, config: &RuntimeConfig) -> Result<()> {
    let mut queues = HashMap::new();
    queues.insert(Priority::Critical, VecDeque::new());
    queues.insert(Priority::High, VecDeque::new());
    queues.insert(Priority::Normal, VecDeque::new());
    queues.insert(Priority::Low, VecDeque::new());
    queues.insert(Priority::Background, VecDeque::new());

    let scheduler_context = SchedulerContext {
        id: Uuid::new_v4(),
        boot_context: Arc::new(boot_context.clone()),
        queues: Mutex::new(queues),
        state: Mutex::new(SchedulerState::Initializing),
        metrics: Mutex::new(SchedulerMetrics {
            scheduled_containers: 0,
            running_containers: 0,
            waiting_containers: 0,
            avg_wait_time_ms: 0,
            avg_execution_time_ms: 0,
            throughput_containers_per_sec: 0.0,
        }),
    };

    tracing::info!(scheduler_id = %scheduler_context.id, "Scheduler initialized with custom config");
    unsafe {
        SCHEDULER_CONTEXT = Some(Arc::new(scheduler_context));
    }

    // Set the scheduler state to Running
    if let Some(context) = unsafe { SCHEDULER_CONTEXT.as_ref() } {
        let mut state = context.state.lock().unwrap();
        *state = SchedulerState::Running;
    }

    Ok(())
}

/// Shutdown the scheduler subsystem
pub fn shutdown() -> Result<()> {
    if let Some(context) = unsafe { SCHEDULER_CONTEXT.as_ref() } {
        // Set the scheduler state to ShuttingDown
        {
            let mut state = context.state.lock().unwrap();
            *state = SchedulerState::ShuttingDown;
        }

        // Clear all queues
        {
            let mut queues = context.queues.lock().unwrap();
            for queue in queues.values_mut() {
                queue.clear();
            }
        }

        // Clear the global scheduler context
        unsafe {
            SCHEDULER_CONTEXT = None;
        }

        tracing::info!(scheduler_id = %context.id, "Scheduler shutdown complete");
    }

    Ok(())
}

/// Get the scheduler context
pub fn get_scheduler_context() -> Result<Arc<SchedulerContext>> {
    unsafe {
        SCHEDULER_CONTEXT
            .as_ref()
            .cloned()
            .ok_or_else(|| ForgeError::ConfigError("Scheduler context not initialized".to_string()))
    }
}

/// Schedule a container for execution
pub fn schedule(container_id: &Uuid, priority: Priority) -> Result<()> {
    let context = get_scheduler_context()?;

    // Verify the container exists
    let _container = get_container(container_id)?;

    // Add the container to the appropriate queue
    {
        let mut queues = context.queues.lock().unwrap();
        if let Some(queue) = queues.get_mut(&priority) {
            queue.push_back(*container_id);
        }
    }

    // Update metrics
    {
        let mut metrics = context.metrics.lock().unwrap();
        metrics.scheduled_containers += 1;
        metrics.waiting_containers += 1;
    }

    tracing::info!(container_id = %container_id, priority = ?priority, "Container scheduled");

    Ok(())
}

/// Unschedule a container
pub fn unschedule(container_id: &Uuid) -> Result<()> {
    let context = get_scheduler_context()?;

    // Remove the container from all queues
    {
        let mut queues = context.queues.lock().unwrap();
        for queue in queues.values_mut() {
            queue.retain(|id| id != container_id);
        }
    }

    // Update metrics
    {
        let mut metrics = context.metrics.lock().unwrap();
        metrics.waiting_containers = metrics.waiting_containers.saturating_sub(1);
    }

    tracing::info!(container_id = %container_id, "Container unscheduled");

    Ok(())
}

/// Get the next container to execute
pub fn get_next_container() -> Result<Option<ContainerContext>> {
    let context = get_scheduler_context()?;
    let runtime_context = get_runtime_context()?;

    // Check each queue in priority order
    let priorities = [
        Priority::Critical,
        Priority::High,
        Priority::Normal,
        Priority::Low,
        Priority::Background,
    ];

    for priority in &priorities {
        let container_id = {
            let mut queues = context.queues.lock().unwrap();
            if let Some(queue) = queues.get_mut(priority) {
                queue.pop_front()
            } else {
                None
            }
        };

        if let Some(id) = container_id {
            // Update metrics
            {
                let mut metrics = context.metrics.lock().unwrap();
                metrics.waiting_containers = metrics.waiting_containers.saturating_sub(1);
                metrics.running_containers += 1;
            }

            // Get the container
            let container = get_container(&id)?;

            tracing::info!(container_id = %id, priority = ?priority, "Container selected for execution");

            return Ok(Some(container));
        }
    }

    Ok(None)
}

/// Get scheduler metrics
pub fn get_metrics() -> Result<SchedulerMetrics> {
    let context = get_scheduler_context()?;

    let metrics = context.metrics.lock().unwrap();
    Ok(metrics.clone())
}

/// Get the number of waiting containers by priority
pub fn get_waiting_count_by_priority() -> Result<HashMap<Priority, usize>> {
    let context = get_scheduler_context()?;

    let queues = context.queues.lock().unwrap();
    let mut counts = HashMap::new();

    for (priority, queue) in queues.iter() {
        counts.insert(*priority, queue.len());
    }

    Ok(counts)
}
