//! # Container Scheduler Module
//!
//! This module provides functionality for scheduling container execution,
//! managing resource allocation, and optimizing container placement.

use crate::metrics::ResourceUsage;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Scheduling policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedulingPolicy {
    /// Round-robin scheduling
    RoundRobin,
    /// Binpack scheduling (minimize number of nodes)
    Binpack,
    /// Spread scheduling (maximize distribution)
    Spread,
    /// Random scheduling
    Random,
    /// Custom scheduling
    Custom,
}

impl std::fmt::Display for SchedulingPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchedulingPolicy::RoundRobin => write!(f, "round-robin"),
            SchedulingPolicy::Binpack => write!(f, "binpack"),
            SchedulingPolicy::Spread => write!(f, "spread"),
            SchedulingPolicy::Random => write!(f, "random"),
            SchedulingPolicy::Custom => write!(f, "custom"),
        }
    }
}

/// Resource constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConstraints {
    /// CPU cores
    pub cpu_cores: Option<f64>,
    /// Memory in bytes
    pub memory_bytes: Option<u64>,
    /// Disk space in bytes
    pub disk_bytes: Option<u64>,
    /// Network bandwidth in bytes per second
    pub network_bps: Option<u64>,
    /// GPU devices
    pub gpu_devices: Option<Vec<String>>,
    /// Custom resource constraints
    pub custom: HashMap<String, String>,
}

impl Default for ResourceConstraints {
    fn default() -> Self {
        Self {
            cpu_cores: None,
            memory_bytes: None,
            disk_bytes: None,
            network_bps: None,
            gpu_devices: None,
            custom: HashMap::new(),
        }
    }
}

/// Placement constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementConstraints {
    /// Node constraints (key-value pairs that must match node labels)
    pub node_constraints: HashMap<String, String>,
    /// Affinity constraints (containers that should be placed together)
    pub affinity: Vec<String>,
    /// Anti-affinity constraints (containers that should not be placed together)
    pub anti_affinity: Vec<String>,
    /// Custom placement constraints
    pub custom: HashMap<String, String>,
}

impl Default for PlacementConstraints {
    fn default() -> Self {
        Self {
            node_constraints: HashMap::new(),
            affinity: Vec::new(),
            anti_affinity: Vec::new(),
            custom: HashMap::new(),
        }
    }
}

/// Scheduling constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingConstraints {
    /// Resource constraints
    pub resources: ResourceConstraints,
    /// Placement constraints
    pub placement: PlacementConstraints,
    /// Priority (higher value means higher priority)
    pub priority: u32,
    /// Preemptible (can be preempted by higher priority containers)
    pub preemptible: bool,
    /// Restart policy (always, on-failure, never)
    pub restart_policy: String,
    /// Maximum restart count
    pub max_restart_count: Option<u32>,
    /// Custom scheduling constraints
    pub custom: HashMap<String, String>,
}

impl Default for SchedulingConstraints {
    fn default() -> Self {
        Self {
            resources: ResourceConstraints::default(),
            placement: PlacementConstraints::default(),
            priority: 0,
            preemptible: false,
            restart_policy: "always".to_string(),
            max_restart_count: None,
            custom: HashMap::new(),
        }
    }
}

/// Node resource capacity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    /// Node ID
    pub id: String,
    /// CPU cores
    pub cpu_cores: f64,
    /// Memory in bytes
    pub memory_bytes: u64,
    /// Disk space in bytes
    pub disk_bytes: u64,
    /// Network bandwidth in bytes per second
    pub network_bps: u64,
    /// GPU devices
    pub gpu_devices: Vec<String>,
    /// Node labels
    pub labels: HashMap<String, String>,
    /// Custom capacity
    pub custom: HashMap<String, String>,
}

/// Node resource allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAllocation {
    /// Node ID
    pub id: String,
    /// Allocated CPU cores
    pub allocated_cpu_cores: f64,
    /// Allocated memory in bytes
    pub allocated_memory_bytes: u64,
    /// Allocated disk space in bytes
    pub allocated_disk_bytes: u64,
    /// Allocated network bandwidth in bytes per second
    pub allocated_network_bps: u64,
    /// Allocated GPU devices
    pub allocated_gpu_devices: HashSet<String>,
    /// Container IDs running on this node
    pub container_ids: HashSet<String>,
    /// Custom allocations
    pub custom: HashMap<String, String>,
}

impl NodeAllocation {
    /// Create a new node allocation
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            allocated_cpu_cores: 0.0,
            allocated_memory_bytes: 0,
            allocated_disk_bytes: 0,
            allocated_network_bps: 0,
            allocated_gpu_devices: HashSet::new(),
            container_ids: HashSet::new(),
            custom: HashMap::new(),
        }
    }

    /// Check if the node has enough resources for the given constraints
    pub fn has_capacity(&self, capacity: &NodeCapacity, constraints: &ResourceConstraints) -> bool {
        // Check CPU
        if let Some(cpu_cores) = constraints.cpu_cores {
            if self.allocated_cpu_cores + cpu_cores > capacity.cpu_cores {
                return false;
            }
        }

        // Check memory
        if let Some(memory_bytes) = constraints.memory_bytes {
            if self.allocated_memory_bytes + memory_bytes > capacity.memory_bytes {
                return false;
            }
        }

        // Check disk
        if let Some(disk_bytes) = constraints.disk_bytes {
            if self.allocated_disk_bytes + disk_bytes > capacity.disk_bytes {
                return false;
            }
        }

        // Check network
        if let Some(network_bps) = constraints.network_bps {
            if self.allocated_network_bps + network_bps > capacity.network_bps {
                return false;
            }
        }

        // Check GPU
        if let Some(gpu_devices) = &constraints.gpu_devices {
            for device in gpu_devices {
                if self.allocated_gpu_devices.contains(device) {
                    return false;
                }
                if !capacity.gpu_devices.contains(device) {
                    return false;
                }
            }
        }

        true
    }

    /// Allocate resources for a container
    pub fn allocate(
        &mut self,
        container_id: &str,
        constraints: &ResourceConstraints,
    ) -> Result<()> {
        // Allocate CPU
        if let Some(cpu_cores) = constraints.cpu_cores {
            self.allocated_cpu_cores += cpu_cores;
        }

        // Allocate memory
        if let Some(memory_bytes) = constraints.memory_bytes {
            self.allocated_memory_bytes += memory_bytes;
        }

        // Allocate disk
        if let Some(disk_bytes) = constraints.disk_bytes {
            self.allocated_disk_bytes += disk_bytes;
        }

        // Allocate network
        if let Some(network_bps) = constraints.network_bps {
            self.allocated_network_bps += network_bps;
        }

        // Allocate GPU
        if let Some(gpu_devices) = &constraints.gpu_devices {
            for device in gpu_devices {
                self.allocated_gpu_devices.insert(device.clone());
            }
        }

        // Add container ID
        self.container_ids.insert(container_id.to_string());

        Ok(())
    }

    /// Deallocate resources for a container
    pub fn deallocate(
        &mut self,
        container_id: &str,
        constraints: &ResourceConstraints,
    ) -> Result<()> {
        // Check if container is allocated on this node
        if !self.container_ids.contains(container_id) {
            return Err(ForgeError::NotFound(format!("container: {}", container_id)));
        }

        // Deallocate CPU
        if let Some(cpu_cores) = constraints.cpu_cores {
            self.allocated_cpu_cores -= cpu_cores;
            if self.allocated_cpu_cores < 0.0 {
                self.allocated_cpu_cores = 0.0;
            }
        }

        // Deallocate memory
        if let Some(memory_bytes) = constraints.memory_bytes {
            if memory_bytes <= self.allocated_memory_bytes {
                self.allocated_memory_bytes -= memory_bytes;
            } else {
                self.allocated_memory_bytes = 0;
            }
        }

        // Deallocate disk
        if let Some(disk_bytes) = constraints.disk_bytes {
            if disk_bytes <= self.allocated_disk_bytes {
                self.allocated_disk_bytes -= disk_bytes;
            } else {
                self.allocated_disk_bytes = 0;
            }
        }

        // Deallocate network
        if let Some(network_bps) = constraints.network_bps {
            if network_bps <= self.allocated_network_bps {
                self.allocated_network_bps -= network_bps;
            } else {
                self.allocated_network_bps = 0;
            }
        }

        // Deallocate GPU
        if let Some(gpu_devices) = &constraints.gpu_devices {
            for device in gpu_devices {
                self.allocated_gpu_devices.remove(device);
            }
        }

        // Remove container ID
        self.container_ids.remove(container_id);

        Ok(())
    }
}

/// Container allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAllocation {
    /// Container ID
    pub container_id: String,
    /// Node ID
    pub node_id: String,
    /// Resource constraints
    pub constraints: ResourceConstraints,
    /// Allocation time
    pub allocated_at: u64,
    /// Allocation status
    pub status: AllocationStatus,
}

/// Allocation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AllocationStatus {
    /// Pending allocation
    Pending,
    /// Allocated
    Allocated,
    /// Failed allocation
    Failed,
    /// Deallocated
    Deallocated,
}

impl std::fmt::Display for AllocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AllocationStatus::Pending => write!(f, "pending"),
            AllocationStatus::Allocated => write!(f, "allocated"),
            AllocationStatus::Failed => write!(f, "failed"),
            AllocationStatus::Deallocated => write!(f, "deallocated"),
        }
    }
}

/// Scheduler
#[derive(Debug)]
pub struct Scheduler {
    /// Scheduling policy
    policy: SchedulingPolicy,
    /// Node capacities
    node_capacities: Arc<RwLock<HashMap<String, NodeCapacity>>>,
    /// Node allocations
    node_allocations: Arc<RwLock<HashMap<String, NodeAllocation>>>,
    /// Container allocations
    container_allocations: Arc<RwLock<HashMap<String, ContainerAllocation>>>,
    /// Last node index for round-robin scheduling
    last_node_index: Arc<RwLock<usize>>,
}

impl Scheduler {
    /// Create a new scheduler
    pub fn new(policy: SchedulingPolicy) -> Self {
        Self {
            policy,
            node_capacities: Arc::new(RwLock::new(HashMap::new())),
            node_allocations: Arc::new(RwLock::new(HashMap::new())),
            container_allocations: Arc::new(RwLock::new(HashMap::new())),
            last_node_index: Arc::new(RwLock::new(0)),
        }
    }

    /// Register a node
    pub fn register_node(&self, capacity: NodeCapacity) -> Result<()> {
        let span = ExecutionSpan::new("register_node", common::identity::IdentityContext::system());

        // Add node capacity
        let mut node_capacities = self
            .node_capacities
            .write()
            .map_err(|_| ForgeError::InternalError("node_capacities lock poisoned".to_string()))?;

        // Check if node already exists
        if node_capacities.contains_key(&capacity.id) {
            return Err(ForgeError::AlreadyExists(format!("node: {}", capacity.id)));
        }

        let node_id = capacity.id.clone();
        node_capacities.insert(node_id.clone(), capacity);

        // Add node allocation
        let mut node_allocations = self
            .node_allocations
            .write()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        node_allocations.insert(node_id.clone(), NodeAllocation::new(&node_id));

        Ok(())
    }

    /// Unregister a node
    pub fn unregister_node(&self, node_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unregister_node",
            common::identity::IdentityContext::system(),
        );

        // Get node allocation
        let node_allocations = self
            .node_allocations
            .read()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        let node_allocation = node_allocations
            .get(node_id)
            .ok_or(ForgeError::NotFound(format!("node: {}", node_id)))?;

        // Check if node has containers
        if !node_allocation.container_ids.is_empty() {
            return Err(ForgeError::InternalError(format!(
                "unregister_node: Node {} has {} containers",
                node_id,
                node_allocation.container_ids.len()
            )));
        }

        // Remove node capacity
        let mut node_capacities = self
            .node_capacities
            .write()
            .map_err(|_| ForgeError::InternalError("node_capacities lock poisoned".to_string()))?;

        node_capacities.remove(node_id);

        // Remove node allocation
        let mut node_allocations = self
            .node_allocations
            .write()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        node_allocations.remove(node_id);

        Ok(())
    }

    /// Update node capacity
    pub fn update_node_capacity(&self, capacity: NodeCapacity) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_node_capacity",
            common::identity::IdentityContext::system(),
        );

        // Get node allocation
        let node_allocations = self
            .node_allocations
            .read()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        let node_allocation = node_allocations
            .get(&capacity.id)
            .ok_or(ForgeError::NotFound(format!("node: {}", capacity.id)))?;

        // Check if new capacity is sufficient for current allocations
        if node_allocation.allocated_cpu_cores > capacity.cpu_cores
            || node_allocation.allocated_memory_bytes > capacity.memory_bytes
            || node_allocation.allocated_disk_bytes > capacity.disk_bytes
            || node_allocation.allocated_network_bps > capacity.network_bps
        {
            return Err(ForgeError::InternalError(format!("update_node_capacity: New capacity for node {} is insufficient for current allocations", capacity.id)));
        }

        // Update node capacity
        let mut node_capacities = self
            .node_capacities
            .write()
            .map_err(|_| ForgeError::InternalError("node_capacities lock poisoned".to_string()))?;

        node_capacities.insert(capacity.id.clone(), capacity);

        Ok(())
    }

    /// Get node capacity
    pub fn get_node_capacity(&self, node_id: &str) -> Result<NodeCapacity> {
        let span = ExecutionSpan::new(
            "get_node_capacity",
            common::identity::IdentityContext::system(),
        );

        // Get node capacity
        let node_capacities = self
            .node_capacities
            .read()
            .map_err(|_| ForgeError::InternalError("node_capacities lock poisoned".to_string()))?;

        let capacity = node_capacities
            .get(node_id)
            .ok_or(ForgeError::NotFound(format!("node: {}", node_id)))?;

        Ok(capacity.clone())
    }

    /// Get node allocation
    pub fn get_node_allocation(&self, node_id: &str) -> Result<NodeAllocation> {
        let span = ExecutionSpan::new(
            "get_node_allocation",
            common::identity::IdentityContext::system(),
        );

        // Get node allocation
        let node_allocations = self
            .node_allocations
            .read()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        let allocation = node_allocations
            .get(node_id)
            .ok_or(ForgeError::NotFound(format!("node: {}", node_id)))?;

        Ok(allocation.clone())
    }

    /// List nodes
    pub fn list_nodes(&self) -> Result<Vec<NodeCapacity>> {
        let span = ExecutionSpan::new("list_nodes", common::identity::IdentityContext::system());

        // Get node capacities
        let node_capacities = self
            .node_capacities
            .read()
            .map_err(|_| ForgeError::InternalError("node_capacities lock poisoned".to_string()))?;

        Ok(node_capacities.values().cloned().collect())
    }

    /// Schedule a container
    pub fn schedule_container(
        &self,
        container_id: &str,
        constraints: SchedulingConstraints,
    ) -> Result<String> {
        let span = ExecutionSpan::new(
            "schedule_container",
            common::identity::IdentityContext::system(),
        );

        // Check if container is already scheduled
        let container_allocations = self.container_allocations.read().map_err(|_| {
            ForgeError::InternalError("container_allocations lock poisoned".to_string())
        })?;

        if container_allocations.contains_key(container_id) {
            return Err(ForgeError::AlreadyExists(format!(
                "container_allocation: {}",
                container_id
            )));
        }

        // Get node capacities and allocations
        let node_capacities = self
            .node_capacities
            .read()
            .map_err(|_| ForgeError::InternalError("node_capacities lock poisoned".to_string()))?;

        let node_allocations = self
            .node_allocations
            .read()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        // Find a suitable node based on scheduling policy
        let node_id = match self.policy {
            SchedulingPolicy::RoundRobin => self.schedule_round_robin(
                &node_capacities,
                &node_allocations,
                &constraints.resources,
                &constraints.placement,
            )?,
            SchedulingPolicy::Binpack => self.schedule_binpack(
                &node_capacities,
                &node_allocations,
                &constraints.resources,
                &constraints.placement,
            )?,
            SchedulingPolicy::Spread => self.schedule_spread(
                &node_capacities,
                &node_allocations,
                &constraints.resources,
                &constraints.placement,
            )?,
            SchedulingPolicy::Random => self.schedule_random(
                &node_capacities,
                &node_allocations,
                &constraints.resources,
                &constraints.placement,
            )?,
            SchedulingPolicy::Custom => self.schedule_custom(
                &node_capacities,
                &node_allocations,
                &constraints.resources,
                &constraints.placement,
            )?,
        };

        // Allocate resources on the selected node
        let mut node_allocations = self
            .node_allocations
            .write()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        let node_allocation = node_allocations
            .get_mut(&node_id)
            .ok_or(ForgeError::NotFound(format!("node: {}", node_id)))?;

        node_allocation.allocate(container_id, &constraints.resources)?;

        // Create container allocation
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let container_allocation = ContainerAllocation {
            container_id: container_id.to_string(),
            node_id: node_id.clone(),
            constraints: constraints.resources.clone(),
            allocated_at: now,
            status: AllocationStatus::Allocated,
        };

        // Add container allocation
        let mut container_allocations = self.container_allocations.write().map_err(|_| {
            ForgeError::InternalError("container_allocations lock poisoned".to_string())
        })?;

        container_allocations.insert(container_id.to_string(), container_allocation);

        Ok(node_id)
    }

    /// Unschedule a container
    pub fn unschedule_container(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unschedule_container",
            common::identity::IdentityContext::system(),
        );

        // Get container allocation
        let mut container_allocations = self.container_allocations.write().map_err(|_| {
            ForgeError::InternalError("container_allocations lock poisoned".to_string())
        })?;

        let container_allocation =
            container_allocations
                .get(container_id)
                .ok_or(ForgeError::NotFound(format!(
                    "container_allocation: {}",
                    container_id
                )))?;

        let node_id = container_allocation.node_id.clone();
        let constraints = container_allocation.constraints.clone();

        // Deallocate resources on the node
        let mut node_allocations = self
            .node_allocations
            .write()
            .map_err(|_| ForgeError::InternalError("node_allocations lock poisoned".to_string()))?;

        let node_allocation = node_allocations
            .get_mut(&node_id)
            .ok_or(ForgeError::NotFound(format!("node: {}", node_id)))?;

        node_allocation.deallocate(container_id, &constraints)?;

        // Update container allocation status
        let mut allocation = container_allocations.get_mut(container_id).unwrap();
        allocation.status = AllocationStatus::Deallocated;

        // Remove container allocation
        container_allocations.remove(container_id);

        Ok(())
    }

    /// Get container allocation
    pub fn get_container_allocation(&self, container_id: &str) -> Result<ContainerAllocation> {
        let span = ExecutionSpan::new(
            "get_container_allocation",
            common::identity::IdentityContext::system(),
        );

        // Get container allocation
        let container_allocations = self.container_allocations.read().map_err(|_| {
            ForgeError::InternalError("container_allocations lock poisoned".to_string())
        })?;

        let allocation = container_allocations
            .get(container_id)
            .ok_or(ForgeError::NotFound(format!(
                "container_allocation: {}",
                container_id
            )))?;

        Ok(allocation.clone())
    }

    /// List container allocations
    pub fn list_container_allocations(&self) -> Result<Vec<ContainerAllocation>> {
        let span = ExecutionSpan::new(
            "list_container_allocations",
            common::identity::IdentityContext::system(),
        );

        // Get container allocations
        let container_allocations = self.container_allocations.read().map_err(|_| {
            ForgeError::InternalError("container_allocations lock poisoned".to_string())
        })?;

        Ok(container_allocations.values().cloned().collect())
    }

    /// Schedule using round-robin policy
    fn schedule_round_robin(
        &self,
        node_capacities: &HashMap<String, NodeCapacity>,
        node_allocations: &HashMap<String, NodeAllocation>,
        resource_constraints: &ResourceConstraints,
        placement_constraints: &PlacementConstraints,
    ) -> Result<String> {
        // Get nodes that match placement constraints
        let mut matching_nodes = self.filter_nodes_by_constraints(
            node_capacities,
            node_allocations,
            resource_constraints,
            placement_constraints,
        )?;

        if matching_nodes.is_empty() {
            return Err(ForgeError::InternalError(
                "No nodes match the constraints".to_string(),
            ));
        }

        // Sort nodes by ID for consistent ordering
        matching_nodes.sort_by(|a, b| a.id.cmp(&b.id));

        // Get last node index
        let mut last_index = self
            .last_node_index
            .write()
            .map_err(|_| ForgeError::InternalError("last_node_index lock poisoned".to_string()))?;

        // Find next node in round-robin fashion
        let node_count = matching_nodes.len();
        let start_index = *last_index % node_count;

        for i in 0..node_count {
            let index = (start_index + i) % node_count;
            let node = &matching_nodes[index];

            // Update last index
            *last_index = (index + 1) % node_count;

            return Ok(node.id.clone());
        }

        Err(ForgeError::InternalError(
            "No nodes available for scheduling".to_string(),
        ))
    }

    /// Schedule using binpack policy
    fn schedule_binpack(
        &self,
        node_capacities: &HashMap<String, NodeCapacity>,
        node_allocations: &HashMap<String, NodeAllocation>,
        resource_constraints: &ResourceConstraints,
        placement_constraints: &PlacementConstraints,
    ) -> Result<String> {
        // Get nodes that match placement constraints
        let matching_nodes = self.filter_nodes_by_constraints(
            node_capacities,
            node_allocations,
            resource_constraints,
            placement_constraints,
        )?;

        if matching_nodes.is_empty() {
            return Err(ForgeError::InternalError(
                "No nodes match the constraints".to_string(),
            ));
        }

        // Sort nodes by resource utilization (most utilized first)
        let mut sorted_nodes = matching_nodes.clone();
        sorted_nodes.sort_by(|a, b| {
            let a_alloc = node_allocations.get(&a.id).unwrap();
            let b_alloc = node_allocations.get(&b.id).unwrap();

            // Calculate utilization ratio (higher is more utilized)
            let a_cpu_util = a_alloc.allocated_cpu_cores / a.cpu_cores;
            let b_cpu_util = b_alloc.allocated_cpu_cores / b.cpu_cores;

            let a_mem_util = a_alloc.allocated_memory_bytes as f64 / a.memory_bytes as f64;
            let b_mem_util = b_alloc.allocated_memory_bytes as f64 / b.memory_bytes as f64;

            // Compare by average utilization
            let a_avg_util = (a_cpu_util + a_mem_util) / 2.0;
            let b_avg_util = (b_cpu_util + b_mem_util) / 2.0;

            // Sort in descending order (most utilized first)
            b_avg_util
                .partial_cmp(&a_avg_util)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Return the most utilized node that has capacity
        for node in sorted_nodes {
            return Ok(node.id.clone());
        }

        Err(ForgeError::InternalError(
            "No nodes available for scheduling".to_string(),
        ))
    }

    /// Schedule using spread policy
    fn schedule_spread(
        &self,
        node_capacities: &HashMap<String, NodeCapacity>,
        node_allocations: &HashMap<String, NodeAllocation>,
        resource_constraints: &ResourceConstraints,
        placement_constraints: &PlacementConstraints,
    ) -> Result<String> {
        // Get nodes that match placement constraints
        let matching_nodes = self.filter_nodes_by_constraints(
            node_capacities,
            node_allocations,
            resource_constraints,
            placement_constraints,
        )?;

        if matching_nodes.is_empty() {
            return Err(ForgeError::InternalError(
                "No nodes match the constraints".to_string(),
            ));
        }

        // Sort nodes by resource utilization (least utilized first)
        let mut sorted_nodes = matching_nodes.clone();
        sorted_nodes.sort_by(|a, b| {
            let a_alloc = node_allocations.get(&a.id).unwrap();
            let b_alloc = node_allocations.get(&b.id).unwrap();

            // Calculate utilization ratio (higher is more utilized)
            let a_cpu_util = a_alloc.allocated_cpu_cores / a.cpu_cores;
            let b_cpu_util = b_alloc.allocated_cpu_cores / b.cpu_cores;

            let a_mem_util = a_alloc.allocated_memory_bytes as f64 / a.memory_bytes as f64;
            let b_mem_util = b_alloc.allocated_memory_bytes as f64 / b.memory_bytes as f64;

            // Compare by average utilization
            let a_avg_util = (a_cpu_util + a_mem_util) / 2.0;
            let b_avg_util = (b_cpu_util + b_mem_util) / 2.0;

            // Sort in ascending order (least utilized first)
            a_avg_util
                .partial_cmp(&b_avg_util)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Return the least utilized node that has capacity
        for node in sorted_nodes {
            return Ok(node.id.clone());
        }

        Err(ForgeError::InternalError(
            "No nodes available for scheduling".to_string(),
        ))
    }

    /// Schedule using random policy
    fn schedule_random(
        &self,
        node_capacities: &HashMap<String, NodeCapacity>,
        node_allocations: &HashMap<String, NodeAllocation>,
        resource_constraints: &ResourceConstraints,
        placement_constraints: &PlacementConstraints,
    ) -> Result<String> {
        // Get nodes that match placement constraints
        let matching_nodes = self.filter_nodes_by_constraints(
            node_capacities,
            node_allocations,
            resource_constraints,
            placement_constraints,
        )?;

        if matching_nodes.is_empty() {
            return Err(ForgeError::InternalError(
                "No nodes match the constraints".to_string(),
            ));
        }

        // Select a random node
        let node_count = matching_nodes.len();
        let random_index = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize)
            % node_count;

        Ok(matching_nodes[random_index].id.clone())
    }

    /// Schedule using custom policy
    fn schedule_custom(
        &self,
        node_capacities: &HashMap<String, NodeCapacity>,
        node_allocations: &HashMap<String, NodeAllocation>,
        resource_constraints: &ResourceConstraints,
        placement_constraints: &PlacementConstraints,
    ) -> Result<String> {
        // For now, just use round-robin as a fallback
        self.schedule_round_robin(
            node_capacities,
            node_allocations,
            resource_constraints,
            placement_constraints,
        )
    }

    /// Filter nodes by constraints
    fn filter_nodes_by_constraints(
        &self,
        node_capacities: &HashMap<String, NodeCapacity>,
        node_allocations: &HashMap<String, NodeAllocation>,
        resource_constraints: &ResourceConstraints,
        placement_constraints: &PlacementConstraints,
    ) -> Result<Vec<NodeCapacity>> {
        let mut matching_nodes = Vec::new();

        for (node_id, capacity) in node_capacities {
            let allocation = node_allocations
                .get(node_id)
                .ok_or(ForgeError::NotFound(format!(
                    "node_allocation: {}",
                    node_id
                )))?;

            // Check resource constraints
            if !allocation.has_capacity(capacity, resource_constraints) {
                continue;
            }

            // Check node constraints
            let mut node_matches = true;
            for (key, value) in &placement_constraints.node_constraints {
                if capacity.labels.get(key) != Some(value) {
                    node_matches = false;
                    break;
                }
            }

            if !node_matches {
                continue;
            }

            // Check affinity constraints
            let mut affinity_matches = true;
            for container_id in &placement_constraints.affinity {
                if !allocation.container_ids.contains(container_id) {
                    affinity_matches = false;
                    break;
                }
            }

            if !affinity_matches {
                continue;
            }

            // Check anti-affinity constraints
            let mut anti_affinity_matches = true;
            for container_id in &placement_constraints.anti_affinity {
                if allocation.container_ids.contains(container_id) {
                    anti_affinity_matches = false;
                    break;
                }
            }

            if !anti_affinity_matches {
                continue;
            }

            // Node matches all constraints
            matching_nodes.push(capacity.clone());
        }

        Ok(matching_nodes)
    }
}

/// Global scheduler instance
static mut SCHEDULER: Option<Scheduler> = None;

/// Initialize the scheduler
pub fn init(policy: SchedulingPolicy) -> Result<()> {
    let span = ExecutionSpan::new(
        "init_scheduler",
        common::identity::IdentityContext::system(),
    );

    // Create scheduler
    let scheduler = Scheduler::new(policy);

    // Store the scheduler
    unsafe {
        if SCHEDULER.is_none() {
            SCHEDULER = Some(scheduler);
        } else {
            return Err(ForgeError::AlreadyExists(format!("scheduler: global")));
        }
    }

    Ok(())
}

/// Get the scheduler
pub fn get_scheduler() -> Result<&'static Scheduler> {
    unsafe {
        match &SCHEDULER {
            Some(scheduler) => Ok(scheduler),
            None => Err(ForgeError::InternalError(
                "scheduler not initialized".to_string(),
            )),
        }
    }
}

/// Register a node
pub fn register_node(capacity: NodeCapacity) -> Result<()> {
    let scheduler = get_scheduler()?;
    scheduler.register_node(capacity)
}

/// Unregister a node
pub fn unregister_node(node_id: &str) -> Result<()> {
    let scheduler = get_scheduler()?;
    scheduler.unregister_node(node_id)
}

/// Update node capacity
pub fn update_node_capacity(capacity: NodeCapacity) -> Result<()> {
    let scheduler = get_scheduler()?;
    scheduler.update_node_capacity(capacity)
}

/// Get node capacity
pub fn get_node_capacity(node_id: &str) -> Result<NodeCapacity> {
    let scheduler = get_scheduler()?;
    scheduler.get_node_capacity(node_id)
}

/// Get node allocation
pub fn get_node_allocation(node_id: &str) -> Result<NodeAllocation> {
    let scheduler = get_scheduler()?;
    scheduler.get_node_allocation(node_id)
}

/// List nodes
pub fn list_nodes() -> Result<Vec<NodeCapacity>> {
    let scheduler = get_scheduler()?;
    scheduler.list_nodes()
}

/// Schedule a container
pub fn schedule_container(
    container_id: &str,
    constraints: SchedulingConstraints,
) -> Result<String> {
    let scheduler = get_scheduler()?;
    scheduler.schedule_container(container_id, constraints)
}

/// Unschedule a container
pub fn unschedule_container(container_id: &str) -> Result<()> {
    let scheduler = get_scheduler()?;
    scheduler.unschedule_container(container_id)
}

/// Get container allocation
pub fn get_container_allocation(container_id: &str) -> Result<ContainerAllocation> {
    let scheduler = get_scheduler()?;
    scheduler.get_container_allocation(container_id)
}

/// List container allocations
pub fn list_container_allocations() -> Result<Vec<ContainerAllocation>> {
    let scheduler = get_scheduler()?;
    scheduler.list_container_allocations()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler() {
        // Initialize scheduler
        init(SchedulingPolicy::RoundRobin).unwrap();
        let scheduler = get_scheduler().unwrap();

        // Register nodes
        let node1 = NodeCapacity {
            id: "node1".to_string(),
            cpu_cores: 4.0,
            memory_bytes: 8 * 1024 * 1024 * 1024, // 8 GB
            disk_bytes: 100 * 1024 * 1024 * 1024, // 100 GB
            network_bps: 1000 * 1000 * 1000,      // 1 Gbps
            gpu_devices: vec!["gpu1".to_string()],
            labels: {
                let mut labels = HashMap::new();
                labels.insert("zone".to_string(), "us-east".to_string());
                labels
            },
            custom: HashMap::new(),
        };

        let node2 = NodeCapacity {
            id: "node2".to_string(),
            cpu_cores: 8.0,
            memory_bytes: 16 * 1024 * 1024 * 1024, // 16 GB
            disk_bytes: 200 * 1024 * 1024 * 1024,  // 200 GB
            network_bps: 10 * 1000 * 1000 * 1000,  // 10 Gbps
            gpu_devices: vec!["gpu2".to_string(), "gpu3".to_string()],
            labels: {
                let mut labels = HashMap::new();
                labels.insert("zone".to_string(), "us-west".to_string());
                labels
            },
            custom: HashMap::new(),
        };

        scheduler.register_node(node1.clone()).unwrap();
        scheduler.register_node(node2.clone()).unwrap();

        // Create scheduling constraints
        let constraints = SchedulingConstraints {
            resources: ResourceConstraints {
                cpu_cores: Some(2.0),
                memory_bytes: Some(4 * 1024 * 1024 * 1024), // 4 GB
                disk_bytes: Some(10 * 1024 * 1024 * 1024),  // 10 GB
                network_bps: Some(100 * 1000 * 1000),       // 100 Mbps
                gpu_devices: None,
                custom: HashMap::new(),
            },
            placement: PlacementConstraints {
                node_constraints: {
                    let mut constraints = HashMap::new();
                    constraints.insert("zone".to_string(), "us-east".to_string());
                    constraints
                },
                affinity: Vec::new(),
                anti_affinity: Vec::new(),
                custom: HashMap::new(),
            },
            priority: 0,
            preemptible: false,
            restart_policy: "always".to_string(),
            max_restart_count: None,
            custom: HashMap::new(),
        };

        // Schedule container
        let node_id = scheduler
            .schedule_container("container1", constraints.clone())
            .unwrap();

        assert_eq!(node_id, "node1");

        // Get container allocation
        let allocation = scheduler.get_container_allocation("container1").unwrap();
        assert_eq!(allocation.container_id, "container1");
        assert_eq!(allocation.node_id, "node1");
        assert_eq!(allocation.status, AllocationStatus::Allocated);

        // Get node allocation
        let node_allocation = scheduler.get_node_allocation("node1").unwrap();
        assert_eq!(node_allocation.allocated_cpu_cores, 2.0);
        assert_eq!(
            node_allocation.allocated_memory_bytes,
            4 * 1024 * 1024 * 1024
        );
        assert!(node_allocation.container_ids.contains("container1"));

        // Unschedule container
        scheduler.unschedule_container("container1").unwrap();

        // Check container is unscheduled
        let result = scheduler.get_container_allocation("container1");
        assert!(result.is_err());

        // Check node allocation is updated
        let node_allocation = scheduler.get_node_allocation("node1").unwrap();
        assert_eq!(node_allocation.allocated_cpu_cores, 0.0);
        assert_eq!(node_allocation.allocated_memory_bytes, 0);
        assert!(!node_allocation.container_ids.contains("container1"));
    }
}
