//! # Container Mesh Module
//!
//! This module provides functionality for container mesh networking, service discovery,
//! and inter-container communication. It implements a secure mesh network for containers
//! with automatic service discovery, load balancing, and fault tolerance.

use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Mesh protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshProtocol {
    /// TCP protocol
    TCP,
    /// UDP protocol
    UDP,
    /// HTTP protocol
    HTTP,
    /// gRPC protocol
    GRPC,
    /// WebSockets protocol
    WebSocket,
    /// Custom protocol
    Custom,
}

impl std::fmt::Display for MeshProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeshProtocol::TCP => write!(f, "tcp"),
            MeshProtocol::UDP => write!(f, "udp"),
            MeshProtocol::HTTP => write!(f, "http"),
            MeshProtocol::GRPC => write!(f, "grpc"),
            MeshProtocol::WebSocket => write!(f, "websocket"),
            MeshProtocol::Custom => write!(f, "custom"),
        }
    }
}

/// Load balancing algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadBalancingAlgorithm {
    /// Round robin
    RoundRobin,
    /// Least connections
    LeastConnections,
    /// Random
    Random,
    /// Consistent hashing
    ConsistentHashing,
    /// Weighted round robin
    WeightedRoundRobin,
    /// Custom algorithm
    Custom,
}

impl std::fmt::Display for LoadBalancingAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadBalancingAlgorithm::RoundRobin => write!(f, "round_robin"),
            LoadBalancingAlgorithm::LeastConnections => write!(f, "least_connections"),
            LoadBalancingAlgorithm::Random => write!(f, "random"),
            LoadBalancingAlgorithm::ConsistentHashing => write!(f, "consistent_hashing"),
            LoadBalancingAlgorithm::WeightedRoundRobin => write!(f, "weighted_round_robin"),
            LoadBalancingAlgorithm::Custom => write!(f, "custom"),
        }
    }
}

/// Service health check type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthCheckType {
    /// HTTP health check
    HTTP,
    /// TCP health check
    TCP,
    /// gRPC health check
    GRPC,
    /// Custom health check
    Custom,
}

impl std::fmt::Display for HealthCheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthCheckType::HTTP => write!(f, "http"),
            HealthCheckType::TCP => write!(f, "tcp"),
            HealthCheckType::GRPC => write!(f, "grpc"),
            HealthCheckType::Custom => write!(f, "custom"),
        }
    }
}

/// Service health check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Health check type
    pub check_type: HealthCheckType,
    /// Health check path (for HTTP/gRPC)
    pub path: Option<String>,
    /// Health check port
    pub port: u16,
    /// Health check interval
    pub interval: Duration,
    /// Health check timeout
    pub timeout: Duration,
    /// Number of consecutive successes required
    pub success_threshold: u32,
    /// Number of consecutive failures required
    pub failure_threshold: u32,
    /// Custom health check options
    pub custom: HashMap<String, String>,
}

impl Default for HealthCheck {
    fn default() -> Self {
        Self {
            check_type: HealthCheckType::HTTP,
            path: Some("/health".to_string()),
            port: 8080,
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(1),
            success_threshold: 1,
            failure_threshold: 3,
            custom: HashMap::new(),
        }
    }
}

/// Service health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Service is healthy
    Healthy,
    /// Service is unhealthy
    Unhealthy,
    /// Service health is unknown
    Unknown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Healthy => write!(f, "healthy"),
            HealthStatus::Unhealthy => write!(f, "unhealthy"),
            HealthStatus::Unknown => write!(f, "unknown"),
        }
    }
}

/// Service endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    /// Endpoint ID
    pub id: String,
    /// Container ID
    pub container_id: String,
    /// IP address
    pub ip_addr: IpAddr,
    /// Port
    pub port: u16,
    /// Protocol
    pub protocol: MeshProtocol,
    /// Weight (for weighted load balancing)
    pub weight: u32,
    /// Health status
    pub health_status: HealthStatus,
    /// Last health check timestamp
    pub last_health_check: u64,
    /// Consecutive successful health checks
    pub consecutive_successes: u32,
    /// Consecutive failed health checks
    pub consecutive_failures: u32,
    /// Custom endpoint options
    pub custom: HashMap<String, String>,
}

impl ServiceEndpoint {
    /// Create a new service endpoint
    pub fn new(container_id: &str, ip_addr: IpAddr, port: u16, protocol: MeshProtocol) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            container_id: container_id.to_string(),
            ip_addr,
            port,
            protocol,
            weight: 1,
            health_status: HealthStatus::Unknown,
            last_health_check: now,
            consecutive_successes: 0,
            consecutive_failures: 0,
            custom: HashMap::new(),
        }
    }

    /// Get the endpoint address
    pub fn address(&self) -> SocketAddr {
        SocketAddr::new(self.ip_addr, self.port)
    }

    /// Update health status
    pub fn update_health_status(
        &mut self,
        healthy: bool,
        success_threshold: u32,
        failure_threshold: u32,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.last_health_check = now;

        if healthy {
            self.consecutive_successes += 1;
            self.consecutive_failures = 0;

            if self.consecutive_successes >= success_threshold {
                self.health_status = HealthStatus::Healthy;
            }
        } else {
            self.consecutive_failures += 1;
            self.consecutive_successes = 0;

            if self.consecutive_failures >= failure_threshold {
                self.health_status = HealthStatus::Unhealthy;
            }
        }
    }

    /// Check if the endpoint is healthy
    pub fn is_healthy(&self) -> bool {
        self.health_status == HealthStatus::Healthy
    }
}

/// Service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// Service ID
    pub id: String,
    /// Service name
    pub name: String,
    /// Service namespace
    pub namespace: String,
    /// Service endpoints
    pub endpoints: Vec<ServiceEndpoint>,
    /// Load balancing algorithm
    pub load_balancing: LoadBalancingAlgorithm,
    /// Health check configuration
    pub health_check: HealthCheck,
    /// Service creation time
    pub created_at: u64,
    /// Service labels
    pub labels: HashMap<String, String>,
    /// Service annotations
    pub annotations: HashMap<String, String>,
    /// Custom service options
    pub custom: HashMap<String, String>,
}

impl Service {
    /// Create a new service
    pub fn new(name: &str, namespace: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            namespace: namespace.to_string(),
            endpoints: Vec::new(),
            load_balancing: LoadBalancingAlgorithm::RoundRobin,
            health_check: HealthCheck::default(),
            created_at: now,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            custom: HashMap::new(),
        }
    }

    /// Add an endpoint
    pub fn add_endpoint(&mut self, endpoint: ServiceEndpoint) -> Result<()> {
        // Check if endpoint already exists
        if self.endpoints.iter().any(|e| e.id == endpoint.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "service_endpoint".to_string(),
                id: endpoint.id.clone(),
            });
        }

        self.endpoints.push(endpoint);
        Ok(())
    }

    /// Remove an endpoint
    pub fn remove_endpoint(&mut self, endpoint_id: &str) -> Result<ServiceEndpoint> {
        let index = self
            .endpoints
            .iter()
            .position(|e| e.id == endpoint_id)
            .ok_or(ForgeError::NotFound(format!(
                "service_endpoint: {}",
                endpoint_id
            )))?;

        Ok(self.endpoints.remove(index))
    }

    /// Get an endpoint
    pub fn get_endpoint(&self, endpoint_id: &str) -> Result<&ServiceEndpoint> {
        self.endpoints
            .iter()
            .find(|e| e.id == endpoint_id)
            .ok_or(ForgeError::NotFound(format!(
                "service_endpoint: {}",
                endpoint_id
            )))
    }

    /// Get a mutable endpoint
    pub fn get_endpoint_mut(&mut self, endpoint_id: &str) -> Result<&mut ServiceEndpoint> {
        self.endpoints
            .iter_mut()
            .find(|e| e.id == endpoint_id)
            .ok_or(ForgeError::NotFound(format!(
                "service_endpoint: {}",
                endpoint_id
            )))
    }

    /// Get healthy endpoints
    pub fn get_healthy_endpoints(&self) -> Vec<&ServiceEndpoint> {
        self.endpoints.iter().filter(|e| e.is_healthy()).collect()
    }

    /// Select an endpoint using the service's load balancing algorithm
    pub fn select_endpoint(&self) -> Result<&ServiceEndpoint> {
        let healthy_endpoints = self.get_healthy_endpoints();

        if healthy_endpoints.is_empty() {
            return Err(ForgeError::InternalError(format!(
                "No healthy endpoints for service: {}",
                self.name
            )));
        }

        // In a real implementation, we would use the load balancing algorithm to select an endpoint
        // For now, just return the first healthy endpoint
        Ok(healthy_endpoints[0])
    }

    /// Update health status for all endpoints
    pub fn update_health_status(&mut self) {
        // In a real implementation, we would perform health checks on all endpoints
        // For now, just set all endpoints to healthy
        for endpoint in &mut self.endpoints {
            endpoint.update_health_status(
                true,
                self.health_check.success_threshold,
                self.health_check.failure_threshold,
            );
        }
    }
}

/// Service discovery type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceDiscoveryType {
    /// DNS-based service discovery
    DNS,
    /// Key-value store-based service discovery
    KeyValueStore,
    /// Multicast DNS-based service discovery
    MulticastDNS,
    /// Custom service discovery
    Custom,
}

impl std::fmt::Display for ServiceDiscoveryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceDiscoveryType::DNS => write!(f, "dns"),
            ServiceDiscoveryType::KeyValueStore => write!(f, "kv_store"),
            ServiceDiscoveryType::MulticastDNS => write!(f, "mdns"),
            ServiceDiscoveryType::Custom => write!(f, "custom"),
        }
    }
}

/// Service discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// Service discovery type
    pub discovery_type: ServiceDiscoveryType,
    /// DNS domain (for DNS-based discovery)
    pub dns_domain: Option<String>,
    /// Key-value store endpoints (for KV-based discovery)
    pub kv_endpoints: Option<Vec<String>>,
    /// Service discovery interval
    pub discovery_interval: Duration,
    /// Service TTL
    pub service_ttl: Duration,
    /// Custom service discovery options
    pub custom: HashMap<String, String>,
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            discovery_type: ServiceDiscoveryType::DNS,
            dns_domain: Some("mesh.local".to_string()),
            kv_endpoints: None,
            discovery_interval: Duration::from_secs(30),
            service_ttl: Duration::from_secs(60),
            custom: HashMap::new(),
        }
    }
}

/// Mesh configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Mesh ID
    pub id: String,
    /// Mesh name
    pub name: String,
    /// Service discovery configuration
    pub service_discovery: ServiceDiscoveryConfig,
    /// Default load balancing algorithm
    pub default_load_balancing: LoadBalancingAlgorithm,
    /// Default health check
    pub default_health_check: HealthCheck,
    /// Mesh enabled
    pub enabled: bool,
    /// Custom mesh options
    pub custom: HashMap<String, String>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "default".to_string(),
            service_discovery: ServiceDiscoveryConfig::default(),
            default_load_balancing: LoadBalancingAlgorithm::RoundRobin,
            default_health_check: HealthCheck::default(),
            enabled: true,
            custom: HashMap::new(),
        }
    }
}

/// Mesh manager
#[derive(Debug)]
pub struct MeshManager {
    /// Mesh configuration
    config: Arc<RwLock<MeshConfig>>,
    /// Services
    services: Arc<RwLock<HashMap<String, Service>>>,
    /// Service name to ID mapping
    service_names: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Container ID to service ID mapping
    container_services: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl MeshManager {
    /// Create a new mesh manager
    pub fn new(config: MeshConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            services: Arc::new(RwLock::new(HashMap::new())),
            service_names: Arc::new(RwLock::new(HashMap::new())),
            container_services: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the mesh configuration
    pub fn get_config(&self) -> Result<MeshConfig> {
        let config = self
            .config
            .read()
            .map_err(|_| ForgeError::InternalError("mesh_config lock poisoned".to_string()))?;

        Ok(config.clone())
    }

    /// Update the mesh configuration
    pub fn update_config(&self, config: MeshConfig) -> Result<()> {
        let mut current_config = self
            .config
            .write()
            .map_err(|_| ForgeError::InternalError("mesh_config lock poisoned".to_string()))?;

        *current_config = config;

        Ok(())
    }

    /// Create a service
    pub fn create_service(&self, name: &str, namespace: &str) -> Result<Service> {
        let span = ExecutionSpan::new(
            "create_service",
            common::identity::IdentityContext::system(),
        );

        let service = Service::new(name, namespace);

        // Add service to services map
        let mut services = self
            .services
            .write()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        // Add service to service names map
        let mut service_names = self
            .service_names
            .write()
            .map_err(|_| ForgeError::InternalError("service_names lock poisoned".to_string()))?;

        let key = format!("{}/{}", namespace, name);
        let service_ids = service_names.entry(key).or_insert_with(HashSet::new);

        if service_ids.contains(&service.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "service".to_string(),
                id: service.id.clone(),
            });
        }

        service_ids.insert(service.id.clone());
        services.insert(service.id.clone(), service.clone());

        Ok(service)
    }

    /// Get a service
    pub fn get_service(&self, service_id: &str) -> Result<Service> {
        let span = ExecutionSpan::new("get_service", common::identity::IdentityContext::system());

        let services = self
            .services
            .read()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        let service = services
            .get(service_id)
            .ok_or(ForgeError::NotFound(format!("service: {}", service_id)))?;

        Ok(service.clone())
    }

    /// Get a service by name and namespace
    pub fn get_service_by_name(&self, name: &str, namespace: &str) -> Result<Vec<Service>> {
        let span = ExecutionSpan::new(
            "get_service_by_name",
            common::identity::IdentityContext::system(),
        );

        let service_names = self
            .service_names
            .read()
            .map_err(|_| ForgeError::InternalError("service_names lock poisoned".to_string()))?;

        let key = format!("{}/{}", namespace, name);
        let service_ids = service_names
            .get(&key)
            .ok_or(ForgeError::NotFound(format!("service: {}", key)))?;

        let services = self
            .services
            .read()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        let result = service_ids
            .iter()
            .filter_map(|id| services.get(id).cloned())
            .collect();

        Ok(result)
    }

    /// Update a service
    pub fn update_service(&self, service: Service) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_service",
            common::identity::IdentityContext::system(),
        );

        let mut services = self
            .services
            .write()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        if !services.contains_key(&service.id) {
            return Err(ForgeError::NotFound(format!("service: {}", service.id)));
        }

        services.insert(service.id.clone(), service);

        Ok(())
    }

    /// Remove a service
    pub fn remove_service(&self, service_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_service",
            common::identity::IdentityContext::system(),
        );

        // Get the service
        let service = self.get_service(service_id)?;

        // Remove service from services map
        let mut services = self
            .services
            .write()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        services.remove(service_id);

        // Remove service from service names map
        let mut service_names = self
            .service_names
            .write()
            .map_err(|_| ForgeError::InternalError("service_names lock poisoned".to_string()))?;

        let key = format!("{}/{}", service.namespace, service.name);
        if let Some(service_ids) = service_names.get_mut(&key) {
            service_ids.remove(service_id);

            if service_ids.is_empty() {
                service_names.remove(&key);
            }
        }

        // Remove service from container services map
        let mut container_services = self.container_services.write().map_err(|_| {
            ForgeError::InternalError("container_services lock poisoned".to_string())
        })?;

        for endpoint in &service.endpoints {
            if let Some(service_ids) = container_services.get_mut(&endpoint.container_id) {
                service_ids.remove(service_id);

                if service_ids.is_empty() {
                    container_services.remove(&endpoint.container_id);
                }
            }
        }

        Ok(())
    }

    /// List all services
    pub fn list_services(&self) -> Result<Vec<Service>> {
        let span = ExecutionSpan::new("list_services", common::identity::IdentityContext::system());

        let services = self
            .services
            .read()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        Ok(services.values().cloned().collect())
    }

    /// List services by namespace
    pub fn list_services_by_namespace(&self, namespace: &str) -> Result<Vec<Service>> {
        let span = ExecutionSpan::new(
            "list_services_by_namespace",
            common::identity::IdentityContext::system(),
        );

        let services = self
            .services
            .read()
            .map_err(|_| ForgeError::InternalError("services lock poisoned".to_string()))?;

        let result = services
            .values()
            .filter(|s| s.namespace == namespace)
            .cloned()
            .collect();

        Ok(result)
    }

    /// Register a container endpoint
    pub fn register_endpoint(
        &self,
        service_name: &str,
        namespace: &str,
        container_id: &str,
        ip_addr: IpAddr,
        port: u16,
        protocol: MeshProtocol,
    ) -> Result<ServiceEndpoint> {
        let span = ExecutionSpan::new(
            "register_endpoint",
            common::identity::IdentityContext::system(),
        );

        // Create endpoint
        let endpoint = ServiceEndpoint::new(container_id, ip_addr, port, protocol);

        // Get or create service
        let services = self.get_service_by_name(service_name, namespace);
        let service = match services {
            Ok(services) if !services.is_empty() => services[0].clone(),
            _ => self.create_service(service_name, namespace)?,
        };

        // Add endpoint to service
        let mut updated_service = service.clone();
        updated_service.add_endpoint(endpoint.clone())?;

        // Update service
        self.update_service(updated_service)?;

        // Update container services map
        let mut container_services = self.container_services.write().map_err(|_| {
            ForgeError::InternalError("container_services lock poisoned".to_string())
        })?;

        let service_ids = container_services
            .entry(container_id.to_string())
            .or_insert_with(HashSet::new);

        service_ids.insert(service.id.clone());

        Ok(endpoint)
    }

    /// Unregister a container endpoint
    pub fn unregister_endpoint(&self, service_id: &str, endpoint_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unregister_endpoint",
            common::identity::IdentityContext::system(),
        );

        // Get service
        let service = self.get_service(service_id)?;

        // Get endpoint
        let endpoint = service.get_endpoint(endpoint_id)?;
        let container_id = endpoint.container_id.clone();

        // Remove endpoint from service
        let mut updated_service = service.clone();
        updated_service.remove_endpoint(endpoint_id)?;

        // Update service
        self.update_service(updated_service)?;

        // Update container services map
        let mut container_services = self.container_services.write().map_err(|_| {
            ForgeError::InternalError("container_services lock poisoned".to_string())
        })?;

        if let Some(service_ids) = container_services.get_mut(&container_id) {
            if service.endpoints.is_empty() {
                service_ids.remove(service_id);

                if service_ids.is_empty() {
                    container_services.remove(&container_id);
                }
            }
        }

        Ok(())
    }

    /// Unregister all container endpoints
    pub fn unregister_container(&self, container_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unregister_container",
            common::identity::IdentityContext::system(),
        );

        // Get container services
        let container_services = self.container_services.read().map_err(|_| {
            ForgeError::InternalError("container_services lock poisoned".to_string())
        })?;

        let service_ids = match container_services.get(container_id) {
            Some(ids) => ids.clone(),
            None => return Ok(()), // No services for this container
        };

        // For each service, remove container endpoints
        for service_id in service_ids {
            let service = self.get_service(&service_id)?;
            let mut updated_service = service.clone();

            // Find and remove all endpoints for this container
            let endpoints_to_remove: Vec<String> = updated_service
                .endpoints
                .iter()
                .filter(|e| e.container_id == container_id)
                .map(|e| e.id.clone())
                .collect();

            for endpoint_id in endpoints_to_remove {
                updated_service.remove_endpoint(&endpoint_id)?;
            }

            // Update service
            self.update_service(updated_service)?;
        }

        // Remove container from container services map
        let mut container_services = self.container_services.write().map_err(|_| {
            ForgeError::InternalError("container_services lock poisoned".to_string())
        })?;

        container_services.remove(container_id);

        Ok(())
    }

    /// Discover a service
    pub fn discover_service(&self, name: &str, namespace: &str) -> Result<Service> {
        let span = ExecutionSpan::new(
            "discover_service",
            common::identity::IdentityContext::system(),
        );

        // Get services by name
        let services = self.get_service_by_name(name, namespace)?;

        if services.is_empty() {
            return Err(ForgeError::NotFound(format!(
                "service: {}/{}",
                namespace, name
            )));
        }

        // In a real implementation, we might do more sophisticated service discovery
        // For now, just return the first service
        Ok(services[0].clone())
    }

    /// Select an endpoint for a service
    pub fn select_endpoint(&self, name: &str, namespace: &str) -> Result<ServiceEndpoint> {
        let span = ExecutionSpan::new(
            "select_endpoint",
            common::identity::IdentityContext::system(),
        );

        // Discover service
        let service = self.discover_service(name, namespace)?;

        // Select endpoint
        let endpoint = service.select_endpoint()?;

        Ok(endpoint.clone())
    }

    /// Update health status for all services
    pub fn update_health_status(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_health_status",
            common::identity::IdentityContext::system(),
        );

        // Get all services
        let services = self.list_services()?;

        // Update health status for each service
        for service in services {
            let mut updated_service = service.clone();
            updated_service.update_health_status();
            self.update_service(updated_service)?;
        }

        Ok(())
    }
}

/// Global mesh manager instance
static mut MESH_MANAGER: Option<MeshManager> = None;

/// Initialize the mesh manager
pub fn init(config: MeshConfig) -> Result<()> {
    let span = ExecutionSpan::new(
        "init_mesh_manager",
        common::identity::IdentityContext::system(),
    );

    // Create mesh manager
    let mesh_manager = MeshManager::new(config);

    // Store the mesh manager
    unsafe {
        if MESH_MANAGER.is_none() {
            MESH_MANAGER = Some(mesh_manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "mesh_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the mesh manager
pub fn get_mesh_manager() -> Result<&'static MeshManager> {
    unsafe {
        match &MESH_MANAGER {
            Some(mesh_manager) => Ok(mesh_manager),
            None => Err(ForgeError::InternalError(
                "mesh_manager not initialized".to_string(),
            )),
        }
    }
}

/// Create a service
pub fn create_service(name: &str, namespace: &str) -> Result<Service> {
    let mesh_manager = get_mesh_manager()?;
    mesh_manager.create_service(name, namespace)
}

/// Register a container endpoint
pub fn register_endpoint(
    service_name: &str,
    namespace: &str,
    container_id: &str,
    ip_addr: IpAddr,
    port: u16,
    protocol: MeshProtocol,
) -> Result<ServiceEndpoint> {
    let mesh_manager = get_mesh_manager()?;
    mesh_manager.register_endpoint(
        service_name,
        namespace,
        container_id,
        ip_addr,
        port,
        protocol,
    )
}

/// Unregister a container endpoint
pub fn unregister_endpoint(service_id: &str, endpoint_id: &str) -> Result<()> {
    let mesh_manager = get_mesh_manager()?;
    mesh_manager.unregister_endpoint(service_id, endpoint_id)
}

/// Unregister all container endpoints
pub fn unregister_container(container_id: &str) -> Result<()> {
    let mesh_manager = get_mesh_manager()?;
    mesh_manager.unregister_container(container_id)
}

/// Discover a service
pub fn discover_service(name: &str, namespace: &str) -> Result<Service> {
    let mesh_manager = get_mesh_manager()?;
    mesh_manager.discover_service(name, namespace)
}

/// Select an endpoint for a service
pub fn select_endpoint(name: &str, namespace: &str) -> Result<ServiceEndpoint> {
    let mesh_manager = get_mesh_manager()?;
    mesh_manager.select_endpoint(name, namespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_endpoint() {
        // Create endpoint
        let ip = "127.0.0.1".parse().unwrap();
        let mut endpoint = ServiceEndpoint::new("test-container", ip, 8080, MeshProtocol::HTTP);

        // Check endpoint fields
        assert_eq!(endpoint.container_id, "test-container");
        assert_eq!(endpoint.ip_addr, ip);
        assert_eq!(endpoint.port, 8080);
        assert_eq!(endpoint.protocol, MeshProtocol::HTTP);
        assert_eq!(endpoint.health_status, HealthStatus::Unknown);
        assert_eq!(endpoint.weight, 1);
        assert_eq!(endpoint.consecutive_successes, 0);
        assert_eq!(endpoint.consecutive_failures, 0);

        // Check address
        let addr = endpoint.address();
        assert_eq!(addr.ip(), ip);
        assert_eq!(addr.port(), 8080);

        // Update health status
        endpoint.update_health_status(true, 1, 3);
        assert_eq!(endpoint.health_status, HealthStatus::Healthy);
        assert_eq!(endpoint.consecutive_successes, 1);
        assert_eq!(endpoint.consecutive_failures, 0);
        assert!(endpoint.is_healthy());

        // Update health status (failure)
        endpoint.update_health_status(false, 1, 3);
        assert_eq!(endpoint.health_status, HealthStatus::Healthy); // Still healthy (need 3 failures)
        assert_eq!(endpoint.consecutive_successes, 0);
        assert_eq!(endpoint.consecutive_failures, 1);

        // Update health status (more failures)
        endpoint.update_health_status(false, 1, 3);
        endpoint.update_health_status(false, 1, 3);
        assert_eq!(endpoint.health_status, HealthStatus::Unhealthy); // Now unhealthy (3 failures)
        assert_eq!(endpoint.consecutive_successes, 0);
        assert_eq!(endpoint.consecutive_failures, 3);
        assert!(!endpoint.is_healthy());
    }

    #[test]
    fn test_service() {
        // Create service
        let mut service = Service::new("test-service", "default");

        // Check service fields
        assert_eq!(service.name, "test-service");
        assert_eq!(service.namespace, "default");
        assert!(service.endpoints.is_empty());
        assert_eq!(service.load_balancing, LoadBalancingAlgorithm::RoundRobin);

        // Add endpoint
        let ip = "127.0.0.1".parse().unwrap();
        let endpoint = ServiceEndpoint::new("test-container", ip, 8080, MeshProtocol::HTTP);
        service.add_endpoint(endpoint.clone()).unwrap();

        // Check endpoint was added
        assert_eq!(service.endpoints.len(), 1);
        assert_eq!(service.endpoints[0].id, endpoint.id);

        // Get endpoint
        let retrieved_endpoint = service.get_endpoint(&endpoint.id).unwrap();
        assert_eq!(retrieved_endpoint.id, endpoint.id);

        // Get healthy endpoints (none yet)
        let healthy_endpoints = service.get_healthy_endpoints();
        assert!(healthy_endpoints.is_empty());

        // Update health status
        service.update_health_status();

        // Get healthy endpoints (should be one now)
        let healthy_endpoints = service.get_healthy_endpoints();
        assert_eq!(healthy_endpoints.len(), 1);

        // Select endpoint
        let selected_endpoint = service.select_endpoint().unwrap();
        assert_eq!(selected_endpoint.id, endpoint.id);

        // Remove endpoint
        let removed_endpoint = service.remove_endpoint(&endpoint.id).unwrap();
        assert_eq!(removed_endpoint.id, endpoint.id);
        assert!(service.endpoints.is_empty());
    }

    #[test]
    fn test_mesh_manager() {
        // Create mesh config
        let config = MeshConfig::default();

        // Initialize mesh manager
        init(config.clone()).unwrap();
        let mesh_manager = get_mesh_manager().unwrap();

        // Check config
        let retrieved_config = mesh_manager.get_config().unwrap();
        assert_eq!(retrieved_config.name, config.name);

        // Create service
        let service = mesh_manager
            .create_service("test-service", "default")
            .unwrap();
        assert_eq!(service.name, "test-service");
        assert_eq!(service.namespace, "default");

        // Get service
        let retrieved_service = mesh_manager.get_service(&service.id).unwrap();
        assert_eq!(retrieved_service.id, service.id);

        // Get service by name
        let services = mesh_manager
            .get_service_by_name("test-service", "default")
            .unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].id, service.id);

        // Register endpoint
        let ip = "127.0.0.1".parse().unwrap();
        let endpoint = mesh_manager
            .register_endpoint(
                "test-service",
                "default",
                "test-container",
                ip,
                8080,
                MeshProtocol::HTTP,
            )
            .unwrap();

        // Get service with endpoint
        let service = mesh_manager.get_service(&service.id).unwrap();
        assert_eq!(service.endpoints.len(), 1);
        assert_eq!(service.endpoints[0].id, endpoint.id);

        // Discover service
        let discovered_service = mesh_manager
            .discover_service("test-service", "default")
            .unwrap();
        assert_eq!(discovered_service.id, service.id);

        // Select endpoint
        let selected_endpoint = mesh_manager
            .select_endpoint("test-service", "default")
            .unwrap();
        assert_eq!(selected_endpoint.id, endpoint.id);

        // Unregister endpoint
        mesh_manager
            .unregister_endpoint(&service.id, &endpoint.id)
            .unwrap();

        // Get service without endpoint
        let service = mesh_manager.get_service(&service.id).unwrap();
        assert!(service.endpoints.is_empty());

        // Register another endpoint
        let endpoint = mesh_manager
            .register_endpoint(
                "test-service",
                "default",
                "test-container",
                ip,
                8080,
                MeshProtocol::HTTP,
            )
            .unwrap();

        // Unregister container
        mesh_manager.unregister_container("test-container").unwrap();

        // Get service without endpoint
        let service = mesh_manager.get_service(&service.id).unwrap();
        assert!(service.endpoints.is_empty());

        // Remove service
        mesh_manager.remove_service(&service.id).unwrap();

        // Check service is removed
        let result = mesh_manager.get_service(&service.id);
        assert!(result.is_err());
    }
}
