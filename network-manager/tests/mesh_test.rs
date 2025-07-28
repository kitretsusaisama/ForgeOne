//! # Mesh Module Tests
//!
//! This module contains tests for the mesh networking functionality.

use network_manager::mesh::{MeshConfig, MeshEndpoint, MeshManager, MeshPeer, MeshPeerStatus, MeshService};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

/// Mock mesh control plane for testing
struct MockMeshControlPlane {
    peers: Arc<Mutex<HashMap<String, MeshPeer>>>,
    services: Arc<Mutex<HashMap<String, MeshService>>>,
}

impl MockMeshControlPlane {
    fn new() -> Self {
        Self {
            peers: Arc::new(Mutex::new(HashMap::new())),
            services: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn register_peer(&self, peer: MeshPeer) {
        let mut peers = self.peers.lock().unwrap();
        peers.insert(peer.id.clone(), peer);
    }

    fn unregister_peer(&self, peer_id: &str) {
        let mut peers = self.peers.lock().unwrap();
        peers.remove(peer_id);
    }

    fn get_peer(&self, peer_id: &str) -> Option<MeshPeer> {
        let peers = self.peers.lock().unwrap();
        peers.get(peer_id).cloned()
    }

    fn register_service(&self, service: MeshService) {
        let mut services = self.services.lock().unwrap();
        services.insert(service.id.clone(), service);
    }

    fn unregister_service(&self, service_id: &str) {
        let mut services = self.services.lock().unwrap();
        services.remove(service_id);
    }

    fn get_service(&self, service_id: &str) -> Option<MeshService> {
        let services = self.services.lock().unwrap();
        services.get(service_id).cloned()
    }

    fn discover_services(&self, name: &str) -> Vec<MeshService> {
        let services = self.services.lock().unwrap();
        services
            .values()
            .filter(|s| s.name == name)
            .cloned()
            .collect()
    }
}

#[tokio::test]
async fn test_mesh_manager_init() {
    // Create a mesh configuration with mesh enabled
    let config = MeshConfig {
        enabled: true,
        control_plane_address: "127.0.0.1".to_string(),
        control_plane_port: 9200,
        encryption_enabled: true,
        mtu: 1450,
    };

    // Create a mesh manager
    let mut mesh_manager = MeshManager::new(config);

    // Initialize the mesh manager
    let result = mesh_manager.init().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_mesh_manager_disabled() {
    // Create a mesh configuration with mesh disabled
    let config = MeshConfig {
        enabled: false,
        ..MeshConfig::default()
    };

    // Create a mesh manager
    let mut mesh_manager = MeshManager::new(config);

    // Initialize the mesh manager
    let result = mesh_manager.init().await;
    assert!(result.is_ok());
}

#[test]
fn test_mesh_peer_registration() {
    // Create a mesh configuration
    let config = MeshConfig::default();

    // Create a mesh manager
    let mesh_manager = MeshManager::new(config);

    // Create a peer
    let peer = MeshPeer {
        id: "peer1".to_string(),
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9201),
        public_key: Some("test-key".to_string()),
        status: MeshPeerStatus::Active,
        last_seen: chrono::Utc::now(),
    };

    // Register the peer
    let result = mesh_manager.register_peer(peer.clone());
    assert!(result.is_ok());

    // Get the peer
    let retrieved_peer = mesh_manager.get_peer(&peer.id);
    assert!(retrieved_peer.is_some());
    assert_eq!(retrieved_peer.unwrap().id, peer.id);

    // Unregister the peer
    let result = mesh_manager.unregister_peer(&peer.id);
    assert!(result.is_ok());

    // Verify the peer is gone
    let retrieved_peer = mesh_manager.get_peer(&peer.id);
    assert!(retrieved_peer.is_none());
}

#[test]
fn test_mesh_service_registration() {
    // Create a mesh configuration
    let config = MeshConfig::default();

    // Create a mesh manager
    let mesh_manager = MeshManager::new(config);

    // Create a service
    let service = MeshService {
        id: "service1".to_string(),
        name: "test-service".to_string(),
        endpoints: vec![MeshEndpoint {
            id: "endpoint1".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            weight: 1,
            healthy: true,
        }],
        metadata: HashMap::new(),
    };

    // Register the service
    let result = mesh_manager.register_service(service.clone());
    assert!(result.is_ok());

    // Get the service
    let retrieved_service = mesh_manager.get_service(&service.id);
    assert!(retrieved_service.is_some());
    assert_eq!(retrieved_service.unwrap().id, service.id);

    // Discover services by name
    let discovered_services = mesh_manager.discover_services(&service.name);
    assert_eq!(discovered_services.len(), 1);
    assert_eq!(discovered_services[0].id, service.id);

    // Unregister the service
    let result = mesh_manager.unregister_service(&service.id);
    assert!(result.is_ok());

    // Verify the service is gone
    let retrieved_service = mesh_manager.get_service(&service.id);
    assert!(retrieved_service.is_none());
}

#[test]
fn test_mesh_service_discovery() {
    // Create a mesh configuration
    let config = MeshConfig::default();

    // Create a mesh manager
    let mesh_manager = MeshManager::new(config);

    // Create multiple services with the same name
    let service1 = MeshService {
        id: "service1".to_string(),
        name: "test-service".to_string(),
        endpoints: vec![MeshEndpoint {
            id: "endpoint1".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            weight: 1,
            healthy: true,
        }],
        metadata: HashMap::new(),
    };

    let service2 = MeshService {
        id: "service2".to_string(),
        name: "test-service".to_string(),
        endpoints: vec![MeshEndpoint {
            id: "endpoint2".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            weight: 1,
            healthy: true,
        }],
        metadata: HashMap::new(),
    };

    // Register the services
    mesh_manager.register_service(service1.clone()).unwrap();
    mesh_manager.register_service(service2.clone()).unwrap();

    // Discover services by name
    let discovered_services = mesh_manager.discover_services(&service1.name);
    assert_eq!(discovered_services.len(), 2);

    // Verify both services are discovered
    let service_ids: Vec<String> = discovered_services.iter().map(|s| s.id.clone()).collect();
    assert!(service_ids.contains(&service1.id));
    assert!(service_ids.contains(&service2.id));
}

#[test]
fn test_mesh_connection_policy() {
    // Create a mesh configuration
    let config = MeshConfig::default();

    // Create a mesh manager
    let mut mesh_manager = MeshManager::new(config);

    // Check connection allowed (no policy graph set)
    let allowed = mesh_manager.is_connection_allowed("source", "destination", "action");
    assert!(allowed);

    // Set a policy graph (in a real implementation, this would be a proper graph)
    let policy_graph = common::trust::ZtaPolicyGraph::new();
    mesh_manager.set_policy_graph(policy_graph);

    // Check connection allowed (with policy graph set)
    let allowed = mesh_manager.is_connection_allowed("source", "destination", "action");
    assert!(allowed);
}

#[test]
fn test_mock_mesh_control_plane() {
    // Create a mock control plane
    let control_plane = MockMeshControlPlane::new();

    // Create a peer
    let peer = MeshPeer {
        id: "peer1".to_string(),
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9201),
        public_key: Some("test-key".to_string()),
        status: MeshPeerStatus::Active,
        last_seen: chrono::Utc::now(),
    };

    // Register the peer
    control_plane.register_peer(peer.clone());

    // Get the peer
    let retrieved_peer = control_plane.get_peer(&peer.id);
    assert!(retrieved_peer.is_some());
    assert_eq!(retrieved_peer.unwrap().id, peer.id);

    // Create a service
    let service = MeshService {
        id: "service1".to_string(),
        name: "test-service".to_string(),
        endpoints: vec![MeshEndpoint {
            id: "endpoint1".to_string(),
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            weight: 1,
            healthy: true,
        }],
        metadata: HashMap::new(),
    };

    // Register the service
    control_plane.register_service(service.clone());

    // Get the service
    let retrieved_service = control_plane.get_service(&service.id);
    assert!(retrieved_service.is_some());
    assert_eq!(retrieved_service.unwrap().id, service.id);

    // Discover services by name
    let discovered_services = control_plane.discover_services(&service.name);
    assert_eq!(discovered_services.len(), 1);
    assert_eq!(discovered_services[0].id, service.id);
}