use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use hyper::{Body, Client, Method, Request, StatusCode};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tokio::time::sleep;

use quantum_network_manager::api::{ApiConfig, ApiServer};
use quantum_network_manager::vnet::{DriverType, IsolationMode, VirtualNetwork, VNetManager};

// Mock VNetManager for testing
struct MockVNetManager {
    networks: RwLock<HashMap<String, VirtualNetwork>>,
}

impl MockVNetManager {
    fn new() -> Self {
        Self {
            networks: RwLock::new(HashMap::new()),
        }
    }

    async fn create_network(&self, network: VirtualNetwork) -> Result<VirtualNetwork, String> {
        let mut networks = self.networks.write().await;
        networks.insert(network.id.clone(), network.clone());
        Ok(network)
    }

    async fn get_network(&self, id: &str) -> Result<VirtualNetwork, String> {
        let networks = self.networks.read().await;
        networks
            .get(id)
            .cloned()
            .ok_or_else(|| format!("Network not found: {}", id))
    }

    async fn list_networks(&self) -> Result<Vec<VirtualNetwork>, String> {
        let networks = self.networks.read().await;
        Ok(networks.values().cloned().collect())
    }

    async fn delete_network(&self, id: &str) -> Result<(), String> {
        let mut networks = self.networks.write().await;
        networks
            .remove(id)
            .ok_or_else(|| format!("Network not found: {}", id))?;
        Ok(())
    }
}

#[tokio::test]
async fn test_api_create_network() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Configure API server
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Use random port
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        auth_enabled: false,
        auth_jwt_secret: None,
        auth_api_keys: None,
        metrics_enabled: false,
    };

    // Start API server
    let api_server = ApiServer::new(config, vnet_manager.clone());
    let server_addr = api_server.start().await.expect("Failed to start API server");

    // Create HTTP client
    let client = Client::new();

    // Test create network
    let network_request = json!({
        "name": "test-network",
        "cidr": "172.20.0.0/16",
        "driver_type": "bridge",
        "isolation_mode": "full",
        "options": {},
        "labels": {"test": "true"}
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/networks", server_addr))
        .header("content-type", "application/json")
        .body(Body::from(network_request.to_string()))
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body_bytes = hyper::body::to_bytes(response.into_body())
        .await
        .expect("Failed to read response body");
    let body: Value = serde_json::from_slice(&body_bytes).expect("Failed to parse JSON");

    assert_eq!(body["name"], "test-network");
    assert_eq!(body["cidr"], "172.20.0.0/16");
    assert_eq!(body["driver_type"], "bridge");
    assert_eq!(body["isolation_mode"], "full");
    assert_eq!(body["labels"]["test"], "true");

    // Verify network was created in the manager
    let networks = vnet_manager.list_networks().await.expect("Failed to list networks");
    assert_eq!(networks.len(), 1);
    assert_eq!(networks[0].name, "test-network");
}

#[tokio::test]
async fn test_api_get_network() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add a test network
    let network = VirtualNetwork {
        id: "test-id".to_string(),
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "172.20.0.1".to_string(),
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: {
            let mut labels = HashMap::new();
            labels.insert("test".to_string(), "true".to_string());
            labels
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    vnet_manager
        .create_network(network.clone())
        .await
        .expect("Failed to create network");

    // Configure API server
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Use random port
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        auth_enabled: false,
        auth_jwt_secret: None,
        auth_api_keys: None,
        metrics_enabled: false,
    };

    // Start API server
    let api_server = ApiServer::new(config, vnet_manager.clone());
    let server_addr = api_server.start().await.expect("Failed to start API server");

    // Create HTTP client
    let client = Client::new();

    // Test get network
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}/networks/test-id", server_addr))
        .body(Body::empty())
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = hyper::body::to_bytes(response.into_body())
        .await
        .expect("Failed to read response body");
    let body: Value = serde_json::from_slice(&body_bytes).expect("Failed to parse JSON");

    assert_eq!(body["id"], "test-id");
    assert_eq!(body["name"], "test-network");
    assert_eq!(body["cidr"], "172.20.0.0/16");
    assert_eq!(body["gateway"], "172.20.0.1");
    assert_eq!(body["driver_type"], "bridge");
    assert_eq!(body["isolation_mode"], "full");
    assert_eq!(body["labels"]["test"], "true");
}

#[tokio::test]
async fn test_api_list_networks() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add test networks
    for i in 1..=3 {
        let network = VirtualNetwork {
            id: format!("test-id-{}", i),
            name: format!("test-network-{}", i),
            cidr: format!("172.{}.0.0/16", i + 20),
            gateway: format!("172.{}.0.1", i + 20),
            driver_type: DriverType::Bridge,
            isolation_mode: IsolationMode::Full,
            options: HashMap::new(),
            labels: {
                let mut labels = HashMap::new();
                labels.insert("index".to_string(), i.to_string());
                labels
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        vnet_manager
            .create_network(network)
            .await
            .expect("Failed to create network");
    }

    // Configure API server
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Use random port
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        auth_enabled: false,
        auth_jwt_secret: None,
        auth_api_keys: None,
        metrics_enabled: false,
    };

    // Start API server
    let api_server = ApiServer::new(config, vnet_manager.clone());
    let server_addr = api_server.start().await.expect("Failed to start API server");

    // Create HTTP client
    let client = Client::new();

    // Test list networks
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}/networks", server_addr))
        .body(Body::empty())
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = hyper::body::to_bytes(response.into_body())
        .await
        .expect("Failed to read response body");
    let body: Value = serde_json::from_slice(&body_bytes).expect("Failed to parse JSON");

    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 3);

    // Verify all networks are present
    let networks = body.as_array().unwrap();
    for i in 1..=3 {
        let network = networks
            .iter()
            .find(|n| n["id"] == format!("test-id-{}", i))
            .expect("Network not found");

        assert_eq!(network["name"], format!("test-network-{}", i));
        assert_eq!(network["cidr"], format!("172.{}.0.0/16", i + 20));
        assert_eq!(network["gateway"], format!("172.{}.0.1", i + 20));
        assert_eq!(network["driver_type"], "bridge");
        assert_eq!(network["isolation_mode"], "full");
        assert_eq!(network["labels"]["index"], i.to_string());
    }
}

#[tokio::test]
async fn test_api_delete_network() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add a test network
    let network = VirtualNetwork {
        id: "test-id".to_string(),
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "172.20.0.1".to_string(),
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    vnet_manager
        .create_network(network)
        .await
        .expect("Failed to create network");

    // Configure API server
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Use random port
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        auth_enabled: false,
        auth_jwt_secret: None,
        auth_api_keys: None,
        metrics_enabled: false,
    };

    // Start API server
    let api_server = ApiServer::new(config, vnet_manager.clone());
    let server_addr = api_server.start().await.expect("Failed to start API server");

    // Create HTTP client
    let client = Client::new();

    // Test delete network
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("http://{}/networks/test-id", server_addr))
        .body(Body::empty())
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify network was deleted
    let networks = vnet_manager.list_networks().await.expect("Failed to list networks");
    assert_eq!(networks.len(), 0);
}

#[tokio::test]
async fn test_api_error_handling() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Configure API server
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Use random port
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        auth_enabled: false,
        auth_jwt_secret: None,
        auth_api_keys: None,
        metrics_enabled: false,
    };

    // Start API server
    let api_server = ApiServer::new(config, vnet_manager.clone());
    let server_addr = api_server.start().await.expect("Failed to start API server");

    // Create HTTP client
    let client = Client::new();

    // Test get non-existent network
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{}/networks/non-existent", server_addr))
        .body(Body::empty())
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Test invalid network creation
    let invalid_network = json!({
        "name": "test-network",
        "cidr": "invalid-cidr", // Invalid CIDR
        "driver_type": "bridge",
        "isolation_mode": "full"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/networks", server_addr))
        .header("content-type", "application/json")
        .body(Body::from(invalid_network.to_string()))
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test invalid JSON
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/networks", server_addr))
        .header("content-type", "application/json")
        .body(Body::from("invalid json"))
        .expect("Failed to build request");

    let response = client.request(request).await.expect("Failed to send request");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_api_concurrent_requests() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Configure API server
    let config = ApiConfig {
        bind_address: "127.0.0.1".to_string(),
        port: 0, // Use random port
        tls_enabled: false,
        tls_cert_path: None,
        tls_key_path: None,
        auth_enabled: false,
        auth_jwt_secret: None,
        auth_api_keys: None,
        metrics_enabled: false,
    };

    // Start API server
    let api_server = ApiServer::new(config, vnet_manager.clone());
    let server_addr = api_server.start().await.expect("Failed to start API server");

    // Create HTTP client
    let client = Client::new();

    // Create multiple networks concurrently
    let mut handles = vec![];
    for i in 1..=5 {
        let client = client.clone();
        let server_addr = server_addr.clone();

        let handle = tokio::spawn(async move {
            let network_request = json!({
                "name": format!("test-network-{}", i),
                "cidr": format!("172.{}.0.0/16", i + 20),
                "driver_type": "bridge",
                "isolation_mode": "full",
                "options": {},
                "labels": {"index": i.to_string()}
            });

            let request = Request::builder()
                .method(Method::POST)
                .uri(format!("http://{}/networks", server_addr))
                .header("content-type", "application/json")
                .body(Body::from(network_request.to_string()))
                .expect("Failed to build request");

            let response = client.request(request).await.expect("Failed to send request");
            assert_eq!(response.status(), StatusCode::CREATED);

            let body_bytes = hyper::body::to_bytes(response.into_body())
                .await
                .expect("Failed to read response body");
            let body: Value = serde_json::from_slice(&body_bytes).expect("Failed to parse JSON");

            body["id"].as_str().unwrap().to_string()
        });

        handles.push(handle);
    }

    // Wait for all networks to be created
    let network_ids = futures::future::join_all(handles)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to create networks");

    // Verify all networks were created
    let networks = vnet_manager.list_networks().await.expect("Failed to list networks");
    assert_eq!(networks.len(), 5);

    // Delete all networks concurrently
    let mut handles = vec![];
    for id in network_ids {
        let client = client.clone();
        let server_addr = server_addr.clone();

        let handle = tokio::spawn(async move {
            let request = Request::builder()
                .method(Method::DELETE)
                .uri(format!("http://{}/networks/{}", server_addr, id))
                .body(Body::empty())
                .expect("Failed to build request");

            let response = client.request(request).await.expect("Failed to send request");
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
        });

        handles.push(handle);
    }

    // Wait for all networks to be deleted
    futures::future::join_all(handles)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to delete networks");

    // Verify all networks were deleted
    let networks = vnet_manager.list_networks().await.expect("Failed to list networks");
    assert_eq!(networks.len(), 0);
}