use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use serde_json::{json, Value};
use tokio::sync::RwLock;

use quantum_network_manager::cni::{CniConfig, CniManager, CniRequest, CniResult, Command};
use quantum_network_manager::vnet::{DriverType, Endpoint, IsolationMode, VirtualNetwork, VNetManager};

// Mock VNetManager for testing
struct MockVNetManager {
    networks: RwLock<HashMap<String, VirtualNetwork>>,
    endpoints: RwLock<HashMap<String, Endpoint>>,
}

impl MockVNetManager {
    fn new() -> Self {
        Self {
            networks: RwLock::new(HashMap::new()),
            endpoints: RwLock::new(HashMap::new()),
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

    async fn create_endpoint(
        &self,
        network_id: &str,
        container_id: &str,
        namespace: &str,
    ) -> Result<Endpoint, String> {
        // Check if network exists
        let networks = self.networks.read().await;
        if !networks.contains_key(network_id) {
            return Err(format!("Network not found: {}", network_id));
        }

        // Create endpoint
        let endpoint = Endpoint {
            id: format!("ep-{}", container_id),
            network_id: network_id.to_string(),
            container_id: container_id.to_string(),
            namespace: namespace.to_string(),
            interface_name: "eth0".to_string(),
            ip_address: "172.20.0.2".to_string(),
            mac_address: "02:42:ac:14:00:02".to_string(),
            gateway: "172.20.0.1".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut endpoints = self.endpoints.write().await;
        endpoints.insert(endpoint.id.clone(), endpoint.clone());
        Ok(endpoint)
    }

    async fn delete_endpoint(&self, id: &str) -> Result<(), String> {
        let mut endpoints = self.endpoints.write().await;
        endpoints
            .remove(id)
            .ok_or_else(|| format!("Endpoint not found: {}", id))?;
        Ok(())
    }

    async fn get_endpoint(&self, id: &str) -> Result<Endpoint, String> {
        let endpoints = self.endpoints.read().await;
        endpoints
            .get(id)
            .cloned()
            .ok_or_else(|| format!("Endpoint not found: {}", id))
    }

    async fn get_endpoint_by_container(
        &self,
        container_id: &str,
    ) -> Result<Endpoint, String> {
        let endpoints = self.endpoints.read().await;
        endpoints
            .values()
            .find(|e| e.container_id == container_id)
            .cloned()
            .ok_or_else(|| format!("Endpoint not found for container: {}", container_id))
    }
}

#[tokio::test]
async fn test_cni_add_command() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add a test network
    let network = VirtualNetwork {
        id: "test-network".to_string(),
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

    // Create CNI manager
    let config = CniConfig {
        socket_path: PathBuf::from("/tmp/cni.sock"),
        log_level: "info".to_string(),
        metrics_enabled: false,
    };

    let cni_manager = CniManager::new(config, vnet_manager.clone());

    // Create ADD request
    let request = CniRequest {
        command: Command::Add,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network",
            "type": "quantum-cni",
            "network": "test-network",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    // Execute ADD command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify result
    assert_eq!(result.code, 0);
    assert!(!result.msg.contains("error"));

    let result_json: Value = serde_json::from_str(&result.data).expect("Failed to parse JSON");
    assert_eq!(result_json["cniVersion"], "0.4.0");
    assert_eq!(result_json["interfaces"][0]["name"], "eth0");
    assert_eq!(result_json["interfaces"][0]["mac"], "02:42:ac:14:00:02");
    assert_eq!(result_json["ips"][0]["address"], "172.20.0.2/16");
    assert_eq!(result_json["ips"][0]["gateway"], "172.20.0.1");

    // Verify endpoint was created
    let endpoint = vnet_manager
        .get_endpoint_by_container("test-container")
        .await
        .expect("Failed to get endpoint");

    assert_eq!(endpoint.container_id, "test-container");
    assert_eq!(endpoint.network_id, "test-network");
    assert_eq!(endpoint.namespace, "/proc/1234/ns/net");
    assert_eq!(endpoint.interface_name, "eth0");
    assert_eq!(endpoint.ip_address, "172.20.0.2");
    assert_eq!(endpoint.mac_address, "02:42:ac:14:00:02");
    assert_eq!(endpoint.gateway, "172.20.0.1");
}

#[tokio::test]
async fn test_cni_del_command() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add a test network
    let network = VirtualNetwork {
        id: "test-network".to_string(),
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

    // Create an endpoint
    let endpoint = vnet_manager
        .create_endpoint(
            "test-network",
            "test-container",
            "/proc/1234/ns/net",
        )
        .await
        .expect("Failed to create endpoint");

    // Create CNI manager
    let config = CniConfig {
        socket_path: PathBuf::from("/tmp/cni.sock"),
        log_level: "info".to_string(),
        metrics_enabled: false,
    };

    let cni_manager = CniManager::new(config, vnet_manager.clone());

    // Create DEL request
    let request = CniRequest {
        command: Command::Del,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network",
            "type": "quantum-cni",
            "network": "test-network",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    // Execute DEL command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify result
    assert_eq!(result.code, 0);
    assert!(!result.msg.contains("error"));

    // Verify endpoint was deleted
    let endpoint_result = vnet_manager.get_endpoint(&endpoint.id).await;
    assert!(endpoint_result.is_err());
}

#[tokio::test]
async fn test_cni_check_command() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add a test network
    let network = VirtualNetwork {
        id: "test-network".to_string(),
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

    // Create an endpoint
    vnet_manager
        .create_endpoint(
            "test-network",
            "test-container",
            "/proc/1234/ns/net",
        )
        .await
        .expect("Failed to create endpoint");

    // Create CNI manager
    let config = CniConfig {
        socket_path: PathBuf::from("/tmp/cni.sock"),
        log_level: "info".to_string(),
        metrics_enabled: false,
    };

    let cni_manager = CniManager::new(config, vnet_manager.clone());

    // Create CHECK request
    let request = CniRequest {
        command: Command::Check,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network",
            "type": "quantum-cni",
            "network": "test-network",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    // Execute CHECK command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify result
    assert_eq!(result.code, 0);
    assert!(!result.msg.contains("error"));
}

#[tokio::test]
async fn test_cni_version_command() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Create CNI manager
    let config = CniConfig {
        socket_path: PathBuf::from("/tmp/cni.sock"),
        log_level: "info".to_string(),
        metrics_enabled: false,
    };

    let cni_manager = CniManager::new(config, vnet_manager.clone());

    // Create VERSION request
    let request = CniRequest {
        command: Command::Version,
        container_id: "".to_string(),
        netns: "".to_string(),
        ifname: "".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0"
        })
        .to_string(),
    };

    // Execute VERSION command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify result
    assert_eq!(result.code, 0);
    assert!(!result.msg.contains("error"));

    let result_json: Value = serde_json::from_str(&result.data).expect("Failed to parse JSON");
    assert_eq!(result_json["cniVersion"], "0.4.0");
    assert!(result_json["supportedVersions"].is_array());
}

#[tokio::test]
async fn test_cni_error_handling() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Create CNI manager
    let config = CniConfig {
        socket_path: PathBuf::from("/tmp/cni.sock"),
        log_level: "info".to_string(),
        metrics_enabled: false,
    };

    let cni_manager = CniManager::new(config, vnet_manager.clone());

    // Test with non-existent network
    let request = CniRequest {
        command: Command::Add,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network",
            "type": "quantum-cni",
            "network": "non-existent-network",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    // Execute ADD command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify error result
    assert_ne!(result.code, 0);
    assert!(result.msg.contains("error"));
    assert!(result.msg.contains("Network not found"));

    // Test with invalid JSON
    let request = CniRequest {
        command: Command::Add,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: "invalid json".to_string(),
    };

    // Execute ADD command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify error result
    assert_ne!(result.code, 0);
    assert!(result.msg.contains("error"));
    assert!(result.msg.contains("Failed to parse"));

    // Test with missing network field
    let request = CniRequest {
        command: Command::Add,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network",
            "type": "quantum-cni",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    // Execute ADD command
    let result = cni_manager.execute(request).await.expect("CNI execution failed");

    // Verify error result
    assert_ne!(result.code, 0);
    assert!(result.msg.contains("error"));
    assert!(result.msg.contains("Missing required field"));
}

#[tokio::test]
async fn test_cni_multiple_networks() {
    // Create mock VNetManager
    let vnet_manager = Arc::new(MockVNetManager::new());

    // Add test networks
    for i in 1..=2 {
        let network = VirtualNetwork {
            id: format!("test-network-{}", i),
            name: format!("test-network-{}", i),
            cidr: format!("172.{}.0.0/16", i + 20),
            gateway: format!("172.{}.0.1", i + 20),
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
    }

    // Create CNI manager
    let config = CniConfig {
        socket_path: PathBuf::from("/tmp/cni.sock"),
        log_level: "info".to_string(),
        metrics_enabled: false,
    };

    let cni_manager = CniManager::new(config, vnet_manager.clone());

    // Connect container to first network
    let request1 = CniRequest {
        command: Command::Add,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth0".to_string(),
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network-1",
            "type": "quantum-cni",
            "network": "test-network-1",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    let result1 = cni_manager.execute(request1).await.expect("CNI execution failed");
    assert_eq!(result1.code, 0);

    // Connect container to second network
    let request2 = CniRequest {
        command: Command::Add,
        container_id: "test-container".to_string(),
        netns: "/proc/1234/ns/net".to_string(),
        ifname: "eth1".to_string(), // Different interface name
        args: vec![],
        path: "/opt/cni/bin".to_string(),
        stdin: json!({
            "cniVersion": "0.4.0",
            "name": "quantum-network-2",
            "type": "quantum-cni",
            "network": "test-network-2",
            "ipam": {
                "type": "quantum-ipam"
            }
        })
        .to_string(),
    };

    let result2 = cni_manager.execute(request2).await.expect("CNI execution failed");
    assert_eq!(result2.code, 0);

    // Verify endpoints
    let endpoints = vnet_manager.endpoints.read().await;
    assert_eq!(endpoints.len(), 2);

    // Verify each endpoint is in the correct network
    let endpoints_vec: Vec<_> = endpoints.values().cloned().collect();
    let network1_endpoint = endpoints_vec
        .iter()
        .find(|e| e.network_id == "test-network-1")
        .expect("Network 1 endpoint not found");
    let network2_endpoint = endpoints_vec
        .iter()
        .find(|e| e.network_id == "test-network-2")
        .expect("Network 2 endpoint not found");

    assert_eq!(network1_endpoint.interface_name, "eth0");
    assert_eq!(network2_endpoint.interface_name, "eth1");
    assert_eq!(network1_endpoint.container_id, "test-container");
    assert_eq!(network2_endpoint.container_id, "test-container");
}