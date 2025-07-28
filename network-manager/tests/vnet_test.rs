use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;

use quantum_network_manager::vnet::{DriverType, Endpoint, IpamConfig, IsolationMode, VNetConfig, VNetManager, VirtualNetwork};

#[tokio::test]
async fn test_vnet_create_network() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create a test network
    let network_request = VirtualNetwork {
        id: "".to_string(), // Will be generated
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "".to_string(), // Will be generated
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

    let network = vnet_manager
        .create_network(network_request)
        .await
        .expect("Failed to create network");

    // Verify network properties
    assert!(!network.id.is_empty());
    assert_eq!(network.name, "test-network");
    assert_eq!(network.cidr, "172.20.0.0/16");
    assert_eq!(network.gateway, "172.20.0.1");
    assert_eq!(network.driver_type, DriverType::Bridge);
    assert_eq!(network.isolation_mode, IsolationMode::Full);
    assert_eq!(network.labels["test"], "true");

    // Get the network
    let retrieved_network = vnet_manager
        .get_network(&network.id)
        .await
        .expect("Failed to get network");

    assert_eq!(retrieved_network.id, network.id);
    assert_eq!(retrieved_network.name, network.name);
    assert_eq!(retrieved_network.cidr, network.cidr);
    assert_eq!(retrieved_network.gateway, network.gateway);
}

#[tokio::test]
async fn test_vnet_list_networks() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create multiple test networks
    for i in 1..=3 {
        let network_request = VirtualNetwork {
            id: "".to_string(), // Will be generated
            name: format!("test-network-{}", i),
            cidr: format!("172.{}.0.0/16", i + 20),
            gateway: "".to_string(), // Will be generated
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
            .create_network(network_request)
            .await
            .expect("Failed to create network");
    }

    // List networks
    let networks = vnet_manager
        .list_networks()
        .await
        .expect("Failed to list networks");

    // Verify networks
    assert_eq!(networks.len(), 3);

    // Verify each network exists
    for i in 1..=3 {
        let network = networks
            .iter()
            .find(|n| n.name == format!("test-network-{}", i))
            .expect("Network not found");

        assert_eq!(network.cidr, format!("172.{}.0.0/16", i + 20));
        assert_eq!(network.gateway, format!("172.{}.0.1", i + 20));
        assert_eq!(network.driver_type, DriverType::Bridge);
        assert_eq!(network.isolation_mode, IsolationMode::Full);
        assert_eq!(network.labels["index"], i.to_string());
    }
}

#[tokio::test]
async fn test_vnet_delete_network() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create a test network
    let network_request = VirtualNetwork {
        id: "".to_string(), // Will be generated
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "".to_string(), // Will be generated
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let network = vnet_manager
        .create_network(network_request)
        .await
        .expect("Failed to create network");

    // Delete the network
    vnet_manager
        .delete_network(&network.id)
        .await
        .expect("Failed to delete network");

    // Verify network is deleted
    let result = vnet_manager.get_network(&network.id).await;
    assert!(result.is_err());

    // List networks should be empty
    let networks = vnet_manager
        .list_networks()
        .await
        .expect("Failed to list networks");
    assert_eq!(networks.len(), 0);
}

#[tokio::test]
async fn test_vnet_create_endpoint() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create a test network
    let network_request = VirtualNetwork {
        id: "".to_string(), // Will be generated
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "".to_string(), // Will be generated
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let network = vnet_manager
        .create_network(network_request)
        .await
        .expect("Failed to create network");

    // Create an endpoint
    let endpoint = vnet_manager
        .create_endpoint(
            &network.id,
            "test-container",
            "/proc/1234/ns/net",
            "eth0",
            None, // Let IPAM assign an IP
            None, // Let IPAM assign a MAC
        )
        .await
        .expect("Failed to create endpoint");

    // Verify endpoint properties
    assert!(!endpoint.id.is_empty());
    assert_eq!(endpoint.network_id, network.id);
    assert_eq!(endpoint.container_id, "test-container");
    assert_eq!(endpoint.namespace, "/proc/1234/ns/net");
    assert_eq!(endpoint.interface_name, "eth0");
    assert!(!endpoint.ip_address.is_empty());
    assert!(!endpoint.mac_address.is_empty());
    assert_eq!(endpoint.gateway, network.gateway);

    // Get the endpoint
    let retrieved_endpoint = vnet_manager
        .get_endpoint(&endpoint.id)
        .await
        .expect("Failed to get endpoint");

    assert_eq!(retrieved_endpoint.id, endpoint.id);
    assert_eq!(retrieved_endpoint.network_id, endpoint.network_id);
    assert_eq!(retrieved_endpoint.container_id, endpoint.container_id);
    assert_eq!(retrieved_endpoint.ip_address, endpoint.ip_address);
    assert_eq!(retrieved_endpoint.mac_address, endpoint.mac_address);
}

#[tokio::test]
async fn test_vnet_delete_endpoint() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create a test network
    let network_request = VirtualNetwork {
        id: "".to_string(), // Will be generated
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "".to_string(), // Will be generated
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let network = vnet_manager
        .create_network(network_request)
        .await
        .expect("Failed to create network");

    // Create an endpoint
    let endpoint = vnet_manager
        .create_endpoint(
            &network.id,
            "test-container",
            "/proc/1234/ns/net",
            "eth0",
            None, // Let IPAM assign an IP
            None, // Let IPAM assign a MAC
        )
        .await
        .expect("Failed to create endpoint");

    // Delete the endpoint
    vnet_manager
        .delete_endpoint(&endpoint.id)
        .await
        .expect("Failed to delete endpoint");

    // Verify endpoint is deleted
    let result = vnet_manager.get_endpoint(&endpoint.id).await;
    assert!(result.is_err());

    // List endpoints should be empty
    let endpoints = vnet_manager
        .list_endpoints()
        .await
        .expect("Failed to list endpoints");
    assert_eq!(endpoints.len(), 0);
}

#[tokio::test]
async fn test_vnet_get_endpoint_by_container() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create a test network
    let network_request = VirtualNetwork {
        id: "".to_string(), // Will be generated
        name: "test-network".to_string(),
        cidr: "172.20.0.0/16".to_string(),
        gateway: "".to_string(), // Will be generated
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let network = vnet_manager
        .create_network(network_request)
        .await
        .expect("Failed to create network");

    // Create an endpoint
    let endpoint = vnet_manager
        .create_endpoint(
            &network.id,
            "test-container",
            "/proc/1234/ns/net",
            "eth0",
            None, // Let IPAM assign an IP
            None, // Let IPAM assign a MAC
        )
        .await
        .expect("Failed to create endpoint");

    // Get endpoint by container ID
    let retrieved_endpoint = vnet_manager
        .get_endpoint_by_container("test-container")
        .await
        .expect("Failed to get endpoint by container");

    assert_eq!(retrieved_endpoint.id, endpoint.id);
    assert_eq!(retrieved_endpoint.container_id, "test-container");
}

#[tokio::test]
async fn test_vnet_multiple_networks_and_endpoints() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create multiple networks
    let mut network_ids = Vec::new();
    for i in 1..=3 {
        let network_request = VirtualNetwork {
            id: "".to_string(), // Will be generated
            name: format!("test-network-{}", i),
            cidr: format!("172.{}.0.0/16", i + 20),
            gateway: "".to_string(), // Will be generated
            driver_type: DriverType::Bridge,
            isolation_mode: IsolationMode::Full,
            options: HashMap::new(),
            labels: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let network = vnet_manager
            .create_network(network_request)
            .await
            .expect("Failed to create network");

        network_ids.push(network.id);
    }

    // Create multiple endpoints in each network
    for (i, network_id) in network_ids.iter().enumerate() {
        for j in 1..=2 {
            let container_id = format!("container-{}-{}", i + 1, j);
            let endpoint = vnet_manager
                .create_endpoint(
                    network_id,
                    &container_id,
                    &format!("/proc/{}/ns/net", 1000 + i * 10 + j),
                    "eth0",
                    None, // Let IPAM assign an IP
                    None, // Let IPAM assign a MAC
                )
                .await
                .expect("Failed to create endpoint");

            assert_eq!(endpoint.network_id, *network_id);
            assert_eq!(endpoint.container_id, container_id);
        }
    }

    // List all endpoints
    let endpoints = vnet_manager
        .list_endpoints()
        .await
        .expect("Failed to list endpoints");
    assert_eq!(endpoints.len(), 6); // 3 networks * 2 endpoints

    // List endpoints by network
    for network_id in &network_ids {
        let network_endpoints = vnet_manager
            .list_endpoints_by_network(network_id)
            .await
            .expect("Failed to list endpoints by network");
        assert_eq!(network_endpoints.len(), 2);
    }

    // Delete a network and verify its endpoints are deleted
    vnet_manager
        .delete_network(&network_ids[0])
        .await
        .expect("Failed to delete network");

    let endpoints = vnet_manager
        .list_endpoints()
        .await
        .expect("Failed to list endpoints");
    assert_eq!(endpoints.len(), 4); // 2 networks * 2 endpoints

    let networks = vnet_manager
        .list_networks()
        .await
        .expect("Failed to list networks");
    assert_eq!(networks.len(), 2);
}

#[tokio::test]
async fn test_vnet_ipam() {
    // Create VNetManager with custom IPAM config
    let mut config = VNetConfig::default();
    config.ipam = IpamConfig {
        subnet_prefix_length: 24,
        allocation_ranges: vec!["10.0.0.0/16".to_string()],
        excluded_ips: vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
    };

    let vnet_manager = VNetManager::new(config);

    // Create a network with custom CIDR
    let network_request = VirtualNetwork {
        id: "".to_string(),
        name: "test-network".to_string(),
        cidr: "10.0.0.0/24".to_string(),
        gateway: "10.0.0.1".to_string(),
        driver_type: DriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let network = vnet_manager
        .create_network(network_request)
        .await
        .expect("Failed to create network");

    // Create multiple endpoints and verify IP allocation
    let mut allocated_ips = Vec::new();
    for i in 1..=5 {
        let endpoint = vnet_manager
            .create_endpoint(
                &network.id,
                &format!("container-{}", i),
                &format!("/proc/{}/ns/net", 1000 + i),
                "eth0",
                None, // Let IPAM assign an IP
                None, // Let IPAM assign a MAC
            )
            .await
            .expect("Failed to create endpoint");

        // Verify IP is in the correct subnet
        assert!(endpoint.ip_address.starts_with("10.0.0."));
        
        // Verify IP is not in excluded list
        assert_ne!(endpoint.ip_address, "10.0.0.1");
        assert_ne!(endpoint.ip_address, "10.0.0.2");
        
        // Verify IP is unique
        assert!(!allocated_ips.contains(&endpoint.ip_address));
        allocated_ips.push(endpoint.ip_address.clone());
    }

    // Create endpoint with specific IP
    let endpoint = vnet_manager
        .create_endpoint(
            &network.id,
            "container-specific",
            "/proc/2000/ns/net",
            "eth0",
            Some("10.0.0.100".to_string()), // Specific IP
            None, // Let IPAM assign a MAC
        )
        .await
        .expect("Failed to create endpoint");

    assert_eq!(endpoint.ip_address, "10.0.0.100");
    allocated_ips.push(endpoint.ip_address.clone());

    // Try to create endpoint with already allocated IP
    let result = vnet_manager
        .create_endpoint(
            &network.id,
            "container-conflict",
            "/proc/3000/ns/net",
            "eth0",
            Some("10.0.0.100".to_string()), // Already allocated
            None,
        )
        .await;

    assert!(result.is_err());

    // Delete an endpoint and verify its IP is released
    vnet_manager
        .delete_endpoint(&endpoint.id)
        .await
        .expect("Failed to delete endpoint");

    // Create a new endpoint and verify it can reuse the released IP
    let new_endpoint = vnet_manager
        .create_endpoint(
            &network.id,
            "container-reuse",
            "/proc/4000/ns/net",
            "eth0",
            Some("10.0.0.100".to_string()), // Previously allocated but now released
            None,
        )
        .await
        .expect("Failed to create endpoint");

    assert_eq!(new_endpoint.ip_address, "10.0.0.100");
}

#[tokio::test]
async fn test_vnet_isolation_modes() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create networks with different isolation modes
    let isolation_modes = vec![
        IsolationMode::Full,
        IsolationMode::PeerOnly,
        IsolationMode::MeshOnly,
        IsolationMode::None,
    ];

    let mut networks = Vec::new();
    for (i, mode) in isolation_modes.iter().enumerate() {
        let network_request = VirtualNetwork {
            id: "".to_string(),
            name: format!("network-{}", i),
            cidr: format!("172.{}.0.0/16", i + 20),
            gateway: "".to_string(),
            driver_type: DriverType::Bridge,
            isolation_mode: mode.clone(),
            options: HashMap::new(),
            labels: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let network = vnet_manager
            .create_network(network_request)
            .await
            .expect("Failed to create network");

        networks.push(network);
    }

    // Verify isolation modes were set correctly
    for (i, mode) in isolation_modes.iter().enumerate() {
        assert_eq!(networks[i].isolation_mode, *mode);
    }

    // Create endpoints in each network
    for network in &networks {
        let endpoint = vnet_manager
            .create_endpoint(
                &network.id,
                &format!("container-{}", network.name),
                &format!("/proc/{}/ns/net", 1000),
                "eth0",
                None,
                None,
            )
            .await
            .expect("Failed to create endpoint");

        assert_eq!(endpoint.network_id, network.id);
    }

    // Verify connectivity based on isolation mode would require integration tests
    // with actual network interfaces and firewall rules
}

#[tokio::test]
async fn test_vnet_driver_types() {
    // Create VNetManager with default config
    let config = VNetConfig::default();
    let vnet_manager = VNetManager::new(config);

    // Create networks with different driver types
    let driver_types = vec![
        DriverType::Bridge,
        DriverType::Overlay,
        DriverType::Macvlan,
        DriverType::Ipvlan,
        DriverType::Host,
    ];

    let mut networks = Vec::new();
    for (i, driver) in driver_types.iter().enumerate() {
        let network_request = VirtualNetwork {
            id: "".to_string(),
            name: format!("network-{}", i),
            cidr: format!("172.{}.0.0/16", i + 20),
            gateway: "".to_string(),
            driver_type: driver.clone(),
            isolation_mode: IsolationMode::Full,
            options: HashMap::new(),
            labels: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let network = vnet_manager
            .create_network(network_request)
            .await
            .expect("Failed to create network");

        networks.push(network);
    }

    // Verify driver types were set correctly
    for (i, driver) in driver_types.iter().enumerate() {
        assert_eq!(networks[i].driver_type, *driver);
    }

    // Note: Testing actual network creation with different drivers
    // would require integration tests with actual network interfaces
}