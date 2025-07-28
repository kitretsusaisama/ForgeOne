use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use quantum_network_manager::model::{Protocol, VirtualNetwork};
use quantum_network_manager::nat::{NatConfig, NatManager, NatRule, NatType, PortMapping};

// Mock NAT backend implementation for testing
struct MockNatBackend {
    rules: RwLock<HashMap<String, NatRule>>,
    port_mappings: RwLock<HashMap<String, PortMapping>>,
    ip_forwarding: RwLock<bool>,
    masquerade: RwLock<bool>,
    initialized: RwLock<bool>,
}

impl MockNatBackend {
    fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            port_mappings: RwLock::new(HashMap::new()),
            ip_forwarding: RwLock::new(false),
            masquerade: RwLock::new(false),
            initialized: RwLock::new(false),
        }
    }

    async fn init(&self) -> Result<(), String> {
        let mut initialized = self.initialized.write().unwrap();
        *initialized = true;
        Ok(())
    }

    async fn is_initialized(&self) -> bool {
        *self.initialized.read().unwrap()
    }

    async fn enable_ip_forwarding(&self) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut ip_forwarding = self.ip_forwarding.write().unwrap();
        *ip_forwarding = true;
        Ok(())
    }

    async fn disable_ip_forwarding(&self) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut ip_forwarding = self.ip_forwarding.write().unwrap();
        *ip_forwarding = false;
        Ok(())
    }

    async fn is_ip_forwarding_enabled(&self) -> bool {
        *self.ip_forwarding.read().unwrap()
    }

    async fn enable_masquerade(&self, _interface: &str) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut masquerade = self.masquerade.write().unwrap();
        *masquerade = true;
        Ok(())
    }

    async fn disable_masquerade(&self, _interface: &str) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut masquerade = self.masquerade.write().unwrap();
        *masquerade = false;
        Ok(())
    }

    async fn is_masquerade_enabled(&self) -> bool {
        *self.masquerade.read().unwrap()
    }

    async fn add_rule(&self, rule: NatRule) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut rules = self.rules.write().unwrap();
        rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut rules = self.rules.write().unwrap();
        if !rules.contains_key(rule_id) {
            return Err(format!("Rule not found: {}", rule_id));
        }

        rules.remove(rule_id);
        Ok(())
    }

    async fn get_rules(&self) -> Result<Vec<NatRule>, String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let rules = self.rules.read().unwrap();
        Ok(rules.values().cloned().collect())
    }

    async fn add_port_mapping(&self, mapping: PortMapping) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut port_mappings = self.port_mappings.write().unwrap();
        port_mappings.insert(mapping.id.clone(), mapping);
        Ok(())
    }

    async fn remove_port_mapping(&self, mapping_id: &str) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let mut port_mappings = self.port_mappings.write().unwrap();
        if !port_mappings.contains_key(mapping_id) {
            return Err(format!("Port mapping not found: {}", mapping_id));
        }

        port_mappings.remove(mapping_id);
        Ok(())
    }

    async fn get_port_mappings(&self) -> Result<Vec<PortMapping>, String> {
        if !self.is_initialized().await {
            return Err("NAT not initialized".to_string());
        }

        let port_mappings = self.port_mappings.read().unwrap();
        Ok(port_mappings.values().cloned().collect())
    }
}

#[tokio::test]
async fn test_nat_initialization() {
    // Create mock backend
    let backend = Arc::new(MockNatBackend::new());
    
    // Create NAT config
    let config = NatConfig {
        enable_ip_forwarding: true,
        enable_masquerade: true,
        external_interface: Some("eth0".to_string()),
        port_range_start: 32768,
        port_range_end: 60999,
    };
    
    // Create NAT manager
    let nat_manager = NatManager::new(config, backend.clone());
    
    // Initialize NAT
    nat_manager.init().await.expect("Failed to initialize NAT");
    
    // Verify NAT was initialized
    assert!(backend.is_initialized().await);
    assert!(backend.is_ip_forwarding_enabled().await);
    assert!(backend.is_masquerade_enabled().await);
}

#[tokio::test]
async fn test_add_source_nat_rule() {
    // Create mock backend
    let backend = Arc::new(MockNatBackend::new());
    
    // Create NAT config
    let config = NatConfig {
        enable_ip_forwarding: true,
        enable_masquerade: true,
        external_interface: Some("eth0".to_string()),
        port_range_start: 32768,
        port_range_end: 60999,
    };
    
    // Create NAT manager
    let nat_manager = NatManager::new(config, backend.clone());
    
    // Initialize NAT
    nat_manager.init().await.expect("Failed to initialize NAT");
    
    // Create a test rule
    let rule = NatRule {
        id: Uuid::new_v4().to_string(),
        nat_type: NatType::Source,
        source_ip: "172.18.0.0/16".to_string(),
        translated_ip: "192.168.1.100".to_string(),
        protocol: Protocol::Tcp,
        source_port: None,
        destination_port: None,
        translated_port: None,
        external_interface: Some("eth0".to_string()),
        description: Some("Test SNAT rule".to_string()),
        created_at: Utc::now(),
    };
    
    // Add rule
    nat_manager.add_rule(rule.clone()).await.expect("Failed to add rule");
    
    // Verify rule was added
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, rule.id);
    assert_eq!(rules[0].nat_type, NatType::Source);
    assert_eq!(rules[0].source_ip, "172.18.0.0/16");
    assert_eq!(rules[0].translated_ip, "192.168.1.100");
}

#[tokio::test]
async fn test_add_destination_nat_rule() {
    // Create mock backend
    let backend = Arc::new(MockNatBackend::new());
    
    // Create NAT config
    let config = NatConfig {
        enable_ip_forwarding: true,
        enable_masquerade: true,
        external_interface: Some("eth0".to_string()),
        port_range_start: 32768,
        port_range_end: 60999,
    };
    
    // Create NAT manager
    let nat_manager = NatManager::new(config, backend.clone());
    
    // Initialize NAT
    nat_manager.init().await.expect("Failed to initialize NAT");
    
    // Create a test rule
    let rule = NatRule {
        id: Uuid::new_v4().to_string(),
        nat_type: NatType::Destination,
        source_ip: "0.0.0.0/0".to_string(),
        translated_ip: "172.18.0.10".to_string(),
        protocol: Protocol::Tcp,
        source_port: None,
        destination_port: Some(80),
        translated_port: Some(8080),
        external_interface: Some("eth0".to_string()),
        description: Some("Test DNAT rule".to_string()),
        created_at: Utc::now(),
    };
    
    // Add rule
    nat_manager.add_rule(rule.clone()).await.expect("Failed to add rule");
    
    // Verify rule was added
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, rule.id);
    assert_eq!(rules[0].nat_type, NatType::Destination);
    assert_eq!(rules[0].destination_port, Some(80));
    assert_eq!(rules[0].translated_port, Some(8080));
}

#[tokio::test]
async fn test_remove_rule() {
    // Create mock backend
    let backend = Arc::new(MockNatBackend::new());
    
    // Create NAT config
    let config = NatConfig {
        enable_ip_forwarding: true,
        enable_masquerade: true,
        external_interface: Some("eth0".to_string()),
        port_range_start: 32768,
        port_range_end: 60999,
    };
    
    // Create NAT manager
    let nat_manager = NatManager::new(config, backend.clone());
    
    // Initialize NAT
    nat_manager.init().await.expect("Failed to initialize NAT");
    
    // Create a test rule
    let rule = NatRule {
        id: Uuid::new_v4().to_string(),
        nat_type: NatType::Source,
        source_ip: "172.18.0.0/16".to_string(),
        translated_ip: "192.168.1.100".to_string(),
        protocol: Protocol::Tcp,
        source_port: None,
        destination_port: None,
        translated_port: None,
        external_interface: Some("eth0".to_string()),
        description: Some("Test SNAT rule".to_string()),
        created_at: Utc::now(),
    };
    
    // Add rule
    nat_manager.add_rule(rule.clone()).await.expect("Failed to add rule");
    
    // Verify rule was added
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 1);
    
    // Remove rule
    nat_manager.remove_rule(&rule.id).await.expect("Failed to remove rule");
    
    // Verify rule was removed
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_port_mapping() {
    // Create mock backend
    let backend = Arc::new(MockNatBackend::new());
    
    // Create NAT config
    let config = NatConfig {
        enable_ip_forwarding: true,
        enable_masquerade: true,
        external_interface: Some("eth0".to_string()),
        port_range_start: 32768,
        port_range_end: 60999,
    };
    
    // Create NAT manager
    let nat_manager = NatManager::new(config, backend.clone());
    
    // Initialize NAT
    nat_manager.init().await.expect("Failed to initialize NAT");
    
    // Create a test network
    let network = VirtualNetwork {
        id: "net-test".to_string(),
        name: "test-network".to_string(),
        cidr: "172.18.0.0/16".to_string(),
        gateway: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
        // Add other required fields
        created_at: Utc::now(),
    };
    
    // Create a test port mapping
    let mapping = PortMapping {
        id: Uuid::new_v4().to_string(),
        container_id: "container1".to_string(),
        network_id: network.id.clone(),
        protocol: Protocol::Tcp,
        host_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        host_port: 8080,
        container_ip: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 10)),
        container_port: 80,
        description: Some("Web server port mapping".to_string()),
        created_at: Utc::now(),
    };
    
    // Add port mapping
    nat_manager.add_port_mapping(mapping.clone()).await.expect("Failed to add port mapping");
    
    // Verify port mapping was added
    let mappings = backend.get_port_mappings().await.expect("Failed to get port mappings");
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].id, mapping.id);
    assert_eq!(mappings[0].host_port, 8080);
    assert_eq!(mappings[0].container_port, 80);
    
    // Verify NAT rule was created
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].nat_type, NatType::Destination);
    assert_eq!(rules[0].destination_port, Some(8080));
    assert_eq!(rules[0].translated_port, Some(80));
    
    // Remove port mapping
    nat_manager.remove_port_mapping(&mapping.id).await.expect("Failed to remove port mapping");
    
    // Verify port mapping was removed
    let mappings = backend.get_port_mappings().await.expect("Failed to get port mappings");
    assert_eq!(mappings.len(), 0);
    
    // Verify NAT rule was removed
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_network_nat() {
    // Create mock backend
    let backend = Arc::new(MockNatBackend::new());
    
    // Create NAT config
    let config = NatConfig {
        enable_ip_forwarding: true,
        enable_masquerade: true,
        external_interface: Some("eth0".to_string()),
        port_range_start: 32768,
        port_range_end: 60999,
    };
    
    // Create NAT manager
    let nat_manager = NatManager::new(config, backend.clone());
    
    // Initialize NAT
    nat_manager.init().await.expect("Failed to initialize NAT");
    
    // Create a test network
    let network = VirtualNetwork {
        id: "net-test".to_string(),
        name: "test-network".to_string(),
        cidr: "172.18.0.0/16".to_string(),
        gateway: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
        // Add other required fields
        created_at: Utc::now(),
    };
    
    // Setup network NAT
    nat_manager.setup_network_nat(&network).await.expect("Failed to setup network NAT");
    
    // Verify NAT rule was created
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert!(!rules.is_empty());
    
    // Verify masquerade rule
    let masquerade_rule = rules.iter().find(|r| r.nat_type == NatType::Masquerade).expect("Masquerade rule not found");
    assert_eq!(masquerade_rule.source_ip, "172.18.0.0/16");
    
    // Cleanup network NAT
    nat_manager.cleanup_network_nat(&network.id).await.expect("Failed to cleanup network NAT");
    
    // Verify rules were removed
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 0);
}