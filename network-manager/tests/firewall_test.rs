use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};

use chrono::Utc;
use uuid::Uuid;

use common::trust::{Action, ZtaPolicyGraph};
use quantum_network_manager::firewall::{FirewallBackend, FirewallConfig, FirewallDefaultPolicy, FirewallManager, FirewallRule};
use quantum_network_manager::model::{Direction, NetworkAddress, PortRange, Protocol, VirtualNetwork};

// Mock implementation for testing
struct MockFirewallBackend {
    rules: RwLock<HashMap<String, FirewallRule>>,
    initialized: RwLock<bool>,
}

impl MockFirewallBackend {
    fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
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

    async fn add_rule(&self, rule: FirewallRule) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("Firewall not initialized".to_string());
        }

        let mut rules = self.rules.write().unwrap();
        rules.insert(rule.id.clone(), rule);
        Ok(())
    }

    async fn remove_rule(&self, rule_id: &str) -> Result<(), String> {
        if !self.is_initialized().await {
            return Err("Firewall not initialized".to_string());
        }

        let mut rules = self.rules.write().unwrap();
        if !rules.contains_key(rule_id) {
            return Err(format!("Rule not found: {}", rule_id));
        }

        rules.remove(rule_id);
        Ok(())
    }

    async fn get_rules(&self) -> Result<Vec<FirewallRule>, String> {
        if !self.is_initialized().await {
            return Err("Firewall not initialized".to_string());
        }

        let rules = self.rules.read().unwrap();
        Ok(rules.values().cloned().collect())
    }

    async fn get_rule(&self, rule_id: &str) -> Result<FirewallRule, String> {
        if !self.is_initialized().await {
            return Err("Firewall not initialized".to_string());
        }

        let rules = self.rules.read().unwrap();
        rules
            .get(rule_id)
            .cloned()
            .ok_or_else(|| format!("Rule not found: {}", rule_id))
    }
}

#[tokio::test]
async fn test_firewall_initialization() {
    // Create mock backend
    let backend = Arc::new(MockFirewallBackend::new());
    
    // Create ZTA policy graph
    let zta_policy = Arc::new(RwLock::new(ZtaPolicyGraph::new()));
    
    // Create firewall config
    let config = FirewallConfig {
        backend: FirewallBackend::NfTables,
        default_policy: FirewallDefaultPolicy::Deny,
        enable_conntrack: true,
        enable_logging: true,
    };
    
    // Create firewall manager
    let firewall_manager = FirewallManager::new(config, zta_policy, backend.clone());
    
    // Initialize firewall
    firewall_manager.init().await.expect("Failed to initialize firewall");
    
    // Verify firewall was initialized
    assert!(backend.is_initialized().await);
}

#[tokio::test]
async fn test_add_rule() {
    // Create mock backend
    let backend = Arc::new(MockFirewallBackend::new());
    
    // Create ZTA policy graph
    let zta_policy = Arc::new(RwLock::new(ZtaPolicyGraph::new()));
    
    // Create firewall config
    let config = FirewallConfig {
        backend: FirewallBackend::NfTables,
        default_policy: FirewallDefaultPolicy::Deny,
        enable_conntrack: true,
        enable_logging: true,
    };
    
    // Create firewall manager
    let firewall_manager = FirewallManager::new(config, zta_policy, backend.clone());
    
    // Initialize firewall
    firewall_manager.init().await.expect("Failed to initialize firewall");
    
    // Create a test rule
    let rule = FirewallRule {
        id: Uuid::new_v4().to_string(),
        network_id: "net-test".to_string(),
        priority: 100,
        direction: Direction::Ingress,
        protocol: Protocol::Tcp,
        source: NetworkAddress::Cidr("0.0.0.0/0".to_string()),
        destination: NetworkAddress::Cidr("172.18.0.0/16".to_string()),
        source_port_range: PortRange::Any,
        destination_port_range: PortRange::Single(80),
        action: Action::Allow,
        description: Some("Allow HTTP traffic".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    // Add rule
    firewall_manager.add_rule(rule.clone()).await.expect("Failed to add rule");
    
    // Verify rule was added
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, rule.id);
    assert_eq!(rules[0].protocol, Protocol::Tcp);
    assert_eq!(rules[0].destination_port_range, PortRange::Single(80));
}

#[tokio::test]
async fn test_remove_rule() {
    // Create mock backend
    let backend = Arc::new(MockFirewallBackend::new());
    
    // Create ZTA policy graph
    let zta_policy = Arc::new(RwLock::new(ZtaPolicyGraph::new()));
    
    // Create firewall config
    let config = FirewallConfig {
        backend: FirewallBackend::NfTables,
        default_policy: FirewallDefaultPolicy::Deny,
        enable_conntrack: true,
        enable_logging: true,
    };
    
    // Create firewall manager
    let firewall_manager = FirewallManager::new(config, zta_policy, backend.clone());
    
    // Initialize firewall
    firewall_manager.init().await.expect("Failed to initialize firewall");
    
    // Create a test rule
    let rule = FirewallRule {
        id: Uuid::new_v4().to_string(),
        network_id: "net-test".to_string(),
        priority: 100,
        direction: Direction::Ingress,
        protocol: Protocol::Tcp,
        source: NetworkAddress::Cidr("0.0.0.0/0".to_string()),
        destination: NetworkAddress::Cidr("172.18.0.0/16".to_string()),
        source_port_range: PortRange::Any,
        destination_port_range: PortRange::Single(80),
        action: Action::Allow,
        description: Some("Allow HTTP traffic".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    // Add rule
    firewall_manager.add_rule(rule.clone()).await.expect("Failed to add rule");
    
    // Verify rule was added
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 1);
    
    // Remove rule
    firewall_manager.remove_rule(&rule.id).await.expect("Failed to remove rule");
    
    // Verify rule was removed
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(rules.len(), 0);
}

#[tokio::test]
async fn test_network_isolation() {
    // Create mock backend
    let backend = Arc::new(MockFirewallBackend::new());
    
    // Create ZTA policy graph
    let zta_policy = Arc::new(RwLock::new(ZtaPolicyGraph::new()));
    
    // Create firewall config
    let config = FirewallConfig {
        backend: FirewallBackend::NfTables,
        default_policy: FirewallDefaultPolicy::Deny,
        enable_conntrack: true,
        enable_logging: true,
    };
    
    // Create firewall manager
    let firewall_manager = FirewallManager::new(config, zta_policy, backend.clone());
    
    // Initialize firewall
    firewall_manager.init().await.expect("Failed to initialize firewall");
    
    // Create a test network
    let network = VirtualNetwork {
        id: "net-test".to_string(),
        name: "test-network".to_string(),
        cidr: "172.18.0.0/16".to_string(),
        gateway: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
        driver: NetworkDriverType::Bridge,
        isolation_mode: IsolationMode::Full,
        options: HashMap::new(),
        labels: HashMap::new(),
        created_at: Utc::now(),
    };
    
    // Setup network isolation
    firewall_manager.setup_network_isolation(&network).await.expect("Failed to setup network isolation");
    
    // Verify isolation rules were created
    let rules = backend.get_rules().await.expect("Failed to get rules");
    assert!(!rules.is_empty());
    
    // Verify isolation type
    let isolation_rules = rules.iter().filter(|r| r.network_id == network.id).collect::<Vec<_>>();
    assert!(!isolation_rules.is_empty());
    
    // Full isolation should block external traffic
    let has_deny_external = isolation_rules.iter().any(|r| {
        r.action == Action::Deny && r.direction == Direction::Ingress && 
        matches!(r.source, NetworkAddress::Cidr(ref cidr) if cidr != &network.cidr)
    });
    
    assert!(has_deny_external);
}

#[tokio::test]
async fn test_security_group() {
    // Create mock backend
    let backend = Arc::new(MockFirewallBackend::new());
    
    // Create ZTA policy graph
    let zta_policy = Arc::new(RwLock::new(ZtaPolicyGraph::new()));
    
    // Create firewall config
    let config = FirewallConfig {
        backend: FirewallBackend::NfTables,
        default_policy: FirewallDefaultPolicy::Deny,
        enable_conntrack: true,
        enable_logging: true,
    };
    
    // Create firewall manager
    let firewall_manager = FirewallManager::new(config, zta_policy, backend.clone());
    
    // Initialize firewall
    firewall_manager.init().await.expect("Failed to initialize firewall");
    
    // Create a security group
    let group_id = "sg-web";
    let network_id = "net-test";
    
    // Create security group rules
    let rules = vec![
        FirewallRule {
            id: Uuid::new_v4().to_string(),
            network_id: network_id.to_string(),
            priority: 100,
            direction: Direction::Ingress,
            protocol: Protocol::Tcp,
            source: NetworkAddress::Cidr("0.0.0.0/0".to_string()),
            destination: NetworkAddress::SecurityGroup(group_id.to_string()),
            source_port_range: PortRange::Any,
            destination_port_range: PortRange::Single(80),
            action: Action::Allow,
            description: Some("Allow HTTP traffic".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        FirewallRule {
            id: Uuid::new_v4().to_string(),
            network_id: network_id.to_string(),
            priority: 101,
            direction: Direction::Ingress,
            protocol: Protocol::Tcp,
            source: NetworkAddress::Cidr("0.0.0.0/0".to_string()),
            destination: NetworkAddress::SecurityGroup(group_id.to_string()),
            source_port_range: PortRange::Any,
            destination_port_range: PortRange::Single(443),
            action: Action::Allow,
            description: Some("Allow HTTPS traffic".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];
    
    // Create security group
    firewall_manager.create_security_group(group_id, network_id, rules.clone())
        .await
        .expect("Failed to create security group");
    
    // Verify security group rules were created
    let backend_rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(backend_rules.len(), rules.len());
    
    // Verify rule properties
    let http_rule = backend_rules.iter().find(|r| {
        matches!(r.destination_port_range, PortRange::Single(80))
    }).expect("HTTP rule not found");
    
    let https_rule = backend_rules.iter().find(|r| {
        matches!(r.destination_port_range, PortRange::Single(443))
    }).expect("HTTPS rule not found");
    
    assert_eq!(http_rule.action, Action::Allow);
    assert_eq!(https_rule.action, Action::Allow);
    
    // Delete security group
    firewall_manager.delete_security_group(group_id, network_id)
        .await
        .expect("Failed to delete security group");
    
    // Verify rules were removed
    let backend_rules = backend.get_rules().await.expect("Failed to get rules");
    assert_eq!(backend_rules.len(), 0);
}