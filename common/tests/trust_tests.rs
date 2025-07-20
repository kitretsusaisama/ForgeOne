//! # Trust Tests
//! //common\tests\trust_tests.rs
//! This module contains tests for the ZtaNode and ZtaPolicyGraph modules, focusing on
//! Zero Trust Architecture policy evaluation and graph traversal.

use std::collections::HashSet;
use common::trust::{ZtaNode, ZtaPolicyGraph, verify_trust_vector};
use common::identity::{IdentityContext, TrustVector};
use common::trust::Action;
use std::sync::{Arc, RwLock};
use std::thread;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic ZTA node creation
    /// 
    /// This test verifies that basic ZTA nodes can be created.
    #[test]
    fn test_basic_zta_node_creation() {
        // Create a basic ZTA node with trust vector
        let node = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        // Verify the node properties
        assert_eq!(node.id, "resource1");
        assert_eq!(node.trust_vector, TrustVector::Unverified);
        assert!(node.allowed_actions.is_empty());
        assert!(node.denied_actions.is_empty());
    }

    /// Test ZTA node with allowed actions
    /// 
    /// This test verifies that ZTA nodes can be created with allowed actions.
    #[test]
    fn test_zta_node_with_allowed_actions() {
        // Create a ZTA node with allowed actions
        let mut node = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        // Add allowed actions
        node.allowed_actions.insert(Action::Read);
        node.allowed_actions.insert(Action::Write);
        
        // Verify the node properties
        assert_eq!(node.id, "resource1");
        assert_eq!(node.trust_vector, TrustVector::Unverified);
        assert_eq!(node.allowed_actions.len(), 2);
        assert!(node.allowed_actions.contains(&Action::Read));
        assert!(node.allowed_actions.contains(&Action::Write));
        assert!(node.denied_actions.is_empty());
    }

    /// Test ZTA node with denied actions
    /// 
    /// This test verifies that ZTA nodes can be created with denied actions.
    #[test]
    fn test_zta_node_with_denied_actions() {
        // Create ZTA nodes
        let mut node = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        // Add denied actions
        node.denied_actions.insert(Action::Custom("delete".to_string()));
        node.denied_actions.insert(Action::Custom("admin".to_string()));
        
        // Verify the node properties
        assert_eq!(node.id, "resource1");
        assert_eq!(node.trust_vector, TrustVector::Unverified);
        assert!(node.allowed_actions.is_empty());
        assert_eq!(node.denied_actions.len(), 2);
        assert!(node.denied_actions.contains(&Action::Custom("delete".to_string())));
        assert!(node.denied_actions.contains(&Action::Custom("admin".to_string())));
    }

    /// Test ZTA node serialization and deserialization
    /// 
    /// This test verifies that ZTA nodes can be serialized to and deserialized from JSON.
    #[test]
    fn test_zta_node_serialization() {
        // Create a ZTA node with allowed and denied actions
        let mut allowed_actions = HashSet::new();
        allowed_actions.insert(Action::Read);
        allowed_actions.insert(Action::Write);
        
        let mut denied_actions = HashSet::new();
        denied_actions.insert(Action::Custom("delete".to_string()));
        
        let node = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions,
            denied_actions,
        };
        
        // Serialize to JSON
        let json = serde_json::to_string(&node).expect("Failed to serialize ZTA node");
        
        // Deserialize from JSON
        let deserialized: ZtaNode = serde_json::from_str(&json).expect("Failed to deserialize ZTA node");
        
        // Verify the deserialized node
        assert_eq!(deserialized.id, "resource1");
        assert_eq!(deserialized.trust_vector, TrustVector::Unverified);
        assert_eq!(deserialized.allowed_actions.len(), 2);
        assert!(deserialized.allowed_actions.contains(&Action::Read));
        assert!(deserialized.allowed_actions.contains(&Action::Write));
        assert_eq!(deserialized.denied_actions.len(), 1);
        assert!(deserialized.denied_actions.contains(&Action::Custom("delete".to_string())));
    }

    /// Test basic ZTA policy graph creation
    /// 
    /// This test verifies that basic ZTA policy graphs can be created.
    #[test]
    fn test_basic_zta_policy_graph_creation() {
        // Create a basic ZTA policy graph
        let graph = ZtaPolicyGraph::new();
        
        // Verify the graph properties
        assert!(graph.nodes.is_empty());
    }

    /// Test ZTA policy graph with nodes
    /// 
    /// This test verifies that ZTA policy graphs can be created with nodes.
    #[test]
    fn test_zta_policy_graph_with_nodes() {
        // Create ZTA nodes
        let node1 = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        let node2 = ZtaNode {
            id: "resource2".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        let node3 = ZtaNode {
            id: "resource3".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        // Create a ZTA policy graph
        let mut graph = ZtaPolicyGraph::new();
        
        // Add nodes
        graph.add_node(node1.clone());
        graph.add_node(node2.clone());
        graph.add_node(node3.clone());
        
        // Verify the graph properties
        assert_eq!(graph.nodes.len(), 3);
        assert!(graph.nodes.contains_key(&node1.id));
        assert!(graph.nodes.contains_key(&node2.id));
        assert!(graph.nodes.contains_key(&node3.id));
    }

    /// Test ZTA policy graph with edges
    /// 
    /// This test verifies that ZTA policy graphs can be created with edges between nodes.
    #[test]
    fn test_zta_policy_graph_with_edges() {
        // Create ZTA nodes
        let node1 = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        let node2 = ZtaNode {
            id: "resource2".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        let node3 = ZtaNode {
            id: "resource3".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        // Create a ZTA policy graph
        let mut graph = ZtaPolicyGraph::new();
        
        // Add nodes
        graph.add_node(node1.clone());
        graph.add_node(node2.clone());
        graph.add_node(node3.clone());
        
        // Add edges with allowed actions
        let read_actions = HashSet::from([Action::Read]);
        let write_actions = HashSet::from([Action::Write]);
        
        graph.add_edge(&node1.id, &node2.id, read_actions);
        graph.add_edge(&node1.id, &node3.id, write_actions);

        
        // Verify the graph properties
        assert_eq!(graph.nodes.len(), 3);
        assert!(graph.nodes.contains_key(&node1.id));
        assert!(graph.nodes.contains_key(&node2.id));
        assert!(graph.nodes.contains_key(&node3.id));
        
        // Verify the edges
        assert_eq!(graph.edges.len(), 3); // node1->node2, node1->node3, node2->node1 (bidirectional)
        
        // Check edges
        let edges_from_node1 = graph.edges.get(&node1.id).unwrap();
        
        // Check edge from node1 to node2
        let actions_to_node2 = edges_from_node1.get(&node2.id).unwrap();
        assert!(actions_to_node2.contains(&Action::Read));
        
        // Check edge from node1 to node3
        let actions_to_node3 = edges_from_node1.get(&node3.id).unwrap();
        assert!(actions_to_node3.contains(&Action::Write));
        
        // Check bidirectional edge from node2 to node1
        let edges_from_node2 = graph.edges.get(&node2.id).unwrap();
        let actions_to_node1 = edges_from_node2.get(&node1.id).unwrap();
        assert!(actions_to_node1.contains(&Action::Read));
    }

    /// Test ZTA policy graph serialization and deserialization
    /// 
    /// This test verifies that ZTA policy graphs can be serialized to and deserialized from JSON.
    #[test]
    fn test_zta_policy_graph_serialization() {
        // Create ZTA nodes with trust vectors and actions
        let mut allowed_actions1 = HashSet::new();
        allowed_actions1.insert(Action::Read);
        
        let mut denied_actions1 = HashSet::new();
        denied_actions1.insert(Action::Custom("delete".to_string()));
        
        let node1 = ZtaNode {
            id: "resource1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: allowed_actions1,
            denied_actions: denied_actions1,
        };
        
        let mut allowed_actions2 = HashSet::new();
        allowed_actions2.insert(Action::Write);
        
        let node2 = ZtaNode {
            id: "resource2".to_string(),
            trust_vector: TrustVector::Signed("signature".to_string()),
            allowed_actions: allowed_actions2,
            denied_actions: HashSet::new(),
        };
        
        let node3 = ZtaNode {
            id: "resource3".to_string(),
            trust_vector: TrustVector::Enclave,
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
        };
        
        // Create a ZTA policy graph
        let mut graph = ZtaPolicyGraph::new();
        
        // Add nodes
        graph.add_node(node1.clone());
        graph.add_node(node2.clone());
        graph.add_node(node3.clone());
        
        // Add edges with allowed actions
        let read_actions = HashSet::from([Action::Read]);
        let write_actions = HashSet::from([Action::Write]);
        
        graph.add_edge(&node1.id, &node2.id, read_actions);
        graph.add_edge(&node1.id, &node3.id, write_actions);
        
        // Serialize to JSON
        let json = serde_json::to_string(&graph).expect("Failed to serialize ZTA policy graph");
        
        // Deserialize from JSON
        let deserialized: ZtaPolicyGraph = serde_json::from_str(&json).expect("Failed to deserialize ZTA policy graph");
        
        // Verify the deserialized graph
        assert_eq!(deserialized.nodes.len(), 3);
        assert!(deserialized.nodes.contains_key(&node1.id));
        assert!(deserialized.nodes.contains_key(&node2.id));
        assert!(deserialized.nodes.contains_key(&node3.id));
        
        // Verify the edges
        assert_eq!(deserialized.edges.len(), 3);
        
        // Check edges
        let edges_from_node1 = deserialized.edges.get(&node1.id).unwrap();
        
        // Check edge from node1 to node2
        let actions_to_node2 = edges_from_node1.get(&node2.id).unwrap();
        assert!(actions_to_node2.contains(&Action::Read));
        
        // Check second edge
        // Check edge from node1 to node3 using HashMap access
        let edges_from_node1 = deserialized.edges.get(&node1.id).unwrap();
        let actions_to_node3 = edges_from_node1.get(&node3.id).unwrap();
        assert!(actions_to_node3.contains(&Action::Write));
        
        // Check bidirectional edge from node2 to node1
        let edges_from_node2 = deserialized.edges.get(&node2.id).unwrap();
        let actions_to_node1 = edges_from_node2.get(&node1.id).unwrap();
        assert!(actions_to_node1.contains(&Action::Read));
        
        // Verify node properties
        let deserialized_node1 = deserialized.nodes.get(&node1.id).unwrap();
        assert_eq!(deserialized_node1.trust_vector, TrustVector::Unverified);
        assert!(deserialized_node1.allowed_actions.contains(&Action::Read));
        assert!(deserialized_node1.denied_actions.contains(&Action::Custom("delete".to_string())));
        
        let deserialized_node2 = deserialized.nodes.get(&node2.id).unwrap();
        if let TrustVector::Signed(signature) = &deserialized_node2.trust_vector {
            assert_eq!(signature, "signature");
        } else {
            panic!("Expected Signed trust vector");
        }
        assert!(deserialized_node2.allowed_actions.contains(&Action::Write));
    }

    /// Test ZTA policy graph evaluation
    /// 
    /// This test verifies that ZTA policy graphs can be used to evaluate access permissions.
    #[test]
    fn test_zta_policy_graph_evaluation() {
        // Create ZTA nodes with different permissions
        let node1 = ZtaNode {
            id: "user1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::from([Action::Read]),
            denied_actions: HashSet::from([Action::Custom("delete".to_string())]),
        };
        
        let node2 = ZtaNode {
            id: "user2".to_string(),
            trust_vector: TrustVector::Signed("signature".to_string()),
            allowed_actions: HashSet::from([Action::Write]),
            denied_actions: HashSet::new(),
        };
        
        // Create a ZTA policy graph
        let mut graph = ZtaPolicyGraph::new();
        
        // Add nodes
        graph.add_node(node1.clone());
        graph.add_node(node2.clone());
        
        // Add edges with allowed actions
        graph.add_edge(&node1.id, &node2.id, HashSet::from([Action::Execute]));
        
        // Create identity contexts for testing
        let identity1 = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user1".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Unverified,
            cryptographic_attestation: None,
        };
        
        let identity2 = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user2".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Signed("signature".to_string()),
            cryptographic_attestation: None,
        };
        
        let root_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "system".to_string(),
            user_id: "root".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Root,
            cryptographic_attestation: None,
        };
        
        // Test evaluation for explicitly allowed actions
        assert!(graph.evaluate(&identity1, "read", &[]));
        assert!(!graph.evaluate(&identity1, "delete", &[]));
        assert!(graph.evaluate(&identity2, "write", &[]));
        
        // Test evaluation for actions allowed via edges
        assert!(graph.evaluate(&identity1, "execute", &[]));
        
        // Test evaluation for root identity (always allowed)
        assert!(graph.evaluate(&root_identity, "any_action", &[]));
        
        // Test evaluation for non-existent user
        let non_existent_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "non_existent".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Unverified,
            cryptographic_attestation: None,
        };
        
        assert!(!graph.evaluate(&non_existent_identity, "read", &[]));

    }

    /// Test ZTA policy graph with trust vector verification
    /// 
    /// This test verifies that trust vectors can be verified correctly.
    #[test]
    fn test_trust_vector_verification() {
        // Create identity contexts with different trust vectors
        let root_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "system".to_string(),
            user_id: "root".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Root,
            cryptographic_attestation: None,
        };
        
        let signed_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user1".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Signed("valid_signature".to_string()),
            cryptographic_attestation: None,
        };
        
        let invalid_signed_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user2".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Signed("".to_string()),
            cryptographic_attestation: None,
        };
        
        let enclave_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user3".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Enclave,
            cryptographic_attestation: Some("attestation".to_string()),
        };
        
        let invalid_enclave_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user4".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Enclave,
            cryptographic_attestation: None,
        };
        
        let edge_gateway_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user5".to_string(),
            agent_id: None,
            device_fingerprint: Some("fingerprint".to_string()),
            geo_ip: None,
            trust_vector: TrustVector::EdgeGateway,
            cryptographic_attestation: None,
        };
        
        let invalid_edge_gateway_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user6".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::EdgeGateway,
            cryptographic_attestation: None,
        };
        
        let unverified_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user7".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Unverified,
            cryptographic_attestation: None,
        };
        
        let compromised_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "user8".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Compromised,
            cryptographic_attestation: None,
        };
        
        let invalid_root_identity = IdentityContext {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tenant_id: "tenant1".to_string(),
            user_id: "root".to_string(),
            agent_id: None,
            device_fingerprint: None,
            geo_ip: None,
            trust_vector: TrustVector::Root,
            cryptographic_attestation: None,
        };
        
        // Verify trust vectors
        assert!(verify_trust_vector(&root_identity));
        assert!(verify_trust_vector(&signed_identity));
        assert!(!verify_trust_vector(&invalid_signed_identity));
        assert!(verify_trust_vector(&enclave_identity));
        assert!(!verify_trust_vector(&invalid_enclave_identity));
        assert!(verify_trust_vector(&edge_gateway_identity));
        assert!(!verify_trust_vector(&invalid_edge_gateway_identity));
        assert!(verify_trust_vector(&unverified_identity));
        assert!(!verify_trust_vector(&compromised_identity));
        assert!(!verify_trust_vector(&invalid_root_identity));
    }

    /// Test ZTA policy graph with concurrent access
    /// 
    /// This test verifies that ZTA policy graphs can be accessed concurrently.
    #[test]
    fn test_zta_policy_graph_with_concurrent_access() {
        // Create ZTA nodes
        let node1 = ZtaNode {
            id: "user1".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::from([Action::Read]),
            denied_actions: HashSet::new(),
        };
        
        let node2 = ZtaNode {
            id: "user2".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::from([Action::Read]),
            denied_actions: HashSet::new(),
        };
        
        let node3 = ZtaNode {
            id: "user3".to_string(),
            trust_vector: TrustVector::Unverified,
            allowed_actions: HashSet::from([Action::Read]),
            denied_actions: HashSet::new(),
        };
        
        // Create a ZTA policy graph
        let mut graph = ZtaPolicyGraph::new();
        
        // Add nodes
        graph.add_node(node1.clone());
        graph.add_node(node2.clone());
        graph.add_node(node3.clone());
        
        let connect_actions = HashSet::from([Action::Connect]);
        graph.add_edge(&node1.id, &node2.id, connect_actions.clone());
        graph.add_edge(&node1.id, &node3.id, connect_actions.clone());
        graph.add_edge(&node2.id, &node3.id, connect_actions);
        
        // Create a shared graph
        let shared_graph = Arc::new(RwLock::new(graph));

        
        // Create a vector to hold thread handles
        let mut handles = vec![];
        
        // Spawn 10 threads to access the graph
        for i in 0..10 {
            let graph_clone = Arc::clone(&shared_graph);
            
            let handle = thread::spawn(move || {
                // Lock the graph and create identity
                let graph = graph_clone.read().unwrap();
                let identity = IdentityContext {
                    request_id: Uuid::new_v4(),
                    session_id: Uuid::new_v4(),
                    tenant_id: "tenant1".to_string(),
                    user_id: format!("user{}", (i % 3) + 1),
                    agent_id: None,
                    device_fingerprint: None,
                    geo_ip: None,
                    trust_vector: TrustVector::Unverified,
                    cryptographic_attestation: None,
                };
                
                // Evaluate access
                let can_read = graph.evaluate(&identity, "read", &[]);
                let can_connect = graph.evaluate(&identity, "connect", &[]);
                
                // Return results
                (can_read, can_connect)
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        for handle in handles {
            let (can_read, can_connect) = handle.join().unwrap();
            
            // Verify that users can read and connect
            assert!(can_read);
            assert!(can_connect);
        }
    }
}