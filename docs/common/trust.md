# Trust Engine

## Overview
The Trust module provides a Zero Trust Policy and graph engine for the ForgeOne platform. It implements a comprehensive trust model for secure operations.

## Key Features
- Zero Trust Architecture (ZTA) implementation
- Trust graph for policy decisions
- Action-based permission model
- Identity context integration
- Trust vector evaluation

## Core Components

### Action
Actions allowed in the system:
- `Read` - Read access
- `Write` - Write access
- `Connect` - Connection access
- `Execute` - Execution access
- `Custom(String)` - Custom action

### ZtaNode
A node in the Zero Trust Policy graph:
- `id` - Node identifier
- `trust_vector` - Trust vector for this node
- `allowed_actions` - Actions allowed for this node
- `denied_actions` - Actions denied for this node

### ZtaPolicyGraph
A Zero Trust Policy graph:
- `nodes` - Map of node IDs to nodes
- `edges` - Map of from node to to node to actions
- `bidirectional` - Whether edges are bidirectional

## Helper Methods
- `new()` - Create a new graph
- `add_node()` - Add a node to the graph
- `add_edge()` - Add an edge between two nodes
- `evaluate()` - Evaluate if an action is allowed

## Trust Evaluation Logic
1. System root access is always allowed
2. Compromised entities are always blocked
3. User must exist in the graph
4. Check node permissions and edge permissions

## Usage Example
```rust
// Create a new ZTA policy graph
let mut graph = ZtaPolicyGraph::new();

// Add nodes
graph.add_node(ZtaNode {
    id: "user1".to_string(),
    trust_vector: TrustVector::Signed("signature1".to_string()),
    allowed_actions: [Action::Read].iter().cloned().collect(),
    denied_actions: HashSet::new(),
});

graph.add_node(ZtaNode {
    id: "resource1".to_string(),
    trust_vector: TrustVector::Root,
    allowed_actions: HashSet::new(),
    denied_actions: HashSet::new(),
});

// Add edge
graph.add_edge(
    "user1",
    "resource1",
    [Action::Read].iter().cloned().collect()
);

// Evaluate action
let identity = IdentityContext::new("tenant1".to_string(), "user1".to_string());
let allowed = graph.evaluate(&identity, "read", &["resource1"]);
```

## Related Modules
- [Identity](./identity.md)
- [Policy](./policy.md)
- [Audit](./audit.md)