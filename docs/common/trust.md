# Trust Engine

*This document is production-ready, MNC-grade, and compliance-focused. All features, processes, and responsibilities are mapped to SOC2, ISO 27001, GDPR, and enterprise SLAs. Security, audit, and evidence generation are integral to every step.*

---

## Overview
The Trust module provides a Zero Trust Policy and graph engine for the ForgeOne platform. It implements a comprehensive trust model for secure operations, with all actions and policy decisions logged and exportable for audit and compliance.

## Key Features
- Zero Trust Architecture (ZTA) implementation
- Trust graph for policy decisions
- Action-based permission model
- Identity context integration
- Trust vector evaluation
- **Auditability:** All trust evaluations, policy changes, and access decisions are logged and exportable

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
- **Auditability:** All evaluation steps and decisions are logged for compliance

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

## Operational & Compliance Guarantees
- **All trust evaluations, policy changes, and access decisions are logged, versioned, and exportable for audit and regulatory review.**
- **Security Note:** Never embed secrets or credentials in code or configuration. Use environment variables and secure storage only.
- **Error Handling:** All API calls and module functions return detailed error types. All errors are logged and can be exported for audit.
- **Integration:** The trust module exposes a stable ABI and API for integration with external systems, plugins, and observability tools.
- **Review:** All procedures and code are reviewed quarterly and after every major incident or regulatory change.

## Troubleshooting
- **Policy Evaluation Failure:** Ensure the policy graph is valid and up-to-date. Check logs for error details.
- **Access Denied:** Validate trust vector and node/edge permissions. All denials are logged with full context.
- **Audit/Compliance Issues:** Ensure all logs and evidence are retained and accessible for review.

## Related Modules
- [Identity](./identity.md)
- [Policy](./policy.md)
- [Audit](./audit.md)

---

*This document is reviewed quarterly and after every major incident or regulatory change. For questions, contact the ForgeOne compliance or platform engineering team.*