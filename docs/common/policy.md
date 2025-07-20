# Policy Engine

## Overview
The Policy module provides a DSL and runtime policy matcher for the ForgeOne platform. It handles role-based access control and policy evaluation, ensuring that actions are only performed by authorized identities.

## Key Features
- Role-based access control
- Policy evaluation engine
- Fine-grained resource permissions
- Trust vector integration
- Policy sets for organization

## Core Components

### PolicyEffect
Policy effect representing the result of a policy evaluation:
- `Allow` - Allow the action
- `Deny` - Deny the action
- `EscalateTo(String)` - Escalate to another role

### PolicyRule
Policy rule representing a single policy:
- `role` - The role this policy applies to
- `action` - The action this policy applies to
- `resource` - The resource this policy applies to
- `effect` - The effect of this policy

### PolicySet
Policy set representing a collection of policies:
- `name` - The name of this policy set
- `version` - The version of this policy set
- `rules` - The rules in this policy set

## Helper Methods
- `new()` - Create a new policy set
- `add_rule()` - Add a rule to this policy set
- `remove_rule()` - Remove a rule from this policy set
- `evaluate()` - Evaluate a policy for a given identity and action

## Policy Evaluation Logic
1. Root trust vector always has access
2. Compromised trust vector never has access
3. Match rules based on role, action, and resource
4. Default to deny if no matching rules

## Usage Example
```rust
// Create a new policy set
let mut policy_set = PolicySet::new(
    "default".to_string(),
    "1.0".to_string()
);

// Add a rule
policy_set.add_rule(PolicyRule {
    role: "admin".to_string(),
    action: "read".to_string(),
    resource: "*".to_string(),
    effect: PolicyEffect::Allow,
});

// Evaluate a policy
let identity = IdentityContext::new("tenant1".to_string(), "admin".to_string());
let effect = policy_set.evaluate(&identity, "read", "document1");

match effect {
    PolicyEffect::Allow => println!("Access allowed"),
    PolicyEffect::Deny => println!("Access denied"),
    PolicyEffect::EscalateTo(role) => println!("Escalate to role: {}", role),
}
```

## Related Modules
- [Identity](./identity.md)
- [Trust](./trust.md)
- [Audit](./audit.md)