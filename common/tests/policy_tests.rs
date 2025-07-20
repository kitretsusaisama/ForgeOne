#[cfg(test)]
mod tests {
    use common::identity::{IdentityContext, TrustVector};
    use common::policy::{PolicyEffect, PolicyRule, PolicySet, evaluate_policy};

    // Helper function to create test identity
    fn create_identity(user_id: &str, trust_vector: TrustVector) -> IdentityContext {
        let mut identity = IdentityContext::new("test-tenant".to_string(), user_id.to_string());
        identity.trust_vector = trust_vector;
        identity
    }

    // Helper function to create test policy rule
    fn create_rule(role: &str, action: &str, resource: &str, effect: PolicyEffect) -> PolicyRule {
        PolicyRule {
            role: role.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            effect,
        }
    }

    #[test]
    fn test_policy_effect_serialization() {
        // Test PolicyEffect serialization/deserialization
        let allow = PolicyEffect::Allow;
        let deny = PolicyEffect::Deny;
        let escalate = PolicyEffect::EscalateTo("admin".to_string());

        let allow_json = serde_json::to_string(&allow).unwrap();
        let deny_json = serde_json::to_string(&deny).unwrap();
        let escalate_json = serde_json::to_string(&escalate).unwrap();

        assert_eq!(serde_json::from_str::<PolicyEffect>(&allow_json).unwrap(), allow);
        assert_eq!(serde_json::from_str::<PolicyEffect>(&deny_json).unwrap(), deny);
        assert_eq!(serde_json::from_str::<PolicyEffect>(&escalate_json).unwrap(), escalate);
    }

    #[test]
    fn test_policy_rule_creation() {
        let rule = create_rule("admin", "read", "database", PolicyEffect::Allow);
        
        assert_eq!(rule.role, "admin");
        assert_eq!(rule.action, "read");
        assert_eq!(rule.resource, "database");
        assert_eq!(rule.effect, PolicyEffect::Allow);
    }

    #[test]
    fn test_policy_set_creation() {
        let policy_set = PolicySet::new("test_policy".to_string(), "1.0.0".to_string());
        
        assert_eq!(policy_set.name, "test_policy");
        assert_eq!(policy_set.version, "1.0.0");
        assert!(policy_set.rules.is_empty());
    }

    #[test]
    fn test_policy_set_add_rule() {
        let mut policy_set = PolicySet::new("test_policy".to_string(), "1.0.0".to_string());
        let rule = create_rule("admin", "read", "database", PolicyEffect::Allow);
        
        policy_set.add_rule(rule.clone());
        
        assert_eq!(policy_set.rules.len(), 1);
        assert_eq!(policy_set.rules[0].role, "admin");
    }

    #[test]
    fn test_policy_set_multiple_rules() {
        let mut policy_set = PolicySet::new("test_policy".to_string(), "1.0.0".to_string());
        
        policy_set.add_rule(create_rule("admin", "read", "database", PolicyEffect::Allow));
        policy_set.add_rule(create_rule("user", "read", "public", PolicyEffect::Allow));
        policy_set.add_rule(create_rule("guest", "*", "*", PolicyEffect::Deny));
        
        assert_eq!(policy_set.rules.len(), 3);
    }

    // Root trust vector tests
    #[test]
    fn test_root_trust_vector_always_allows() {
        let policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let root_identity = create_identity("root_user", TrustVector::Root);
        
        // Root should always get Allow, regardless of rules
        assert_eq!(policy_set.evaluate(&root_identity, "any_action", "any_resource"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&root_identity, "delete", "critical_data"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&root_identity, "shutdown", "system"), PolicyEffect::Allow);
    }

    #[test]
    fn test_root_trust_vector_ignores_deny_rules() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let root_identity = create_identity("root_user", TrustVector::Root);
        
        // Add explicit deny rule
        policy_set.add_rule(create_rule("root_user", "delete", "database", PolicyEffect::Deny));
        
        // Root should still get Allow
        assert_eq!(policy_set.evaluate(&root_identity, "delete", "database"), PolicyEffect::Allow);
    }

    // Compromised trust vector tests
    #[test]
    fn test_compromised_trust_vector_always_denies() {
        let policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let compromised_identity = create_identity("compromised_user", TrustVector::Compromised);
        
        // Compromised should always get Deny, regardless of rules
        assert_eq!(policy_set.evaluate(&compromised_identity, "read", "public"), PolicyEffect::Deny);
        assert_eq!(policy_set.evaluate(&compromised_identity, "any_action", "any_resource"), PolicyEffect::Deny);
    }

    #[test]
    fn test_compromised_trust_vector_ignores_allow_rules() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let compromised_identity = create_identity("compromised_user", TrustVector::Compromised);
        
        // Add explicit allow rule
        policy_set.add_rule(create_rule("compromised_user", "read", "public", PolicyEffect::Allow));
        
        // Compromised should still get Deny
        assert_eq!(policy_set.evaluate(&compromised_identity, "read", "public"), PolicyEffect::Deny);
    }

    // Wildcard matching tests
    #[test]
    fn test_wildcard_role_matching() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("any_user", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("*", "read", "public", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "read", "public"), PolicyEffect::Allow);
    }

    #[test]
    fn test_wildcard_action_matching() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("admin", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("admin", "*", "database", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "read", "database"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&identity, "write", "database"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&identity, "delete", "database"), PolicyEffect::Allow);
    }

    #[test]
    fn test_wildcard_resource_matching() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("admin", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("admin", "read", "*", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "read", "database"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&identity, "read", "files"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&identity, "read", "secrets"), PolicyEffect::Allow);
    }

    #[test]
    fn test_all_wildcards() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("any_user", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("*", "*", "*", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "any_action", "any_resource"), PolicyEffect::Allow);
    }

    // Rule precedence and order tests
    #[test]
    fn test_rule_precedence_first_match_wins() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        // First rule should match and return Allow
        policy_set.add_rule(create_rule("user", "read", "file", PolicyEffect::Allow));
        policy_set.add_rule(create_rule("user", "read", "file", PolicyEffect::Deny));
        
        assert_eq!(policy_set.evaluate(&identity, "read", "file"), PolicyEffect::Allow);
    }

    #[test]
    fn test_specific_rule_vs_wildcard_precedence() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("admin", TrustVector::Signed("test".to_string()));
        
        // More specific rule comes first
        policy_set.add_rule(create_rule("admin", "delete", "critical", PolicyEffect::Deny));
        policy_set.add_rule(create_rule("admin", "*", "*", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "delete", "critical"), PolicyEffect::Deny);
        assert_eq!(policy_set.evaluate(&identity, "read", "critical"), PolicyEffect::Allow);
    }

    // Default deny tests
    #[test]
    fn test_default_deny_no_matching_rules() {
        let policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        // No rules, should default to Deny
        assert_eq!(policy_set.evaluate(&identity, "read", "file"), PolicyEffect::Deny);
    }

    #[test]
    fn test_default_deny_no_matching_role() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("admin", "read", "file", PolicyEffect::Allow));
        
        // No matching role, should default to Deny
        assert_eq!(policy_set.evaluate(&identity, "read", "file"), PolicyEffect::Deny);
    }

    #[test]
    fn test_default_deny_no_matching_action() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("user", "read", "file", PolicyEffect::Allow));
        
        // No matching action, should default to Deny
        assert_eq!(policy_set.evaluate(&identity, "write", "file"), PolicyEffect::Deny);
    }

    #[test]
    fn test_default_deny_no_matching_resource() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("user", "read", "file", PolicyEffect::Allow));
        
        // No matching resource, should default to Deny
        assert_eq!(policy_set.evaluate(&identity, "read", "database"), PolicyEffect::Deny);
    }

    // Escalation tests
    #[test]
    fn test_escalation_effect() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("user", "delete", "critical", 
            PolicyEffect::EscalateTo("admin".to_string())));
        
        assert_eq!(policy_set.evaluate(&identity, "delete", "critical"), 
            PolicyEffect::EscalateTo("admin".to_string()));
    }

    #[test]
    fn test_escalation_with_different_roles() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("junior_admin", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("junior_admin", "shutdown", "system", 
            PolicyEffect::EscalateTo("senior_admin".to_string())));
        
        assert_eq!(policy_set.evaluate(&identity, "shutdown", "system"), 
            PolicyEffect::EscalateTo("senior_admin".to_string()));
    }

    // Trust vector edge cases
    #[test]
    fn test_all_trust_vectors() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        policy_set.add_rule(create_rule("user", "read", "file", PolicyEffect::Allow));
        
        // Test each trust vector
        assert_eq!(policy_set.evaluate(&create_identity("user", TrustVector::Root), "read", "file"), 
            PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&create_identity("user", TrustVector::Enclave), "read", "file"), 
            PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&create_identity("user", TrustVector::Signed("test".to_string())), "read", "file"), 
            PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&create_identity("user", TrustVector::Unverified), "read", "file"), 
            PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&create_identity("user", TrustVector::Compromised), "read", "file"), 
            PolicyEffect::Deny);
    }

    // Complex policy scenarios
    #[test]
    fn test_complex_policy_hierarchy() {
        let mut policy_set = PolicySet::new("complex".to_string(), "1.0.0".to_string());
        let admin = create_identity("admin", TrustVector::Signed("test".to_string()));
        let user = create_identity("user", TrustVector::Signed("test".to_string()));
        let guest = create_identity("guest", TrustVector::Unverified);
        
        // Admin can do everything
        policy_set.add_rule(create_rule("admin", "*", "*", PolicyEffect::Allow));
        
        // Users can read public resources
        policy_set.add_rule(create_rule("user", "read", "public", PolicyEffect::Allow));
        
        // Users need escalation for sensitive operations
        policy_set.add_rule(create_rule("user", "write", "sensitive", 
            PolicyEffect::EscalateTo("admin".to_string())));
        
        // Guests can only read public resources
        policy_set.add_rule(create_rule("guest", "read", "public", PolicyEffect::Allow));
        
        // Test admin access
        assert_eq!(policy_set.evaluate(&admin, "delete", "sensitive"), PolicyEffect::Allow);
        
        // Test user access
        assert_eq!(policy_set.evaluate(&user, "read", "public"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&user, "write", "sensitive"), 
            PolicyEffect::EscalateTo("admin".to_string()));
        assert_eq!(policy_set.evaluate(&user, "delete", "sensitive"), PolicyEffect::Deny);
        
        // Test guest access
        assert_eq!(policy_set.evaluate(&guest, "read", "public"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&guest, "write", "public"), PolicyEffect::Deny);
    }

    // Edge cases for empty and invalid data
    #[test]
    fn test_empty_strings() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("", "", "", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "", ""), PolicyEffect::Allow);
    }

    #[test]
    fn test_unicode_strings() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("用户", TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule("用户", "读取", "文件", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "读取", "文件"), PolicyEffect::Allow);
    }

    #[test]
    fn test_very_long_strings() {
        let long_string = "a".repeat(1000);
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity(&long_string, TrustVector::Signed("test".to_string()));
        
        policy_set.add_rule(create_rule(&long_string, &long_string, &long_string, PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, &long_string, &long_string), PolicyEffect::Allow);
    }

    // Test standalone evaluate_policy function
    #[test]
    fn test_standalone_evaluate_policy_root() {
        let root_identity = create_identity("root", TrustVector::Root);
        assert_eq!(evaluate_policy(&root_identity, "any_action"), PolicyEffect::Allow);
    }

    #[test]
    fn test_standalone_evaluate_policy_compromised() {
        let compromised_identity = create_identity("user", TrustVector::Compromised);
        assert_eq!(evaluate_policy(&compromised_identity, "any_action"), PolicyEffect::Deny);
    }

    #[test]
    fn test_standalone_evaluate_policy_shutdown_non_enclave() {
        let verified_identity = create_identity("user", TrustVector::Signed("test".to_string()));
        assert_eq!(evaluate_policy(&verified_identity, "shutdown"), 
            PolicyEffect::EscalateTo("compliance_auditor".to_string()));
        
        let untrusted_identity = create_identity("user", TrustVector::Unverified);
        assert_eq!(evaluate_policy(&untrusted_identity, "shutdown"), 
            PolicyEffect::EscalateTo("compliance_auditor".to_string()));
    }

    #[test]
    fn test_standalone_evaluate_policy_shutdown_enclave() {
        let enclave_identity = create_identity("user", TrustVector::Enclave);
        assert_eq!(evaluate_policy(&enclave_identity, "shutdown"), PolicyEffect::Allow);
    }

    #[test]
    fn test_standalone_evaluate_policy_normal_action() {
        let verified_identity = create_identity("user", TrustVector::Signed("test".to_string()));
        assert_eq!(evaluate_policy(&verified_identity, "read"), PolicyEffect::Allow);
        assert_eq!(evaluate_policy(&verified_identity, "write"), PolicyEffect::Allow);
    }

    // Performance and stress tests
    #[test]
    fn test_large_policy_set() {
        let mut policy_set = PolicySet::new("large".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        // Add many rules
        for i in 0..1000 {
            policy_set.add_rule(create_rule(
                &format!("role_{}", i),
                &format!("action_{}", i),
                &format!("resource_{}", i),
                PolicyEffect::Allow
            ));
        }
        
        // Add a matching rule at the end
        policy_set.add_rule(create_rule("user", "read", "file", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "read", "file"), PolicyEffect::Allow);
    }

    #[test]
    fn test_multiple_wildcard_combinations() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        let identity = create_identity("user", TrustVector::Signed("test".to_string()));
        
        // Test various wildcard combinations
        policy_set.add_rule(create_rule("*", "read", "public", PolicyEffect::Allow));
        policy_set.add_rule(create_rule("user", "*", "private", PolicyEffect::Allow));
        policy_set.add_rule(create_rule("admin", "write", "*", PolicyEffect::Allow));
        
        assert_eq!(policy_set.evaluate(&identity, "read", "public"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&identity, "write", "private"), PolicyEffect::Allow);
        assert_eq!(policy_set.evaluate(&identity, "delete", "private"), PolicyEffect::Allow);
    }

    // Serialization tests
    #[test]
    fn test_policy_set_serialization() {
        let mut policy_set = PolicySet::new("test".to_string(), "1.0.0".to_string());
        policy_set.add_rule(create_rule("admin", "read", "database", PolicyEffect::Allow));
        policy_set.add_rule(create_rule("user", "write", "file", PolicyEffect::EscalateTo("admin".to_string())));
        
        let json = serde_json::to_string(&policy_set).unwrap();
        let deserialized: PolicySet = serde_json::from_str(&json).unwrap();
        
        assert_eq!(policy_set.name, deserialized.name);
        assert_eq!(policy_set.version, deserialized.version);
        assert_eq!(policy_set.rules.len(), deserialized.rules.len());
    }

    // Clone and equality tests
    #[test]
    fn test_policy_effect_clone_and_equality() {
        let original = PolicyEffect::EscalateTo("admin".to_string());
        let cloned = original.clone();
        
        assert_eq!(original, cloned);
        assert_ne!(original, PolicyEffect::Allow);
        assert_ne!(original, PolicyEffect::Deny);
    }

    #[test]
    fn test_policy_rule_clone() {
        let original = create_rule("admin", "read", "database", PolicyEffect::Allow);
        let cloned = original.clone();
        
        assert_eq!(original.role, cloned.role);
        assert_eq!(original.action, cloned.action);
        assert_eq!(original.resource, cloned.resource);
        assert_eq!(original.effect, cloned.effect);
    }

    #[test]
    fn test_policy_set_clone() {
        let mut original = PolicySet::new("test".to_string(), "1.0.0".to_string());
        original.add_rule(create_rule("admin", "read", "database", PolicyEffect::Allow));
        
        let cloned = original.clone();
        
        assert_eq!(original.name, cloned.name);
        assert_eq!(original.version, cloned.version);
        assert_eq!(original.rules.len(), cloned.rules.len());
    }
}