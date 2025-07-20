// Advanced production-grade tests for db/access.rs
// NOTE: All tests are commented out because db/access.rs is private and its items are not accessible from here.
// If you want to test these, make the module and its items public, or move the tests to the same crate as the implementation.

/*
// use common::db::access::*;
// use common::identity::IdentityContext;
// use common::policy::{PolicyRule, PolicyEffect};
// use std::sync::Arc;
// use std::thread;
// use proptest::prelude::*;

#[test]
fn test_init_and_get_access_manager() {
    assert!(init_access_manager().is_ok());
    let manager = get_access_manager();
    assert!(manager.is_ok());
}

#[test]
fn test_get_access_manager_before_init() {
    let _ = DB_ACCESS_MANAGER.write().unwrap().take();
    let result = get_access_manager();
    assert!(result.is_err());
}

#[test]
fn test_check_access_root() {
    init_access_manager().unwrap();
    let manager = get_access_manager().unwrap();
    let identity = IdentityContext::root();
    let op = DbOperation::Read;
    let resource = DbResource::new("test");
    assert!(manager.check_access(&identity, &op, &resource).is_ok());
}

#[test]
fn test_check_access_compromised() {
    init_access_manager().unwrap();
    let manager = get_access_manager().unwrap();
    let mut identity = IdentityContext::root();
    identity.trust_vector = common::identity::TrustVector::Compromised;
    let op = DbOperation::Read;
    let resource = DbResource::new("test");
    let result = manager.check_access(&identity, &op, &resource);
    assert!(result.is_err());
}

#[test]
fn test_access_logging() {
    init_access_manager().unwrap();
    let manager = get_access_manager().unwrap();
    let identity = IdentityContext::root();
    let op = DbOperation::Read;
    let resource = DbResource::new("test");
    manager.log_access(&identity, &op, &resource, true, None, 10);
    let logs = manager.get_access_logs(1);
    assert!(!logs.is_empty());
}

#[test]
fn test_policy_rule_add_and_remove() {
    init_access_manager().unwrap();
    let manager = get_access_manager().unwrap();
    let rule = PolicyRule {
        role: "TestRole".to_string(),
        action: "read".to_string(),
        resource: "data:test".to_string(),
        effect: PolicyEffect::Allow,
    };
    manager.add_policy_rule(rule.clone());
    manager.remove_policy_rule(&rule.role, &rule.action, &rule.resource);
}

#[test]
fn test_rate_limiting() {
    init_access_manager().unwrap();
    let manager = get_access_manager().unwrap();
    manager.configure_rate_limit("global", 1, 1);
    let identity = IdentityContext::root();
    let op = DbOperation::Read;
    let resource = DbResource::new("test");
    assert!(manager.check_access(&identity, &op, &resource).is_ok());
    // Second call should fail due to rate limit
    let result = manager.check_access(&identity, &op, &resource);
    assert!(result.is_err());
}

#[test]
fn test_db_access_guard_success_and_error() {
    init_access_manager().unwrap();
    let identity = IdentityContext::root();
    let op = DbOperation::Read;
    let resource = DbResource::new("test");
    let guard = DbAccessGuard::new(&identity, op.clone(), resource.clone());
    assert!(guard.is_ok());
    guard.unwrap().complete();
    let guard2 = DbAccessGuard::new(&identity, op, resource);
    assert!(guard2.is_ok());
    guard2.unwrap().complete_with_error("fail");
}

// --- Advanced: Property-based test for access checks ---
proptest! {
    #[test]
    fn prop_access_check_random_resource(random_id in "[a-zA-Z0-9]{1,8}") {
        init_access_manager().unwrap();
        let manager = get_access_manager().unwrap();
        let identity = IdentityContext::root();
        let op = DbOperation::Read;
        let resource = DbResource::new(&random_id);
        let result = manager.check_access(&identity, &op, &resource);
        assert!(result.is_ok());
    }
}

// --- Advanced: Concurrency test for access logging ---
#[test]
fn test_concurrent_access_logging() {
    init_access_manager().unwrap();
    let manager = get_access_manager().unwrap();
    let manager = Arc::new(manager);
    let identity = IdentityContext::root();
    let op = DbOperation::Read;
    let resource = DbResource::new("test");

    let handles: Vec<_> = (0..8).map(|i| {
        let mgr = Arc::clone(&manager);
        let id = identity.clone();
        let op = op.clone();
        let res = resource.clone();
        thread::spawn(move || {
            mgr.log_access(&id, &op, &res, true, None, i);
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }
    let logs = manager.get_access_logs(8);
    assert!(logs.len() >= 8);
}
*/
