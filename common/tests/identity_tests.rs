use common::prelude::*;
use uuid::Uuid;
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // Test TrustVector enum
    #[test]
    fn test_trust_vector_variants() {
        // Test all variants can be created
        let root = TrustVector::Root;
        let signed = TrustVector::Signed("signature123".to_string());
        let enclave = TrustVector::Enclave;
        let edge_gateway = TrustVector::EdgeGateway;
        let unverified = TrustVector::Unverified;
        let compromised = TrustVector::Compromised;

        assert_eq!(root, TrustVector::Root);
        assert_eq!(signed, TrustVector::Signed("signature123".to_string()));
        assert_eq!(enclave, TrustVector::Enclave);
        assert_eq!(edge_gateway, TrustVector::EdgeGateway);
        assert_eq!(unverified, TrustVector::Unverified);
        assert_eq!(compromised, TrustVector::Compromised);
    }

    #[test]
    fn test_trust_vector_equality() {
        // Test equality for different variants
        assert_eq!(TrustVector::Root, TrustVector::Root);
        assert_eq!(
            TrustVector::Signed("sig1".to_string()),
            TrustVector::Signed("sig1".to_string())
        );
        assert_ne!(
            TrustVector::Signed("sig1".to_string()),
            TrustVector::Signed("sig2".to_string())
        );
        assert_ne!(TrustVector::Root, TrustVector::Unverified);
    }

    #[test]
    fn test_trust_vector_serialization() {
        // Test serialization of all variants
        let test_cases = vec![
            TrustVector::Root,
            TrustVector::Signed("test_signature".to_string()),
            TrustVector::Enclave,
            TrustVector::EdgeGateway,
            TrustVector::Unverified,
            TrustVector::Compromised,
        ];

        for trust_vector in test_cases {
            let serialized = serde_json::to_string(&trust_vector).unwrap();
            let deserialized: TrustVector = serde_json::from_str(&serialized).unwrap();
            assert_eq!(trust_vector, deserialized);
        }
    }

    #[test]
    fn test_trust_vector_signed_edge_cases() {
        // Test signed variant with edge cases
        let empty_sig = TrustVector::Signed("".to_string());
        let long_sig = TrustVector::Signed("a".repeat(10000));
        let unicode_sig = TrustVector::Signed("🔐🔑🛡️".to_string());
        let special_chars = TrustVector::Signed("!@#$%^&*()[]{}|;:,.<>?".to_string());

        // All should be valid
        assert!(matches!(empty_sig, TrustVector::Signed(_)));
        assert!(matches!(long_sig, TrustVector::Signed(_)));
        assert!(matches!(unicode_sig, TrustVector::Signed(_)));
        assert!(matches!(special_chars, TrustVector::Signed(_)));
    }

    // Test IdentityContext creation
    #[test]
    fn test_identity_context_new() {
        let tenant_id = "tenant123".to_string();
        let user_id = "user456".to_string();
        let ctx = IdentityContext::new(tenant_id.clone(), user_id.clone());

        assert_eq!(ctx.tenant_id, tenant_id);
        assert_eq!(ctx.user_id, user_id);
        assert!(ctx.agent_id.is_none());
        assert!(ctx.device_fingerprint.is_none());
        assert!(ctx.geo_ip.is_none());
        assert_eq!(ctx.trust_vector, TrustVector::Unverified);
        assert!(ctx.cryptographic_attestation.is_none());
        
        // UUIDs should be valid
        assert_ne!(ctx.request_id, Uuid::nil());
        assert_ne!(ctx.session_id, Uuid::nil());
    }

    #[test]
    fn test_identity_context_new_with_empty_strings() {
        let ctx = IdentityContext::new("".to_string(), "".to_string());
        assert_eq!(ctx.tenant_id, "");
        assert_eq!(ctx.user_id, "");
        assert_eq!(ctx.trust_vector, TrustVector::Unverified);
    }

    #[test]
    fn test_identity_context_new_with_unicode() {
        let tenant_id = "租户123".to_string();
        let user_id = "用户456".to_string();
        let ctx = IdentityContext::new(tenant_id.clone(), user_id.clone());

        assert_eq!(ctx.tenant_id, tenant_id);
        assert_eq!(ctx.user_id, user_id);
    }

    #[test]
    fn test_identity_context_new_with_long_strings() {
        let long_tenant = "a".repeat(10000);
        let long_user = "b".repeat(10000);
        let ctx = IdentityContext::new(long_tenant.clone(), long_user.clone());

        assert_eq!(ctx.tenant_id, long_tenant);
        assert_eq!(ctx.user_id, long_user);
    }

    #[test]
    fn test_identity_context_root() {
        let ctx = IdentityContext::root();

        assert_eq!(ctx.tenant_id, "system");
        assert_eq!(ctx.user_id, "root");
        assert_eq!(ctx.agent_id, Some("system".to_string()));
        assert!(ctx.device_fingerprint.is_none());
        assert!(ctx.geo_ip.is_none());
        assert_eq!(ctx.trust_vector, TrustVector::Root);
        assert!(ctx.cryptographic_attestation.is_none());
        
        // UUIDs should be valid
        assert_ne!(ctx.request_id, Uuid::nil());
        assert_ne!(ctx.session_id, Uuid::nil());
    }

    #[test]
    fn test_identity_context_multiple_root_calls() {
        let ctx1 = IdentityContext::root();
        let ctx2 = IdentityContext::root();

        // Should have different UUIDs
        assert_ne!(ctx1.request_id, ctx2.request_id);
        assert_ne!(ctx1.session_id, ctx2.session_id);
        
        // But same fixed values
        assert_eq!(ctx1.tenant_id, ctx2.tenant_id);
        assert_eq!(ctx1.user_id, ctx2.user_id);
        assert_eq!(ctx1.agent_id, ctx2.agent_id);
        assert_eq!(ctx1.trust_vector, ctx2.trust_vector);
    }

    // Test builder methods
    #[test]
    fn test_with_agent() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("agent123".to_string());

        assert_eq!(ctx.agent_id, Some("agent123".to_string()));
    }

    #[test]
    fn test_with_agent_empty_string() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("".to_string());

        assert_eq!(ctx.agent_id, Some("".to_string()));
    }

    #[test]
    fn test_with_agent_unicode() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("代理🤖".to_string());

        assert_eq!(ctx.agent_id, Some("代理🤖".to_string()));
    }

    #[test]
    fn test_with_device() {
        let fingerprint = "device_fingerprint_123".to_string();
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_device(fingerprint.clone());

        assert_eq!(ctx.device_fingerprint, Some(fingerprint));
    }

#[test]
fn test_with_device_edge_cases() {
    let long_string = "a".repeat(10000);

    let test_cases = vec![
        "",                       // static str
        &long_string,            // now a long-lived binding
        "🔐📱💻",
        "!@#$%^&*()",
        "device:fingerprint:with:colons",
    ];

    for case in test_cases {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_device(case.to_string());
        assert_eq!(ctx.device_fingerprint, Some(case.to_string()));
    }
}

    #[test]
    fn test_with_geo_ip() {
        let geo_ip = "192.168.1.1".to_string();
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_geo_ip(geo_ip.clone());

        assert_eq!(ctx.geo_ip, Some(geo_ip));
    }

    #[test]
    fn test_with_geo_ip_edge_cases() {
        let test_cases = vec![
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "::1",
            "2001:db8::1",
            "", // Invalid but should be accepted
            "not.an.ip.address",
            "192.168.1.999", // Invalid but should be accepted
        ];

        for case in test_cases {
            let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
                .with_geo_ip(case.to_string());
            assert_eq!(ctx.geo_ip, Some(case.to_string()));
        }
    }

    #[test]
    fn test_with_trust() {
        let trust_vectors = vec![
            TrustVector::Root,
            TrustVector::Signed("sig".to_string()),
            TrustVector::Enclave,
            TrustVector::EdgeGateway,
            TrustVector::Unverified,
            TrustVector::Compromised,
        ];

        for trust in trust_vectors {
            let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
                .with_trust(trust.clone());
            assert_eq!(ctx.trust_vector, trust);
        }
    }

    #[test]
    fn test_with_attestation() {
        let attestation = "crypto_attestation_123".to_string();
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_attestation(attestation.clone());

        assert_eq!(ctx.cryptographic_attestation, Some(attestation));
    }

    #[test]
fn test_with_attestation_edge_cases() {
    let long_string = "a".repeat(10000);

    let test_cases = vec![
        "".to_string(),
        long_string,
        "🔐🔑🛡️".to_string(),
        "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----".to_string(),
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...".to_string(), // JWT-like
    ];

    for case in test_cases {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_attestation(case.clone());
        assert_eq!(ctx.cryptographic_attestation, Some(case));
    }
}

    // Test method chaining
    #[test]
    fn test_method_chaining() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("agent123".to_string())
            .with_device("device456".to_string())
            .with_geo_ip("192.168.1.1".to_string())
            .with_trust(TrustVector::Signed("signature".to_string()))
            .with_attestation("attestation".to_string());

        assert_eq!(ctx.agent_id, Some("agent123".to_string()));
        assert_eq!(ctx.device_fingerprint, Some("device456".to_string()));
        assert_eq!(ctx.geo_ip, Some("192.168.1.1".to_string()));
        assert_eq!(ctx.trust_vector, TrustVector::Signed("signature".to_string()));
        assert_eq!(ctx.cryptographic_attestation, Some("attestation".to_string()));
    }

    #[test]
    fn test_method_chaining_partial() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("agent123".to_string())
            .with_trust(TrustVector::Enclave);

        assert_eq!(ctx.agent_id, Some("agent123".to_string()));
        assert_eq!(ctx.trust_vector, TrustVector::Enclave);
        assert!(ctx.device_fingerprint.is_none());
        assert!(ctx.geo_ip.is_none());
        assert!(ctx.cryptographic_attestation.is_none());
    }

    #[test]
    fn test_method_chaining_overwrite() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("agent1".to_string())
            .with_agent("agent2".to_string())
            .with_trust(TrustVector::Unverified)
            .with_trust(TrustVector::Root);

        assert_eq!(ctx.agent_id, Some("agent2".to_string()));
        assert_eq!(ctx.trust_vector, TrustVector::Root);
    }

    // Test serialization
    #[test]
    fn test_identity_context_serialization() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("agent".to_string())
            .with_device("device".to_string())
            .with_geo_ip("1.2.3.4".to_string())
            .with_trust(TrustVector::Signed("sig".to_string()))
            .with_attestation("attestation".to_string());

        let serialized = serde_json::to_string(&ctx).unwrap();
        let deserialized: IdentityContext = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ctx.request_id, deserialized.request_id);
        assert_eq!(ctx.session_id, deserialized.session_id);
        assert_eq!(ctx.tenant_id, deserialized.tenant_id);
        assert_eq!(ctx.user_id, deserialized.user_id);
        assert_eq!(ctx.agent_id, deserialized.agent_id);
        assert_eq!(ctx.device_fingerprint, deserialized.device_fingerprint);
        assert_eq!(ctx.geo_ip, deserialized.geo_ip);
        assert_eq!(ctx.trust_vector, deserialized.trust_vector);
        assert_eq!(ctx.cryptographic_attestation, deserialized.cryptographic_attestation);
    }

    #[test]
    fn test_identity_context_serialization_minimal() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string());
        let serialized = serde_json::to_string(&ctx).unwrap();
        let deserialized: IdentityContext = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ctx.request_id, deserialized.request_id);
        assert_eq!(ctx.session_id, deserialized.session_id);
        assert_eq!(ctx.tenant_id, deserialized.tenant_id);
        assert_eq!(ctx.user_id, deserialized.user_id);
        assert_eq!(ctx.agent_id, deserialized.agent_id);
        assert_eq!(ctx.device_fingerprint, deserialized.device_fingerprint);
        assert_eq!(ctx.geo_ip, deserialized.geo_ip);
        assert_eq!(ctx.trust_vector, deserialized.trust_vector);
        assert_eq!(ctx.cryptographic_attestation, deserialized.cryptographic_attestation);
    }

    #[test]
    fn test_identity_context_serialization_root() {
        let ctx = IdentityContext::root();
        let serialized = serde_json::to_string(&ctx).unwrap();
        let deserialized: IdentityContext = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ctx.request_id, deserialized.request_id);
        assert_eq!(ctx.session_id, deserialized.session_id);
        assert_eq!(ctx.tenant_id, deserialized.tenant_id);
        assert_eq!(ctx.user_id, deserialized.user_id);
        assert_eq!(ctx.agent_id, deserialized.agent_id);
        assert_eq!(ctx.trust_vector, deserialized.trust_vector);
    }

    // Test Debug and Clone traits
    #[test]
    fn test_debug_formatting() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string());
        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("IdentityContext"));
        assert!(debug_str.contains("tenant"));
        assert!(debug_str.contains("user"));
    }

    #[test]
    fn test_clone() {
        let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
            .with_agent("agent".to_string())
            .with_trust(TrustVector::Enclave);

        let cloned = ctx.clone();

        assert_eq!(ctx.request_id, cloned.request_id);
        assert_eq!(ctx.session_id, cloned.session_id);
        assert_eq!(ctx.tenant_id, cloned.tenant_id);
        assert_eq!(ctx.user_id, cloned.user_id);
        assert_eq!(ctx.agent_id, cloned.agent_id);
        assert_eq!(ctx.trust_vector, cloned.trust_vector);
    }

    #[test]
    fn test_trust_vector_debug_clone() {
        let trust = TrustVector::Signed("signature".to_string());
        let cloned = trust.clone();
        let debug_str = format!("{:?}", trust);

        assert_eq!(trust, cloned);
        assert!(debug_str.contains("Signed"));
        assert!(debug_str.contains("signature"));
    }

    // Edge cases and error conditions
    #[test]
    fn test_uuid_uniqueness() {
        let mut request_ids = std::collections::HashSet::new();
        let mut session_ids = std::collections::HashSet::new();

        // Generate 1000 contexts and ensure UUIDs are unique
        for _ in 0..1000 {
            let ctx = IdentityContext::new("tenant".to_string(), "user".to_string());
            assert!(request_ids.insert(ctx.request_id));
            assert!(session_ids.insert(ctx.session_id));
        }
    }

    #[test]
    fn test_special_characters_in_ids() {
        let special_chars = vec![
            "tenant/with/slashes",
            "tenant@with@symbols",
            "tenant with spaces",
            "tenant\nwith\nnewlines",
            "tenant\twith\ttabs",
            "tenant\"with\"quotes",
            "tenant'with'quotes",
            "tenant\\with\\backslashes",
        ];

        for tenant in special_chars {
            let ctx = IdentityContext::new(tenant.to_string(), "user".to_string());
            assert_eq!(ctx.tenant_id, tenant);
        }
    }

    #[test]
    fn test_numeric_string_ids() {
        let ctx = IdentityContext::new("12345".to_string(), "67890".to_string());
        assert_eq!(ctx.tenant_id, "12345");
        assert_eq!(ctx.user_id, "67890");
    }

    #[test]
    fn test_json_serialization_with_special_chars() {
        let ctx = IdentityContext::new("tenant\"with\"quotes".to_string(), "user\nwith\nnewlines".to_string())
            .with_agent("agent\twith\ttabs".to_string());

        let serialized = serde_json::to_string(&ctx).unwrap();
        let deserialized: IdentityContext = serde_json::from_str(&serialized).unwrap();

        assert_eq!(ctx.tenant_id, deserialized.tenant_id);
        assert_eq!(ctx.user_id, deserialized.user_id);
        assert_eq!(ctx.agent_id, deserialized.agent_id);
    }

    // Performance and memory tests
    #[test]
    fn test_large_data_handling() {
        let large_string = "x".repeat(1_000_000); // 1MB string
        let ctx = IdentityContext::new(large_string.clone(), "user".to_string())
            .with_agent(large_string.clone())
            .with_device(large_string.clone())
            .with_geo_ip(large_string.clone())
            .with_attestation(large_string.clone());

        assert_eq!(ctx.tenant_id.len(), 1_000_000);
        assert_eq!(ctx.agent_id.as_ref().unwrap().len(), 1_000_000);
        assert_eq!(ctx.device_fingerprint.as_ref().unwrap().len(), 1_000_000);
        assert_eq!(ctx.geo_ip.as_ref().unwrap().len(), 1_000_000);
        assert_eq!(ctx.cryptographic_attestation.as_ref().unwrap().len(), 1_000_000);
    }

    #[test]
    fn test_concurrent_uuid_generation() {
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::thread;

        let uuids = Arc::new(Mutex::new(Vec::new()));
        let mut handles = vec![];

        for _ in 0..10 {
            let uuids_clone = Arc::clone(&uuids);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    let ctx = IdentityContext::new("tenant".to_string(), "user".to_string());
                    let mut uuids_guard = uuids_clone.lock().unwrap();
                    uuids_guard.push(ctx.request_id);
                    uuids_guard.push(ctx.session_id);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let uuids_guard = uuids.lock().unwrap();
        let mut unique_uuids = std::collections::HashSet::new();
        for uuid in uuids_guard.iter() {
            assert!(unique_uuids.insert(*uuid));
        }
    }

    // Integration tests
    #[test]
    fn test_real_world_scenario_api_request() {
        let ctx = IdentityContext::new("acme-corp".to_string(), "john.doe@example.com".to_string())
            .with_agent("api-gateway-v1.2.3".to_string())
            .with_device("mobile-app-ios-fingerprint-abc123".to_string())
            .with_geo_ip("203.0.113.1".to_string())
            .with_trust(TrustVector::Signed("jwt-signature-here".to_string()))
            .with_attestation("device-attestation-certificate".to_string());

        // Verify all fields are properly set
        assert_eq!(ctx.tenant_id, "acme-corp");
        assert_eq!(ctx.user_id, "john.doe@example.com");
        assert_eq!(ctx.agent_id.unwrap(), "api-gateway-v1.2.3");
        assert_eq!(ctx.device_fingerprint.unwrap(), "mobile-app-ios-fingerprint-abc123");
        assert_eq!(ctx.geo_ip.unwrap(), "203.0.113.1");
        assert_eq!(ctx.trust_vector, TrustVector::Signed("jwt-signature-here".to_string()));
        assert_eq!(ctx.cryptographic_attestation.unwrap(), "device-attestation-certificate");
    }

    #[test]
    fn test_real_world_scenario_compromised_request() {
        let ctx = IdentityContext::new("suspicious-tenant".to_string(), "potential-threat".to_string())
            .with_agent("unknown-agent".to_string())
            .with_device("compromised-device-123".to_string())
            .with_geo_ip("192.0.2.1".to_string())
            .with_trust(TrustVector::Compromised);

        assert_eq!(ctx.trust_vector, TrustVector::Compromised);
        assert!(ctx.cryptographic_attestation.is_none());
    }

    #[test]
    fn test_real_world_scenario_system_operation() {
        let ctx = IdentityContext::root()
            .with_device("system-server-01".to_string())
            .with_geo_ip("10.0.0.1".to_string())
            .with_attestation("system-root-certificate".to_string());

        assert_eq!(ctx.tenant_id, "system");
        assert_eq!(ctx.user_id, "root");
        assert_eq!(ctx.agent_id.unwrap(), "system");
        assert_eq!(ctx.trust_vector, TrustVector::Root);
        assert_eq!(ctx.device_fingerprint.unwrap(), "system-server-01");
        assert_eq!(ctx.geo_ip.unwrap(), "10.0.0.1");
        assert_eq!(ctx.cryptographic_attestation.unwrap(), "system-root-certificate");
    }

    // Negative tests for potential panics or errors
    #[test]
    fn test_no_panics_with_extreme_inputs() {
        // Test with null bytes
        let ctx = IdentityContext::new("tenant\0with\0nulls".to_string(), "user\0id".to_string());
        assert!(ctx.tenant_id.contains('\0'));
        assert!(ctx.user_id.contains('\0'));

        // Test with maximum Unicode characters
        let ctx = IdentityContext::new("🚀🌟💫⭐✨".to_string(), "🦀🔥💎🎯🏆".to_string());
        assert_eq!(ctx.tenant_id, "🚀🌟💫⭐✨");
        assert_eq!(ctx.user_id, "🦀🔥💎🎯🏆");
    }

    #[test]
    fn test_serialization_roundtrip_with_all_trust_vectors() {
        let trust_vectors = vec![
            TrustVector::Root,
            TrustVector::Signed("test".to_string()),
            TrustVector::Enclave,
            TrustVector::EdgeGateway,
            TrustVector::Unverified,
            TrustVector::Compromised,
        ];

        for trust in trust_vectors {
            let ctx = IdentityContext::new("tenant".to_string(), "user".to_string())
                .with_trust(trust.clone());

            let serialized = serde_json::to_string(&ctx).unwrap();
            let deserialized: IdentityContext = serde_json::from_str(&serialized).unwrap();

            assert_eq!(ctx.trust_vector, deserialized.trust_vector);
        }
    }
}