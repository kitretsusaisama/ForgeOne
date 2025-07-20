//! # LLM-explainable observation system for ForgeOne
//! observer.rs
//! This module provides an LLM-explainable observation system for the ForgeOne platform.
//! It handles creating and formatting observations for LLM consumption.

// No need for prelude import

#[cfg(test)]
mod tests {
    // No need for super import
    use chrono::Utc;
    use common::error::ForgeError;
    use common::identity::IdentityContext;
    use common::observer::{
        result_to_llm_string, telemetry_span_to_llm_string, Observation, ObservationSeverity,
        ObservationType,
    };
    use common::telemetry::{TelemetryEvent, TelemetrySpan};
    use std::collections::HashMap;
    use uuid::Uuid;

    // Helper function to create test identity context
    fn create_test_identity() -> IdentityContext {
        IdentityContext::new("test_tenant".to_string(), "test_user".to_string())
    }

    // Helper function to create test identity with specific values
    fn create_identity(tenant_id: &str, user_id: &str) -> IdentityContext {
        IdentityContext::new(tenant_id.to_string(), user_id.to_string())
    }

    // Helper function to create test telemetry span
    fn create_test_span() -> TelemetrySpan {
        TelemetrySpan {
            span_id: Uuid::new_v4(),
            trace_id: Uuid::new_v4(),
            parent_span_id: None,
            name: "test_span".to_string(),
            start_time: Utc::now(),
            end_time: None,
            identity: create_test_identity(),
            attributes: HashMap::new(),
            events: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    #[test]
    fn test_observation_type_serialization() {
        // Test all observation types serialize/deserialize correctly
        let types = vec![
            ObservationType::Info,
            ObservationType::Warning,
            ObservationType::Error,
            ObservationType::Debug,
            ObservationType::Trace,
            ObservationType::Security,
            ObservationType::Performance,
            ObservationType::Policy,
        ];

        for obs_type in types {
            let serialized = serde_json::to_string(&obs_type).unwrap();
            let deserialized: ObservationType = serde_json::from_str(&serialized).unwrap();
            assert_eq!(obs_type, deserialized);
        }
    }

    #[test]
    fn test_observation_severity_serialization() {
        // Test all severity levels serialize/deserialize correctly
        let severities = vec![
            ObservationSeverity::Info,
            ObservationSeverity::Warning,
            ObservationSeverity::Error,
            ObservationSeverity::Critical,
        ];

        for severity in severities {
            let serialized = serde_json::to_string(&severity).unwrap();
            let deserialized: ObservationSeverity = serde_json::from_str(&serialized).unwrap();
            assert_eq!(severity, deserialized);
        }
    }

    #[test]
    fn test_observation_creation() {
        let identity = create_test_identity();
        let content = "Test observation content".to_string();

        let observation = Observation::new(
            identity.clone(),
            ObservationType::Info,
            content.clone(),
            ObservationSeverity::Info,
        );

        assert_eq!(observation.identity.tenant_id, identity.tenant_id);
        assert_eq!(observation.identity.user_id, identity.user_id);
        assert_eq!(observation.observation_type, ObservationType::Info);
        assert_eq!(observation.content, content);
        assert_eq!(observation.severity, ObservationSeverity::Info);

        // Timestamp should be recent (within last second)
        let now = Utc::now();
        let diff = now.signed_duration_since(observation.timestamp);
        assert!(diff.num_seconds() < 1);
    }

    #[test]
    fn test_observation_to_llm_string_all_combinations() {
        let identity = create_test_identity();
        let content = "Test message";

        // Test all severity levels
        let severities = vec![
            (ObservationSeverity::Info, "INFO"),
            (ObservationSeverity::Warning, "WARNING"),
            (ObservationSeverity::Error, "ERROR"),
            (ObservationSeverity::Critical, "CRITICAL"),
        ];

        // Test all observation types
        let types = vec![
            (ObservationType::Info, "INFO"),
            (ObservationType::Warning, "WARNING"),
            (ObservationType::Error, "ERROR"),
            (ObservationType::Debug, "DEBUG"),
            (ObservationType::Trace, "TRACE"),
            (ObservationType::Security, "SECURITY"),
            (ObservationType::Performance, "PERFORMANCE"),
            (ObservationType::Policy, "POLICY"),
        ];

        for (severity, severity_str) in severities {
            for (obs_type, type_str) in &types {
                let observation = Observation::new(
                    identity.clone(),
                    obs_type.clone(),
                    content.to_string(),
                    severity.clone(),
                );

                let llm_string = observation.to_llm_string();

                // Check format: [timestamp] [severity] [type] [tenant_id] [user_id]: content
                assert!(llm_string.contains(&format!("[{}]", severity_str)));
                assert!(llm_string.contains(&format!("[{}]", type_str)));
                assert!(llm_string.contains(&format!("[{}]", identity.tenant_id)));
                assert!(llm_string.contains(&format!("[{}]", identity.user_id)));
                assert!(llm_string.ends_with(&format!(": {}", content)));
                assert!(llm_string.contains(&observation.timestamp.to_rfc3339()));
            }
        }
    }

    #[test]
    fn test_observation_to_llm_string_with_special_characters() {
        let identity = create_identity("tenant-with-dashes", "user@domain.com");
        let content = "Content with special chars: !@#$%^&*()[]{}|;':\",./<>?";

        let observation = Observation::new(
            identity.clone(),
            ObservationType::Info,
            content.to_string(),
            ObservationSeverity::Info,
        );

        let llm_string = observation.to_llm_string();

        assert!(llm_string.contains("[tenant-with-dashes]"));
        assert!(llm_string.contains("[user@domain.com]"));
        assert!(llm_string.contains(content));
    }

    #[test]
    fn test_observation_to_llm_string_with_unicode() {
        let identity = create_identity("租户", "用户");
        let content = "Unicode content: 🚀 测试 αβγ";

        let observation = Observation::new(
            identity.clone(),
            ObservationType::Info,
            content.to_string(),
            ObservationSeverity::Info,
        );

        let llm_string = observation.to_llm_string();

        assert!(llm_string.contains("[租户]"));
        assert!(llm_string.contains("[用户]"));
        assert!(llm_string.contains(content));
    }

    #[test]
    fn test_observation_to_llm_string_with_empty_strings() {
        let identity = create_identity("", "");
        let content = "";

        let observation = Observation::new(
            identity.clone(),
            ObservationType::Info,
            content.to_string(),
            ObservationSeverity::Info,
        );

        let llm_string = observation.to_llm_string();

        assert!(llm_string.contains("[]"));
        assert!(llm_string.ends_with(": "));
    }

    #[test]
    fn test_observation_to_llm_string_with_very_long_content() {
        let identity = create_test_identity();
        let content = "x".repeat(10000); // Very long content

        let observation = Observation::new(
            identity.clone(),
            ObservationType::Info,
            content.clone(),
            ObservationSeverity::Info,
        );

        let llm_string = observation.to_llm_string();

        assert!(llm_string.contains(&content));
        assert!(llm_string.len() > 10000);
    }

    #[test]
    fn test_observation_serialization_roundtrip() {
        let identity = create_test_identity();
        let observation = Observation::new(
            identity,
            ObservationType::Security,
            "Security event detected".to_string(),
            ObservationSeverity::Critical,
        );

        let serialized = serde_json::to_string(&observation).unwrap();
        let deserialized: Observation = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            observation.identity.tenant_id,
            deserialized.identity.tenant_id
        );
        assert_eq!(observation.identity.user_id, deserialized.identity.user_id);
        assert_eq!(observation.observation_type, deserialized.observation_type);
        assert_eq!(observation.content, deserialized.content);
        assert_eq!(observation.severity, deserialized.severity);
        assert_eq!(observation.timestamp, deserialized.timestamp);
    }

    #[test]
    fn test_telemetry_span_to_llm_string_basic() {
        let span = create_test_span();
        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains(&format!("Span: {}", span.name)));
        assert!(llm_string.contains(&format!("ID: {}", span.span_id)));
        assert!(llm_string.contains(&format!("Trace: {}", span.trace_id)));
        assert!(llm_string.contains(&format!("Start: {}", span.start_time.to_rfc3339())));
        assert!(llm_string.contains(&format!("Tenant={}", span.identity.tenant_id)));
        assert!(llm_string.contains(&format!("User={}", span.identity.user_id)));
        assert!(!llm_string.contains("Parent:"));
        assert!(!llm_string.contains("End:"));
        assert!(!llm_string.contains("Duration:"));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_parent() {
        let mut span = create_test_span();
        span.parent_span_id = Some(Uuid::new_v4());

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains(&format!("Parent: {}", span.parent_span_id.unwrap())));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_end_time() {
        let mut span = create_test_span();
        let end_time = span.start_time + chrono::Duration::milliseconds(1500);
        span.end_time = Some(end_time);

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains(&format!("End: {}", end_time.to_rfc3339())));
        assert!(llm_string.contains("Duration: 1500 ms"));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_zero_duration() {
        let mut span = create_test_span();
        span.end_time = Some(span.start_time);

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains("Duration: 0 ms"));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_negative_duration() {
        let mut span = create_test_span();
        span.end_time = Some(span.start_time - chrono::Duration::milliseconds(100));

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains("Duration: -100 ms"));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_attributes() {
        let mut span = create_test_span();
        span.attributes
            .insert("key1".to_string(), "value1".to_string());
        span.attributes
            .insert("key2".to_string(), "value2".to_string());
        span.attributes
            .insert("special_chars".to_string(), "!@#$%^&*()".to_string());

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains("Attributes:"));
        assert!(llm_string.contains("key1: value1"));
        assert!(llm_string.contains("key2: value2"));
        assert!(llm_string.contains("special_chars: !@#$%^&*()"));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_events() {
        let mut span = create_test_span();
        let event_time = Utc::now();
        let mut event_attributes = HashMap::new();
        event_attributes.insert("event_attr".to_string(), "event_value".to_string());

        span.events.push(TelemetryEvent {
            time: event_time,
            name: "test_event".to_string(),
            attributes: event_attributes,
        });

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains("Events:"));
        assert!(llm_string.contains(&format!("[{}] test_event", event_time.to_rfc3339())));
        assert!(llm_string.contains("event_attr: event_value"));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_with_multiple_events() {
        let mut span = create_test_span();
        let event_time1 = Utc::now();
        let event_time2 = event_time1 + chrono::Duration::seconds(1);

        span.events.push(TelemetryEvent {
            time: event_time1,
            name: "event1".to_string(),
            attributes: HashMap::new(),
        });

        span.events.push(TelemetryEvent {
            time: event_time2,
            name: "event2".to_string(),
            attributes: HashMap::new(),
        });

        let llm_string = telemetry_span_to_llm_string(&span);

        assert!(llm_string.contains(&format!("[{}] event1", event_time1.to_rfc3339())));
        assert!(llm_string.contains(&format!("[{}] event2", event_time2.to_rfc3339())));
    }

    #[test]
    fn test_telemetry_span_to_llm_string_complex_scenario() {
        let mut span = create_test_span();
        span.parent_span_id = Some(Uuid::new_v4());
        span.end_time = Some(span.start_time + chrono::Duration::milliseconds(2500));

        span.attributes
            .insert("service.name".to_string(), "auth-service".to_string());
        span.attributes
            .insert("http.method".to_string(), "POST".to_string());
        span.attributes
            .insert("http.status_code".to_string(), "200".to_string());

        let event_time = span.start_time + chrono::Duration::milliseconds(1000);
        let mut event_attributes = HashMap::new();
        event_attributes.insert("cache.hit".to_string(), "true".to_string());

        span.events.push(TelemetryEvent {
            time: event_time,
            name: "cache_lookup".to_string(),
            attributes: event_attributes,
        });

        let llm_string = telemetry_span_to_llm_string(&span);

        // Verify all components are present
        assert!(llm_string.contains("Parent:"));
        assert!(llm_string.contains("Duration: 2500 ms"));
        assert!(llm_string.contains("service.name: auth-service"));
        assert!(llm_string.contains("http.method: POST"));
        assert!(llm_string.contains("http.status_code: 200"));
        assert!(llm_string.contains("cache_lookup"));
        assert!(llm_string.contains("cache.hit: true"));
    }

    #[test]
    fn test_result_to_llm_string_success() {
        let identity = create_test_identity();
        let result: common::error::Result<String> = Ok("success".to_string());

        let llm_string = result_to_llm_string(&identity, &result);

        assert!(llm_string.contains("Operation succeeded"));
        assert!(llm_string.contains(&format!("tenant={}", identity.tenant_id)));
        assert!(llm_string.contains(&format!("user={}", identity.user_id)));
    }

    #[test]
    fn test_result_to_llm_string_error() {
        let identity = create_test_identity();
        let result: common::error::Result<String> =
            Err(ForgeError::SerializationError("Invalid input".to_string()));

        let llm_string = result_to_llm_string(&identity, &result);

        assert!(llm_string.contains("Operation failed"));
        assert!(llm_string.contains(&format!("tenant={}", identity.tenant_id)));
        assert!(llm_string.contains(&format!("user={}", identity.user_id)));
        assert!(llm_string.contains("SerializationError"));
        assert!(llm_string.contains("Invalid input"));
    }

    #[test]
    fn test_result_to_llm_string_with_complex_types() {
        let identity = create_test_identity();

        // Test with complex success type
        let complex_result = vec![1, 2, 3, 4, 5];
        let result: common::error::Result<Vec<i32>> = Ok(complex_result);

        let llm_string = result_to_llm_string(&identity, &result);

        assert!(llm_string.contains("Operation succeeded"));
        assert!(llm_string.contains(&format!("tenant={}", identity.tenant_id)));
        assert!(llm_string.contains(&format!("user={}", identity.user_id)));
    }

    #[test]
    fn test_result_to_llm_string_with_different_identities() {
        let identities = vec![
            create_identity("tenant1", "user1"),
            create_identity("", ""),
            create_identity(
                "very-long-tenant-name-with-special-chars@#$",
                "user@domain.com",
            ),
        ];

        for identity in identities {
            let result: common::error::Result<()> = Ok(());
            let llm_string = result_to_llm_string(&identity, &result);

            assert!(llm_string.contains(&format!("tenant={}", identity.tenant_id)));
            assert!(llm_string.contains(&format!("user={}", identity.user_id)));
        }
    }

    #[test]
    fn test_observation_clone() {
        let identity = create_test_identity();
        let observation = Observation::new(
            identity,
            ObservationType::Policy,
            "Policy violation detected".to_string(),
            ObservationSeverity::Warning,
        );

        let cloned = observation.clone();

        assert_eq!(observation.identity.tenant_id, cloned.identity.tenant_id);
        assert_eq!(observation.identity.user_id, cloned.identity.user_id);
        assert_eq!(observation.observation_type, cloned.observation_type);
        assert_eq!(observation.content, cloned.content);
        assert_eq!(observation.severity, cloned.severity);
        assert_eq!(observation.timestamp, cloned.timestamp);
    }

    #[test]
    fn test_observation_debug() {
        let identity = create_test_identity();
        let observation = Observation::new(
            identity,
            ObservationType::Debug,
            "Debug message".to_string(),
            ObservationSeverity::Info,
        );

        let debug_str = format!("{:?}", observation);
        assert!(debug_str.contains("Observation"));
        assert!(debug_str.contains("Debug"));
        assert!(debug_str.contains("Info"));
    }

    #[test]
    fn test_enum_equality() {
        // Test ObservationType equality
        assert_eq!(ObservationType::Info, ObservationType::Info);
        assert_ne!(ObservationType::Info, ObservationType::Warning);

        // Test ObservationSeverity equality
        assert_eq!(ObservationSeverity::Critical, ObservationSeverity::Critical);
        assert_ne!(ObservationSeverity::Critical, ObservationSeverity::Warning);
    }

    #[test]
    fn test_observation_with_newlines_in_content() {
        let identity = create_test_identity();
        let content = "Multi-line\ncontent\nwith\nnewlines";

        let observation = Observation::new(
            identity,
            ObservationType::Info,
            content.to_string(),
            ObservationSeverity::Info,
        );

        let llm_string = observation.to_llm_string();
        assert!(llm_string.contains(content));
    }

    #[test]
    fn test_observation_with_tabs_in_content() {
        let identity = create_test_identity();
        let content = "Content\twith\ttabs";

        let observation = Observation::new(
            identity,
            ObservationType::Info,
            content.to_string(),
            ObservationSeverity::Info,
        );

        let llm_string = observation.to_llm_string();
        assert!(llm_string.contains(content));
    }

    #[test]
    fn test_telemetry_span_with_empty_name() {
        let mut span = create_test_span();
        span.name = String::new();

        let llm_string = telemetry_span_to_llm_string(&span);
        assert!(llm_string.contains("Span:  (ID:"));
    }

    #[test]
    fn test_concurrent_observation_creation() {
        use std::sync::Arc;
        use std::thread;

        let identity = Arc::new(create_test_identity());
        let mut handles = vec![];

        for i in 0..10 {
            let id = identity.clone();
            let handle = thread::spawn(move || {
                let observation = Observation::new(
                    (*id).clone(),
                    ObservationType::Info,
                    format!("Message {}", i),
                    ObservationSeverity::Info,
                );
                observation.to_llm_string()
            });
            handles.push(handle);
        }

        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.contains("Message"));
        }
    }

    #[test]
    fn test_memory_efficiency() {
        // Test that observations don't hold unnecessary memory
        let identity = create_test_identity();
        let mut observations = Vec::new();

        for i in 0..1000 {
            let observation = Observation::new(
                identity.clone(),
                ObservationType::Info,
                format!("Message {}", i),
                ObservationSeverity::Info,
            );
            observations.push(observation);
        }

        // Verify we can create many observations without issues
        assert_eq!(observations.len(), 1000);

        // Verify each observation is independent
        for (i, obs) in observations.iter().enumerate() {
            assert_eq!(obs.content, format!("Message {}", i));
        }
    }

    #[test]
    fn test_json_deserialization_with_missing_fields() {
        // Test that deserialization fails gracefully with missing required fields
        let incomplete_json = r#"{"observation_type": "Info", "content": "test"}"#;
        let result = serde_json::from_str::<Observation>(incomplete_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_json_deserialization_with_invalid_enum() {
        // Test that deserialization fails with invalid enum values
        let invalid_json = r#"{"observation_type": "InvalidType"}"#;
        let result = serde_json::from_str::<ObservationType>(invalid_json);
        assert!(result.is_err());
    }
}
