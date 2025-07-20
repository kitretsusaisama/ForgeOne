//! # Telemetry and Tracing Tests
//! 
//! This module contains tests for the TelemetrySpan and related modules, focusing on
//! stress testing, latency testing, and concurrent telemetry traces.

use common::prelude::*;
use common::observer;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic telemetry span creation and events
    /// 
    /// This test verifies that telemetry spans can be created and events can be added.
    #[test]
    fn test_basic_telemetry() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a new telemetry span
        let mut span = TelemetrySpan::new("test-span".to_string(), identity.clone());
        
        // Add attributes to the span
        span.add_attribute("key1".to_string(), "value1".to_string());
        span.add_attribute("key2".to_string(), "value2".to_string());
        
        // Add events to the span
        span.add_event("event1".to_string(), HashMap::new());
        
        let mut event2_attrs = HashMap::new();
        event2_attrs.insert("event-key1".to_string(), "event-value1".to_string());
        span.add_event("event2".to_string(), event2_attrs);
        
        // End the span
        span.end();
        
        // Verify span properties
        assert_eq!(span.name, "test-span");
        assert_eq!(span.identity.tenant_id, "test-tenant");
        assert_eq!(span.identity.user_id, "test-user");
        assert!(span.end_time.is_some());
        
        // Verify attributes
        assert_eq!(span.attributes.len(), 2);
        assert_eq!(span.attributes.get("key1"), Some(&"value1".to_string()));
        assert_eq!(span.attributes.get("key2"), Some(&"value2".to_string()));
        
        // Verify events
        assert_eq!(span.events.len(), 2);
        assert_eq!(span.events[0].name, "event1");
        assert_eq!(span.events[1].name, "event2");
        assert_eq!(span.events[1].attributes.len(), 1);
        assert_eq!(span.events[1].attributes.get("event-key1"), Some(&"event-value1".to_string()));
    }

    /// Test parent-child span relationships
    /// 
    /// This test verifies that parent-child relationships between spans are maintained correctly.
    #[test]
    fn test_parent_child_spans() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a parent span
        let parent_span = TelemetrySpan::new("parent-span".to_string(), identity.clone());
        
        // Create a child span
        let child_span = parent_span.create_child("child-span".to_string());
        
        // Create a grandchild span
        let grandchild_span = child_span.create_child("grandchild-span".to_string());
        
        // Verify parent-child relationships
        assert!(parent_span.parent_span_id.is_none());
        assert_eq!(child_span.parent_span_id, Some(parent_span.span_id));
        assert_eq!(grandchild_span.parent_span_id, Some(child_span.span_id));
        
        // Verify trace IDs are consistent
        assert_eq!(parent_span.trace_id, child_span.trace_id);
        assert_eq!(child_span.trace_id, grandchild_span.trace_id);
        
        // Verify span IDs are unique
        assert_ne!(parent_span.span_id, child_span.span_id);
        assert_ne!(child_span.span_id, grandchild_span.span_id);
        assert_ne!(parent_span.span_id, grandchild_span.span_id);
    }

    /// Test span duration calculation
    /// 
    /// This test verifies that span durations are calculated correctly.
    #[test]
    fn test_span_duration() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a new telemetry span
        let mut span = TelemetrySpan::new("test-span".to_string(), identity.clone());
        
        // Sleep for a short time
        thread::sleep(Duration::from_millis(10));
        
        // End the span
        span.end();
        
        // Verify that the span has a duration
        let start_time = span.start_time;
        let end_time = span.end_time.unwrap();
        let duration = end_time.signed_duration_since(start_time);
        
        assert!(duration.num_milliseconds() >= 10, "Span duration was too short: {:?}", duration);
    }

    /// Test concurrent span creation and modification
    /// 
    /// This test verifies that spans can be created and modified concurrently.
    #[test]
    fn test_concurrent_spans() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a parent span
        let parent_span = Arc::new(Mutex::new(TelemetrySpan::new("parent-span".to_string(), identity.clone())));
        
        // Create a vector to hold thread handles
        let mut handles = vec![];
        
        // Spawn 10 threads to create child spans
        for i in 0..10 {
            let parent_span_clone = Arc::clone(&parent_span);
            let _identity_clone = identity.clone();
            
            let handle = thread::spawn(move || {
                // Lock the parent span
                let parent = parent_span_clone.lock().unwrap();
                
                // Create a child span
                let mut child = parent.create_child(format!("child-span-{}", i));
                
                // Add attributes and events
                child.add_attribute(format!("thread-{}", i), format!("value-{}", i));
                
                let mut event_attrs = HashMap::new();
                event_attrs.insert(format!("event-key-{}", i), format!("event-value-{}", i));
                child.add_event(format!("event-{}", i), event_attrs);
                
                // End the span
                child.end();
                
                // Return the child span
                child
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let mut child_spans = vec![];
        for handle in handles {
            child_spans.push(handle.join().unwrap());
        }
        
        // Verify that all child spans were created correctly
        assert_eq!(child_spans.len(), 10);
        
        // Get the parent span ID
        let parent_span_id = parent_span.lock().unwrap().span_id;
        
        // Verify that all child spans have the correct parent
        for (i, child) in child_spans.iter().enumerate() {
            assert_eq!(child.name, format!("child-span-{}", i));
            assert_eq!(child.parent_span_id, Some(parent_span_id));
            assert_eq!(child.attributes.len(), 1);
            assert_eq!(child.attributes.get(&format!("thread-{}", i)), Some(&format!("value-{}", i)));
            assert_eq!(child.events.len(), 1);
            assert_eq!(child.events[0].name, format!("event-{}", i));
            assert_eq!(child.events[0].attributes.len(), 1);
            assert_eq!(child.events[0].attributes.get(&format!("event-key-{}", i)), Some(&format!("event-value-{}", i)));
        }
    }

    /// Test stress testing of span creation
    /// 
    /// This test verifies that a large number of spans can be created efficiently.
    #[test]
    fn test_span_stress_test() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a vector to hold spans
        let mut spans = vec![];
        
        // Measure the time to create 10,000 spans
        let start = Instant::now();
        
        for i in 0..10000 {
            let mut span = TelemetrySpan::new(format!("span-{}", i), identity.clone());
            span.add_attribute("index".to_string(), i.to_string());
            span.end();
            spans.push(span);
        }
        
        let duration = start.elapsed();
        
        // Verify that 10,000 spans were created
        assert_eq!(spans.len(), 10000);
        
        // Verify that the operation completed within 2 seconds
        assert!(duration < Duration::from_secs(2), "Span creation took too long: {:?}", duration);
    }

    /// Test concurrent span creation with shared trace ID
    /// 
    /// This test verifies that spans can be created concurrently with a shared trace ID.
    #[test]
    fn test_concurrent_spans_shared_trace() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a shared trace ID
        let trace_id = identity.request_id;
        
        // Create a vector to hold thread handles
        let mut handles = vec![];
        
        // Spawn 10 threads to create spans
        for i in 0..10 {
            let identity_clone = identity.clone();
            
            let handle = thread::spawn(move || {
                // Create a new span with the shared trace ID
                let mut span = TelemetrySpan::new(format!("span-{}", i), identity_clone);
                
                // Verify that the trace ID is correct
                assert_eq!(span.trace_id, trace_id);
                
                // Add attributes and events
                span.add_attribute(format!("thread-{}", i), format!("value-{}", i));
                
                let mut event_attrs = HashMap::new();
                event_attrs.insert(format!("event-key-{}", i), format!("event-value-{}", i));
                span.add_event(format!("event-{}", i), event_attrs);
                
                // End the span
                span.end();
                
                // Return the span
                span
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let mut spans = vec![];
        for handle in handles {
            spans.push(handle.join().unwrap());
        }
        
        // Verify that all spans were created correctly
        assert_eq!(spans.len(), 10);
        
        // Verify that all spans have the same trace ID
        for span in &spans {
            assert_eq!(span.trace_id, trace_id);
        }
    }

    /// Test span event ordering
    /// 
    /// This test verifies that span events are ordered correctly.
    #[test]
    fn test_span_event_ordering() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a new telemetry span
        let mut span = TelemetrySpan::new("test-span".to_string(), identity.clone());
        
        // Add events with delays
        span.add_event("event1".to_string(), HashMap::new());
        thread::sleep(Duration::from_millis(10));
        
        span.add_event("event2".to_string(), HashMap::new());
        thread::sleep(Duration::from_millis(10));
        
        span.add_event("event3".to_string(), HashMap::new());
        
        // End the span
        span.end();
        
        // Verify that events are in the correct order
        assert_eq!(span.events.len(), 3);
        assert_eq!(span.events[0].name, "event1");
        assert_eq!(span.events[1].name, "event2");
        assert_eq!(span.events[2].name, "event3");
        
        // Verify that event times are in ascending order
        assert!(span.events[0].time <= span.events[1].time);
        assert!(span.events[1].time <= span.events[2].time);
    }

    /// Test span logging methods
    /// 
    /// This test verifies that span logging methods work correctly.
    #[test]
    fn test_span_logging() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a new telemetry span
        let mut span = TelemetrySpan::new("test-span".to_string(), identity.clone());
        
        // Log messages at different levels
        span.log_info("Info message");
        span.log_debug("Debug message");
        span.log_warn("Warning message");
        span.log_error("Error message");
        span.log_trace("Trace message");
        
        // End the span
        span.end();
        
        // Verify that events were created for each log message
        assert_eq!(span.events.len(), 5);
        
        // Verify that event names contain the log level
        assert!(span.events[0].name.contains("INFO"));
        assert!(span.events[1].name.contains("DEBUG"));
        assert!(span.events[2].name.contains("WARN"));
        assert!(span.events[3].name.contains("ERROR"));
        assert!(span.events[4].name.contains("TRACE"));
        
        // Verify that event attributes contain the message
        assert_eq!(span.events[0].attributes.get("message"), Some(&"Info message".to_string()));
        assert_eq!(span.events[1].attributes.get("message"), Some(&"Debug message".to_string()));
        assert_eq!(span.events[2].attributes.get("message"), Some(&"Warning message".to_string()));
        assert_eq!(span.events[3].attributes.get("message"), Some(&"Error message".to_string()));
        assert_eq!(span.events[4].attributes.get("message"), Some(&"Trace message".to_string()));
    }

    /// Test LLM-readable string conversion
    /// 
    /// This test verifies that spans can be converted to LLM-readable strings.
    #[test]
    fn test_span_to_llm_string() {
        // Create a new identity context
        let identity = IdentityContext::new("test-tenant".to_string(), "test-user".to_string());
        
        // Create a new telemetry span
        let mut span = TelemetrySpan::new("test-span".to_string(), identity.clone());
        
        // Add attributes and events
        span.add_attribute("key1".to_string(), "value1".to_string());
        
        let mut event_attrs = HashMap::new();
        event_attrs.insert("event-key1".to_string(), "event-value1".to_string());
        span.add_event("event1".to_string(), event_attrs);
        
        // End the span
        span.end();
        
        // Convert to LLM-readable string
        let llm_string = observer::telemetry_span_to_llm_string(&span);
        
        // Verify that the string contains all the important information
        assert!(llm_string.contains("test-span"));
        assert!(llm_string.contains("test-tenant"));
        assert!(llm_string.contains("test-user"));
        assert!(llm_string.contains("key1"));
        assert!(llm_string.contains("value1"));
        assert!(llm_string.contains("event1"));
        assert!(llm_string.contains("event-key1"));
        assert!(llm_string.contains("event-value1"));
    }

    /// Test massive concurrent span creation and event logging
    /// 
    /// This test verifies that a large number of spans can be created and events can be logged concurrently.
    #[test]
    fn test_massive_concurrent_spans() {
        // Create a shared trace ID
        let trace_id = uuid::Uuid::new_v4();
        
        // Create a vector to hold thread handles
        let mut handles = vec![];
        
        // Spawn 20 threads to create spans and log events
        for thread_id in 0..20 {
            let _trace_id_clone = trace_id;
            
            let handle = thread::spawn(move || {
                // Create a new identity context
                let identity = IdentityContext::new(
                    format!("tenant-{}", thread_id),
                    format!("user-{}", thread_id)
                );
                
                // Create spans and log events
                let mut spans = vec![];
                for span_id in 0..500 {
                    // Create a new span
                    let mut span = TelemetrySpan::new(
                        format!("span-{}-{}", thread_id, span_id),
                        identity.clone()
                    );
                    
                    // Add attributes
                    span.add_attribute("thread_id".to_string(), thread_id.to_string());
                    span.add_attribute("span_id".to_string(), span_id.to_string());
                    
                    // Log events
                    for event_id in 0..5 {
                        let mut event_attrs = HashMap::new();
                        event_attrs.insert("event_id".to_string(), event_id.to_string());
                        span.add_event(format!("event-{}-{}-{}", thread_id, span_id, event_id), event_attrs);
                    }
                    
                    // End the span
                    span.end();
                    
                    // Add to the list
                    spans.push(span);
                }
                
                spans
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let start = Instant::now();
        let mut all_spans = vec![];
        for handle in handles {
            all_spans.push(handle.join().unwrap());
        }
        let duration = start.elapsed();
        
        // Verify that the operation completed within 2 seconds
        assert!(duration < Duration::from_secs(2), "Massive concurrent span creation took too long: {:?}", duration);
        
        // Verify that all spans were created
        assert_eq!(all_spans.len(), 20);
        for spans in &all_spans {
            assert_eq!(spans.len(), 500);
            for span in spans {
                assert_eq!(span.events.len(), 5);
            }
        }
    }
}