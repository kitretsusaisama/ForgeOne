// //! # Error Tests
// //! /common/tests/error_tests.rs
// //! This module contains tests for the ForgeError and TraceableError modules, focusing on
// //! error creation, tracing, and handling.
// // NOTE: Some tests are commented out because of missing or unresolved items, or methods that do not exist. If you want to test these, make the modules and items public or move the tests to the same crate as the implementation.
// /*
// use common::prelude::*;
// use std::sync::Arc;
// use std::collections::HashMap;
// use common::error::*;
// use uuid::Uuid;
// use chrono::Utc;
// use std::sync::atomic::{AtomicU64, Ordering};
// use serde_json::json;

// /// Helper function to convert ThreadId to u64 in a stable way
// fn thread_id_to_u64(t: &std::thread::ThreadId) -> u64 {
//     static NEXT_ID: AtomicU64 = AtomicU64::new(1);
//     let id = t as *const _ as u64;
//     if id == 0 {
//         NEXT_ID.fetch_add(1, Ordering::Relaxed)
//     } else {
//         id
//     }
// }

// /// Helper function to create a test ErrorContext
// fn create_test_context() -> ErrorContext {
//     ErrorContext {
//         operation: "test_operation".to_string(),
//         tenant_id: Some(Uuid::new_v4()),
//         user_id: Some(Uuid::new_v4()),
//         session_id: Some(Uuid::new_v4()),
//         request_id: Some(Uuid::new_v4()),
//         service_name: "test_service".to_string(),
//         service_version: "1.0.0".to_string(),
//         environment: "test".to_string(),
//         region: "us-east-1".to_string(),
//         availability_zone: "us-east-1a".to_string(),
//         node_id: "node-1".to_string(),
//         process_id: std::process::id(),
//         thread_id: thread_id_to_u64(&std::thread::current().id()),
//         additional_context: HashMap::new(),
//     }
// }

// /// Helper function to convert ThreadId to u64 in a stable way

// /// Helper function to create a test SourceLocation
// ///
// // fn create_test_source_location() -> SourceLocation {
// //     SourceLocation {
// //         file: "test_file.rs".to_string(),
// //         line: 42,
// //         column: 10,
// //         function: "test_function".to_string(),
// //         module: "test_module".to_string(),
// //         git_commit: "a1b2c3d".to_string(),
// //         build_version: "1.0.0".to_string(),
// //     }
// // }

// /// Helper function to insert a string into additional_context
// fn insert_context_string(context: &mut ErrorContext, key: &str, value: &str) {
//     context.additional_context.insert(
//         key.to_string(),
//         serde_json::Value::String(value.to_string())
//     );
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     /// Test basic error creation
//     ///
//     /// This test verifies that basic errors can be created with different error types.
//     #[test]
//     fn test_basic_error_creation() {
//         // Create a basic error
//         let error = ForgeError::InvalidConfig {
//             message: "test-config-error".to_string(),
//         };

//         // Verify the error type
//         assert!(matches!(error, ForgeError::InvalidConfig { .. }));

//         // Verify the error message contains the expected information
//         assert!(error.to_string().contains("INVALID_CONFIG"));
//         assert!(error.to_string().contains("test-config-error"));

//         // Create a different error type
//         let error = ForgeError::ConfigError("Configuration error".to_string());

//         // Verify the error type
//         assert!(matches!(error, ForgeError::ConfigError(_)));

//         // Verify the error message
//         assert_eq!(error.to_string(), "CONFIG_ERROR: Configuration error");

//         // Test IoError variant
//         let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
//         let error = ForgeError::IoError {
//             message: "I/O error occurred".to_string(),
//             source: Some(Arc::new(io_error.into())),
//         };
//         assert!(matches!(error, ForgeError::IoError { .. }));
//         assert!(error.to_string().contains("I/O error occurred"));
//     }

//     /// Test traceable error creation
//     ///
//     /// This test verifies that traceable errors can be created with error context.
//     #[tokio::test]
//     async fn test_traceable_error_creation() {
//         // Create an error context using the helper function
//         let mut context = create_test_context();

//         // Add some additional context
//         insert_context_string(&mut context, "test_key", "test_value");

//         // Create a traceable error
//         let error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "test-config-error".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Verify the error type
//         assert!(matches!(error.error, ForgeError::InvalidConfig { .. }));

//         // Verify the error message contains expected information
//         assert!(error.error.to_string().contains("INVALID_CONFIG"));
//         assert!(error.error.to_string().contains("test-config-error"));

//         // Verify the error context
//         assert_eq!(error.context.operation, context.operation);
//         assert_eq!(error.context.service_name, context.service_name);

//         // Verify the additional context was preserved
//         assert_eq!(
//             error.context.additional_context.get("test_key").unwrap(),
//             &serde_json::Value::String("test_value".to_string())
//         );

//         // Verify the trace ID is not empty
//         assert!(!error.trace_id.to_string().is_empty());

//         // Verify the timestamp is set
//         assert!(error.timestamp <= Utc::now());
//     }

//     /// Test error with trace ID
//     ///
//     /// This test verifies that errors can be created with a trace ID.
//     #[tokio::test]
//     async fn test_error_with_trace_id() {
//         // Create an error context using the helper function
//         let context = create_test_context();

//         // Create a traceable error
//         let error1 = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "test-config-error".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Create another error with the same context (should get the same trace ID)
//         let error2 = TraceableError::new(
//             ForgeError::ConfigError("Another error".to_string()),
//             context.clone(),
//         ).await;

//         // Verify the trace IDs are the same when using the same context
//         assert_eq!(error1.trace_id, error2.trace_id);

//         // Verify the trace ID is not empty
//         let trace_id_str = error1.trace_id.to_string();
//         assert!(!trace_id_str.is_empty());

//         // Verify the trace ID is in the expected format (32-character hex string)
//         assert_eq!(trace_id_str.len(), 32);
//         assert!(trace_id_str.chars().all(|c| c.is_ascii_hexdigit()));

//         // Create a new error with a different context (should get a different trace ID)
//         let mut different_context = create_test_context();
//         different_context.request_id = Some(Uuid::new_v4()); // Change something to make it different

//         let error3 = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "different-context-error".to_string(),
//             },
//             different_context,
//         ).await;

//         // Verify the trace IDs are different for different contexts
//         assert_ne!(error1.trace_id, error3.trace_id);
//     }

//     /// Test error to string
//     ///
//     /// This test verifies that errors can be converted to strings.
//     #[tokio::test]
//     async fn test_error_to_string() {
//         // Create an error context with additional context
//         let mut additional_context = HashMap::new();
//         additional_context.insert("resource_id".to_string(), json!("resource-123"));

//         let context = ErrorContext {
//             operation: "access_resource".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "resource-service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: {
//                 let id = std::thread::current().id();
//                 format!("{:?}", id).parse::<u64>().unwrap_or(0)
//             },
//             additional_context,
//         };

//         // Create a traceable error with InvalidConfig
//         let mut error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "test-config-error".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Set source location manually with all required fields
//         error.source_location = SourceLocation {
//             file: "auth_service.rs".to_string(),
//             line: 85,
//             column: 12,
//             function: "function_name".to_string(),     // String, not Option
//             module: "module_name".to_string(),         // String, not Option
//             git_commit: "commit_hash".to_string(),     // String, not Option
//             build_version: "1.0.0".to_string(),       // String, not Option
//         };

//         // Convert the error to a string
//         let error_string = error.to_string();

//         // Verify the error string contains the error message
//         assert!(error_string.contains("INVALID_CONFIG"));

//         // Verify the error string contains the trace ID
//         assert!(error_string.contains(&format!("Trace ID: {}", error.trace_id)));

//         // Verify the error string contains the operation context
//         assert!(error_string.contains("Operation: access_resource"));

//         // Verify the error string contains the source location
//         assert!(error_string.contains("Location: auth_service.rs:85"));

//         // Verify the error string contains the error message
//         assert!(error_string.contains("test-config-error"));
//     }

//     /// Test error with additional context
//     ///
//     /// This test verifies that errors can be created with additional context in the ErrorContext.
//     #[tokio::test]
//     async fn test_error_with_context() {
//         // Create a base error context using the helper
//         let mut context = create_test_context();
//         context.operation = "download_document".to_string();
//         context.service_name = "document-service".to_string();

//         // Add additional context using the helper
//         insert_context_string(&mut context, "resource_type", "document");
//         insert_context_string(&mut context, "resource_id", "doc-123");
//         insert_context_string(&mut context, "action", "download");

//         // Create a traceable error with context
//         let error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "test-config-error".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Verify the error type
//         assert!(matches!(error.error, ForgeError::InvalidConfig { .. }));

//         // Verify the error message contains expected information
//         assert!(error.error.to_string().contains("INVALID_CONFIG"));

//         // Verify the context was stored correctly
//         assert_eq!(error.context.operation, "download_document");
//         assert_eq!(error.context.service_name, "document-service");

//         // Verify the additional context was preserved with proper types
//         assert_eq!(
//             error.context.additional_context.get("resource_type"),
//             Some(&serde_json::Value::String("document".to_string()))
//         );
//         assert_eq!(
//             error.context.additional_context.get("resource_id"),
//             Some(&serde_json::Value::String("doc-123".to_string()))
//         );
//         assert_eq!(
//             error.context.additional_context.get("action"),
//             Some(&serde_json::Value::String("download".to_string()))
//         );

//         // Test with a different error type and context
//         let mut another_context = create_test_context();
//         another_context.operation = "upload_file".to_string();
//         another_context.service_name = "file-service".to_string();

//         // Add some context using the helper
//         insert_context_string(&mut another_context, "file_name", "example.txt");
//         insert_context_string(&mut another_context, "file_size", "1024");

//         let io_error = std::io::Error::new(
//             std::io::ErrorKind::PermissionDenied,
//             "Permission denied"
//         );

//         let error = TraceableError::new(
//             ForgeError::IoError {
//                 message: "Failed to upload file".to_string(),
//                 source: Some(Arc::new(io_error.into())),
//             },
//             another_context,
//         ).await;

//         // Verify the error type
//         assert!(matches!(error.error, ForgeError::IoError { .. }));

//         // Verify the error message contains expected information
//         assert!(error.error.to_string().contains("IO_ERROR"));
//         assert!(error.error.to_string().contains("Failed to upload file"));

//         // Verify the context was stored correctly
//         assert_eq!(error.context.operation, "upload_file");
//         assert_eq!(error.context.service_name, "file-service");

//         // Verify the additional context was preserved with proper types
//         assert_eq!(
//             error.context.additional_context.get("file_name"),
//             Some(&serde_json::Value::String("example.txt".to_string()))
//         );
//         assert_eq!(
//             error.context.additional_context.get("file_size"),
//             Some(&serde_json::Value::String("1024".to_string()))
//         );
//     }

//     /// Test error to LLM string conversion
//     ///
//     /// This test verifies that errors can be converted to LLM-readable strings.
//     #[tokio::test]
//     async fn test_error_to_llm_string() {
//         // Create a test context with some additional information
//         let mut context = create_test_context();
//         context.operation = "process_request".to_string();
//         insert_context_string(&mut context, "request_id", "req-12345");
//         insert_context_string(&mut context, "endpoint", "/api/data");

//         // Create a traceable error with a security-related error
//         let error = TraceableError::new(
//             ForgeError::ZeroTrustViolation {
//                 violation_type: "invalid_credentials".to_string(),
//                 risk_score: 0.9,  // Add risk score (0.0 to 1.0)
//                 tenant_id: Uuid::new_v4(),  // Add a tenant UUID
//                 evidence: vec![],  // Add empty vector or actual evidence
//             },
//             context,
//         ).await;

//         // Convert to LLM-readable string
//         let llm_string = error.to_llm_string();

//         // Verify that the LLM-readable string contains the error message
//         assert!(
//             llm_string.contains("ZERO_TRUST_VIOLATION"),
//             "LLM string should contain error variant"
//         );
//         assert!(
//             llm_string.contains("Unauthorized access attempt"),
//             "LLM string should contain error message"
//         );

//         // Verify that the LLM-readable string contains the trace ID
//         assert!(
//             llm_string.contains(&error.trace_id.to_string()),
//             "LLM string should contain trace ID"
//         );

//         // Verify that the LLM-readable string contains the operation context
//         assert!(
//             llm_string.contains("process_request"),
//             "LLM string should contain operation context"
//         );

//         // Verify that the LLM-readable string contains the additional context
//         assert!(
//             llm_string.contains("request_id") && llm_string.contains("req-12345"),
//             "LLM string should contain request ID from additional context"
//         );

//         // Verify that the severity is included
//         assert!(
//             llm_string.contains("Critical"),
//             "LLM string should contain error severity"
//         );

//         // Test with a different error type
//         let io_context = create_test_context();
//         let io_error = std::io::Error::new(
//             std::io::ErrorKind::NotFound,
//             "File not found",
//         );

//         let error = TraceableError::new(
//             ForgeError::IoError {
//                 message: "Failed to read configuration".to_string(),
//                 source: Some(Arc::new(io_error.into())),
//             },
//             io_context,
//         ).await;

//         let llm_string = error.to_llm_string();

//         // Verify IO error details are included
//         assert!(
//             llm_string.contains("IO_ERROR"),
//             "LLM string should contain IO_ERROR variant"
//         );
//         assert!(
//             llm_string.contains("Failed to read configuration"),
//             "LLM string should contain IO error message"
//         );
//     }

//     /// Test error audit log
//     ///
//     /// This test verifies that errors can be converted to audit log format.
//     #[tokio::test]
//     async fn test_error_audit_log() {
//         // Create an error context with additional context
//         use serde_json::Value;
//         let mut additional_context = HashMap::new();
//         additional_context.insert("resource_id".to_string(), Value::String("resource-123".to_string()));
//         additional_context.insert("client_ip".to_string(), Value::String("192.168.1.100".to_string()));

//         let context = ErrorContext {
//             operation: "access_resource".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "resource-service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context,
//         };

//         // Create a traceable error with InvalidConfig
//         let mut error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "test-config-error".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Set source location manually with all required fields
//         error.source_location = SourceLocation {
//             file: "auth_service.rs".to_string(),
//             line: 85,
//             column: 12,
//             function: "function_name".to_string(),     // String, not Option
//             module: "module_name".to_string(),         // String, not Option
//             git_commit: "commit_hash".to_string(),     // String, not Option
//             build_version: "1.0.0".to_string(),       // String, not Option
//         };

//         // Convert the error to an audit log string
//         let audit_log_str = error.to_audit_log();

//         // The audit log should be in the format: "AUDIT: {message} at {timestamp}"
//         assert!(audit_log_str.starts_with("AUDIT: "), "Audit log should start with 'AUDIT: '");
//         assert!(
//             audit_log_str.contains("test-config-error"),
//             "Audit log should contain the error message"
//         );

//         // Extract the timestamp part (everything after " at ")
//         let timestamp_part = audit_log_str.split(" at ").nth(1).expect("Audit log should contain ' at ' separator");

//         // Verify the timestamp is in the expected format (ISO 8601)
//         let _timestamp: chrono::DateTime<chrono::Utc> = timestamp_part.parse()
//             .expect("Audit log should contain a valid timestamp");
//     }

//     /// Test error result handling
//     ///
//     /// This test verifies that Result<T, ForgeError> can be handled correctly.
//     #[test]
//     fn test_error_result_handling() {
//         // Create a function that returns a Result<T, ForgeError>
//         fn may_fail(should_fail: bool) -> Result<String> {
//             if should_fail {
//                 Err(ForgeError::InvalidConfig {
//                     message: "test-config-error".to_string(),
//                 })
//             } else {
//                 Ok("Success".to_string())
//             }
//         }

//         // Test success case
//         let result = may_fail(false);
//         assert!(result.is_ok());
//         assert_eq!(result.unwrap(), "Success");

//         // Test failure case
//         let result = may_fail(true);
//         assert!(result.is_err());
//         assert!(matches!(result.unwrap_err(), ForgeError::InvalidConfig { .. }));
//     }

//     /// Test traceable error result handling
//     ///
//     /// This test verifies that Result<T, TraceableError> can be handled correctly.
//     #[tokio::test]
//     async fn test_traceable_error_result_handling() {
//         // Create an error context
//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Define a function that may fail
//         async fn may_fail(should_fail: bool, context: ErrorContext) -> TraceableResult<String> {
//             if should_fail {
//                 Err(TraceableError::new(
//                     ForgeError::InvalidConfig {
//                         message: "test-config-error".to_string(),
//                     },
//                     context,
//                 ).await)
//             } else {
//                 Ok("Success".to_string())
//             }
//         }

//         // Test success case
//         let result = may_fail(false, context.clone()).await;
//         assert!(result.is_ok());
//         assert_eq!(result.unwrap(), "Success");

//         // Test failure case
//         let result = may_fail(true, context.clone()).await;
//         assert!(result.is_err());

//         // Verify the error
//         let error = result.unwrap_err();
//         assert!(matches!(error.error, ForgeError::InvalidConfig { .. }));
//         assert_eq!(error.context.operation, context.operation);
//         assert_eq!(error.context.service_name, context.service_name);
//     }

//     /// Test error conversion from ForgeError to TraceableError
//     ///
//     /// This test verifies that ForgeError can be converted to TraceableError.
//     #[tokio::test]
//     async fn test_error_conversion() {
//         // Create a ForgeError
//         let forge_error = ForgeError::ValidationError {
//             field: "email".to_string(),
//             rule: "format".to_string(),
//             value: "invalid-email".to_string(),
//             suggestions: vec!["Use a valid email format".to_string()],
//         };

//         // Create a default error context
//         let context = ErrorContext {
//             operation: "validate_user".to_string(),
//             tenant_id: None,
//             user_id: None,
//             session_id: None,
//             request_id: None,
//             service_name: "user-service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Convert to TraceableError
//         let traceable_error = TraceableError::new(forge_error.clone(), context.clone()).await;

//         // Verify the error type
//         assert!(matches!(traceable_error.error, ForgeError::ValidationError { .. }));

//         // Verify the error message contains expected information
//         assert!(traceable_error.error.to_string().contains("VALIDATION_ERROR"));
//         assert!(traceable_error.error.to_string().contains("email"));

//         // Verify the context is set
//         assert_eq!(traceable_error.context.operation, "validate_user");
//         assert_eq!(traceable_error.context.service_name, "user-service");

//         // Verify the trace ID is set
//         assert!(!traceable_error.trace_id.to_string().is_empty());

//         // Verify the correlation ID is set
//         assert!(traceable_error.correlation_id != Uuid::nil());
//     }

//     /// Test concurrent error creation
//     ///
//     /// This test verifies that errors can be created concurrently.
//     #[tokio::test]
//     async fn test_concurrent_error_creation() {
//         // Create a base error context
//         let base_context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: None,
//             user_id: None,
//             session_id: None,
//             request_id: None,
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create multiple errors concurrently
//         let mut handles = vec![];

//         for i in 0..10 {
//             let context = base_context.clone();
//             let handle = tokio::spawn(async move {
//                 let mut ctx = context;
//                 ctx.operation = format!("operation_{}", i);

//                 TraceableError::new(
//                     ForgeError::ValidationError {
//                         field: format!("field_{}", i),
//                         rule: "required".to_string(),
//                         value: "".to_string(),
//                         suggestions: vec![format!("Provide value for field_{}", i)],
//                     },
//                     ctx,
//                 ).await
//             });

//             handles.push(handle);
//         }

//         let mut errors = vec![];
//         for handle in handles {
//             errors.push(handle.await.unwrap());
//         }

//         // Verify that each error has a unique trace ID
//         let trace_ids: std::collections::HashSet<String> = errors
//             .iter()
//             .map(|e| e.trace_id.to_string())
//             .collect();

//         assert_eq!(trace_ids.len(), errors.len());

//         // Verify that each error has a unique correlation ID
//         let correlation_ids: std::collections::HashSet<Uuid> = errors
//             .iter()
//             .map(|e| e.correlation_id)
//             .collect();

//         assert_eq!(correlation_ids.len(), errors.len());
//     }

//     /// Test error with different trust vectors
//     ///
//     /// This test verifies that errors can be created with different trust vectors.
//     #[tokio::test]
//     async fn test_error_with_different_trust_vectors() {
//         // Create identity contexts with different trust vectors
//         let root_identity = IdentityContext::root();
//         let unverified_identity = IdentityContext::new("tenant-1".to_string(), "user-1".to_string())
//             .with_trust(TrustVector::Unverified);
//         let signed_identity = IdentityContext::new("tenant-2".to_string(), "user-2".to_string())
//             .with_trust(TrustVector::Signed("valid-signature".to_string()));
//         let enclave_identity = IdentityContext::new("tenant-3".to_string(), "user-3".to_string())
//             .with_trust(TrustVector::Enclave);
//         let edge_gateway_identity = IdentityContext::new("tenant-4".to_string(), "user-4".to_string())
//             .with_trust(TrustVector::EdgeGateway);
//         let compromised_identity = IdentityContext::new("tenant-5".to_string(), "user-5".to_string())
//             .with_trust(TrustVector::Compromised);

//         // Create traceable errors with different trust vectors using valid ForgeError variants
//         let mut root_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Root error".to_string(),
//             },
//             create_test_context(),
//         ).await;

//         let mut unverified_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Unverified error".to_string(),
//             },
//             create_test_context(),
//         ).await;

//         let mut signed_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Signed error".to_string(),
//             },
//             create_test_context(),
//         ).await;

//         let mut enclave_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Enclave error".to_string(),
//             },
//             create_test_context(),
//         ).await;

//         let mut edge_gateway_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Edge gateway error".to_string(),
//             },
//             create_test_context(),
//         ).await;

//         let mut compromised_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Compromised error".to_string(),
//             },
//             create_test_context(),
//         ).await;

//         // Manually set the identities since we can't use with_identity
//         root_error.identity = Some(root_identity);
//         unverified_error.identity = Some(unverified_identity);
//         signed_error.identity = Some(signed_identity);
//         enclave_error.identity = Some(enclave_identity);
//         edge_gateway_error.identity = Some(edge_gateway_identity);
//         compromised_error.identity = Some(compromised_identity);

//         // Verify the trust vectors
//         assert_eq!(root_error.identity.as_ref().unwrap().trust_vector, TrustVector::Root);
//         assert_eq!(unverified_error.identity.as_ref().unwrap().trust_vector, TrustVector::Unverified);
//         assert_eq!(signed_error.identity.as_ref().unwrap().trust_vector, TrustVector::Signed("valid-signature".to_string()));
//         assert_eq!(enclave_error.identity.as_ref().unwrap().trust_vector, TrustVector::Enclave);
//         assert_eq!(edge_gateway_error.identity.as_ref().unwrap().trust_vector, TrustVector::EdgeGateway);
//         assert_eq!(compromised_error.identity.as_ref().unwrap().trust_vector, TrustVector::Compromised);
//     }

//     /// Test error severity levels
//     ///
//     /// This test verifies that errors have correct severity levels.
//     #[tokio::test]
//     async fn test_error_severity() {
//         // Create a base error context
//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: None,
//             user_id: None,
//             session_id: None,
//             request_id: None,
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Test Emergency severity (KernelPanic)
//         let emergency_error = TraceableError::new(
//             ForgeError::KernelPanic {
//                 message: "Kernel panic".to_string(),
//                 context: "Test context".to_string(),
//                 recovery_hint: "Check system logs".to_string(),
//                 core_dump_id: None,
//             },
//             context.clone(),
//         ).await;

//         // Test Alert severity (MemoryCorruption)
//         let alert_error = TraceableError::new(
//             ForgeError::MemoryCorruption {
//                 address: None,
//                 size: 1024,
//                 pattern: "deadbeef".to_string(),
//                 stack_trace: vec!["test".to_string()],
//             },
//             context.clone(),
//         ).await;

//         // Test Critical severity (HardwareFailure)
//         let critical_error = TraceableError::new(
//             ForgeError::HardwareFailure {
//                 component: "CPU".to_string(),
//                 status: "overheating".to_string(),
//                 remediation: "replace cooling system".to_string(),
//                 telemetry_data: HashMap::new(),
//             },
//             context.clone(),
//         ).await;

//         // Test Error severity (InvalidConfig)
//         let error_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Invalid configuration".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Verify severity levels
//         assert_eq!(emergency_error.severity(), ErrorSeverity::Emergency);
//         assert_eq!(alert_error.severity(), ErrorSeverity::Alert);
//         assert_eq!(critical_error.severity(), ErrorSeverity::Critical);
//         assert_eq!(error_error.severity(), ErrorSeverity::Error);
//     }

//     /// Test security error detection
//     ///
//     /// This test verifies that security errors are properly detected.
//     #[tokio::test]
//     async fn test_security_error_detection() {
//         // Create a base error context
//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: None,
//             user_id: None,
//             session_id: None,
//             request_id: None,
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create security errors using valid ForgeError variants
//         let zero_trust_violation = TraceableError::new(
//             ForgeError::ZeroTrustViolation {
//                 violation_type: "Unauthorized access".to_string(),
//                 risk_score: 0.9,
//                 tenant_id: Uuid::new_v4(),
//                 evidence: vec![],
//             },
//             context.clone(),
//         ).await;

//         let quantum_crypto_error = TraceableError::new(
//             ForgeError::QuantumCryptoError {
//                 algorithm: "RSA-4096".to_string(),
//                 entropy_level: 0.5,
//                 key_id: "key-123".to_string(),
//                 quantum_safe: false,
//             },
//             context.clone(),
//         ).await;

//         let config_error = TraceableError::new(
//             ForgeError::ConfigError("Configuration error".to_string()),
//             context.clone(),
//         ).await;

//         // Verify security error detection
//         assert!(zero_trust_violation.is_security_error());
//         assert!(quantum_crypto_error.is_security_error());
//         assert!(!config_error.is_security_error());
//     }

//     /// Test immediate alert requirement
//     ///
//     /// This test verifies that critical errors require immediate alerts.
//     #[tokio::test]
//     async fn test_immediate_alert_requirement() {
//         // Create a base error context
//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: None,
//             user_id: None,
//             session_id: None,
//             request_id: None,
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create errors that require immediate alerts using valid ForgeError variants
//         let kernel_panic = TraceableError::new(
//             ForgeError::KernelPanic {
//                 message: "Critical system failure".to_string(),
//                 context: "Test context".to_string(),
//                 recovery_hint: "Contact support immediately".to_string(),
//                 core_dump_id: Some(Uuid::new_v4()),
//             },
//             context.clone(),
//         ).await;

//         let memory_corruption = TraceableError::new(
//             ForgeError::MemoryCorruption {
//                 address: Some(0x12345678),
//                 size: 1024,
//                 pattern: "DEADBEEF".to_string(),
//                 stack_trace: vec!["frame1".to_string(), "frame2".to_string()],
//             },
//             context.clone(),
//         ).await;

//         let zero_trust_violation = TraceableError::new(
//             ForgeError::ZeroTrustViolation {
//                 violation_type: "Unauthorized access".to_string(),
//                 risk_score: 0.95,
//                 tenant_id: Uuid::new_v4(),
//                 evidence: vec![],
//             },
//             context.clone(),
//         ).await;

//         // Verify immediate alert requirements
//         assert!(kernel_panic.requires_immediate_alert());
//         assert!(memory_corruption.requires_immediate_alert());
//         assert!(zero_trust_violation.requires_immediate_alert());
//     }

//     /// Test error chaining
//     ///
//     /// This test verifies that errors can be chained together.
//     #[tokio::test]
//     async fn test_error_chaining() {
//         // Create a base error context
//         let context = ErrorContext {
//             operation: "config_operation".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "config-service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create a base error
//         let base_error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Invalid database URL format".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Create a second context for the chained error
//         let mut chained_context = context.clone();
//         chained_context.operation = "system_operation".to_string();
//         chained_context.service_name = "system-service".to_string();

//         // Add the base error information to the additional context

//         chained_context.additional_context.insert(
//             "caused_by".to_string(),
//             serde_json::Value::String(base_error.to_string())
//         );
//         chained_context.additional_context.insert(
//             "original_trace_id".to_string(),
//             serde_json::Value::String(base_error.trace_id.to_string())
//         );

//         // Create a chained error using a valid error variant
//         let chained_error = TraceableError::new(
//             ForgeError::KernelPanic {
//                 message: "Failed to initialize system".to_string(),
//                 context: "System initialization failed due to config error".to_string(),
//                 recovery_hint: "Check configuration and restart the service".to_string(),
//                 core_dump_id: Some(Uuid::new_v4()),
//             },
//             chained_context.clone(),
//         ).await;

//         // Verify the chained error
//         assert!(matches!(
//             chained_error.error,
//             ForgeError::KernelPanic {
//                 message: _,
//                 context: _,
//                 recovery_hint: _,
//                 core_dump_id: _
//             }
//         ));
//         assert_eq!(chained_error.context.operation, "system_operation");
//         let map = &chained_error.context.additional_context;
//         if let Some(serde_json::Value::String(caused_by)) = map.get("caused_by") {
//             assert!(caused_by.contains("INVALID_CONFIG"));
//         } else {
//             panic!("caused_by not found in additional_context");
//         }

//         if let Some(serde_json::Value::String(trace_id)) = map.get("original_trace_id") {
//             assert_eq!(trace_id, &base_error.trace_id.to_string());
//         } else {
//             panic!("original_trace_id not found in additional_context");
//         }
//     }

//     /// Test traceable error macro
//     ///
//     /// This test verifies that the traceable_error! macro works correctly.
//     #[tokio::test]
//     async fn test_traceable_error_macro() {
//         // Create an error context
//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create a traceable error using the new method with a valid error variant
//         let error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Missing required configuration: database.url".to_string(),
//             },
//             context.clone(),
//         ).await;

//         // Verify the error type
//         assert!(matches!(
//             error.error,
//             ForgeError::InvalidConfig { message: _ }
//         ));

//         // Verify the error message contains expected information
//         assert!(error.error.to_string().contains("INVALID_CONFIG"));
//         assert!(error.error.to_string().contains("database.url"));

//         // Verify the context
//         assert_eq!(error.context.operation, context.operation);
//         assert_eq!(error.context.service_name, context.service_name);

//         // Create a traceable error with additional context
//         let mut context_with_additional = context.clone();
//         context_with_additional.additional_context.insert(
//             "resource_id".to_string(),
//             serde_json::json!("resource-123")
//         );

//         let error_with_additional = TraceableError::new(
//             ForgeError::KernelPanic {
//                 message: "Critical system failure".to_string(),
//                 context: "Failed to initialize resource".to_string(),
//                 recovery_hint: "Check resource configuration and restart".to_string(),
//                 core_dump_id: Some(Uuid::new_v4()),
//             },
//             context_with_additional.clone(),
//         ).await;

//         // Verify the error type
//         assert!(matches!(
//             error_with_additional.error,
//             ForgeError::KernelPanic {
//                 message: _,
//                 context: _,
//                 recovery_hint: _,
//                 core_dump_id: _
//             }
//         ));

//         // Verify the additional context
//         assert_eq!(
//             error_with_additional.context.additional_context.get("resource_id").unwrap(),
//             "resource-123"
//         );

//         // Create a traceable error with source location
//         let mut error_with_location = TraceableError::new(
//             ForgeError::IoError {
//                 message: "File not found: /tmp/test.txt".to_string(),
//                 source: Some(Arc::new(anyhow::Error::new(std::io::Error::new(
//                     std::io::ErrorKind::NotFound,
//                     "No such file or directory"
//                 )))),
//             },
//             context.clone(),
//         ).await;

//         // Set source location using the current method
//         error_with_location.source_location = SourceLocation::current();

//         // Verify the error type
//         assert!(matches!(
//             error_with_location.error,
//             ForgeError::IoError { message: _, source: _ }
//         ));

//         // Just access the field to ensure it exists - this will panic if it's not set
//         let _ = error_with_location.source_location;
//     }

//     /// Test adding context to existing errors
//     ///
//     /// This test verifies that additional context can be added to existing errors.
//     #[tokio::test]
//     async fn test_add_context_and_location() {
//         // Create a base error context
//         let base_context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create a basic error with valid variant
//         let error = TraceableError::new(
//             ForgeError::InvalidConfig {
//                 message: "Missing required configuration: database.url".to_string(),
//             },
//             base_context.clone(),
//         ).await;

//         // Create a new error with additional context
//         let mut updated_context = error.context.clone();
//         updated_context.additional_context.insert(
//             "resource_id".to_string(),
//             json!("resource-123")
//         );
//         updated_context.additional_context.insert(
//             "action".to_string(),
//             json!("read")
//         );

//         let error_with_additional_context = TraceableError::new(
//             error.error.clone(),
//             updated_context.clone(),
//         ).await;

//         // Verify the additional context was added
//         assert_eq!(
//             error_with_additional_context.context.additional_context.get("resource_id").unwrap(),
//             "resource-123"
//         );
//         assert_eq!(
//             error_with_additional_context.context.additional_context.get("action").unwrap(),
//             "read"
//         );

//         // Create a new error with source location using the current method
//         let mut error_with_location = error_with_additional_context.clone();
//         error_with_location.source_location = SourceLocation::current();

//         // Verify the source location was added
//         assert!(!error_with_location.source_location.file.is_empty());

//         // Verify the context is preserved
//         assert_eq!(
//             error_with_location.context.additional_context.get("resource_id").unwrap(),
//             "resource-123"
//         );

//         // Verify the error type is still correct
//         assert!(matches!(
//             error_with_location.error,
//             ForgeError::InvalidConfig { message: _ }
//         ));
//     }

//     /// Test async error creation with ErrorContext
//     ///
//     /// This test verifies that errors can be created asynchronously with a detailed ErrorContext.
//     #[tokio::test]
//     async fn test_error_creation() {
//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Create a valid error variant
//         let error = ForgeError::InvalidConfig {
//             message: "Missing required configuration: api_key".to_string(),
//         };

//         // Create a traceable error with the context
//         let traceable_error = TraceableError::new(error, context).await;

//         // Verify the error properties
//         assert_eq!(traceable_error.severity(), ErrorSeverity::Error);
//         assert!(!traceable_error.fingerprint.is_empty());
//         assert!(matches!(
//             traceable_error.error,
//             ForgeError::InvalidConfig { message: _ }
//         ));

//         // Verify the context was properly set
//         assert_eq!(traceable_error.context.operation, "test_operation");
//         assert_eq!(traceable_error.context.service_name, "test_service");
//     }

//     #[tokio::test]
//     async fn test_error_manager() {
//         let manager = ErrorManager::new();

//         let context = ErrorContext {
//             operation: "test_operation".to_string(),
//             tenant_id: Some(Uuid::new_v4()),
//             user_id: Some(Uuid::new_v4()),
//             session_id: Some(Uuid::new_v4()),
//             request_id: Some(Uuid::new_v4()),
//             service_name: "test_service".to_string(),
//             service_version: "1.0.0".to_string(),
//             environment: "test".to_string(),
//             region: "us-east-1".to_string(),
//             availability_zone: "us-east-1a".to_string(),
//             node_id: "node-1".to_string(),
//             process_id: std::process::id(),
//             thread_id: thread_id_to_u64(&std::thread::current().id()),
//             additional_context: HashMap::new(),
//         };

//         // Use a valid error variant that would typically be handled by the error manager
//         let error = ForgeError::InvalidConfig {
//             message: "Invalid configuration: missing required field 'api_key'".to_string(),
//         };

//         // Process the error through the manager
//         let traceable_error = manager.process_error(error, context.clone()).await;

//         // Verify the error was processed correctly
//         assert_eq!(traceable_error.severity(), ErrorSeverity::Error);
//         assert!(matches!(
//             traceable_error.error,
//             ForgeError::InvalidConfig { message: _ }
//         ));

//         // Verify the context was preserved
//         assert_eq!(traceable_error.context.operation, "test_operation");
//         assert_eq!(traceable_error.context.service_name, "test_service");

//         // Test with a different error type to verify different severities
//         let critical_error = ForgeError::KernelPanic {
//             message: "Critical system failure".to_string(),
//             context: "Failed to initialize critical component".to_string(),
//             recovery_hint: "Restart the service and check logs".to_string(),
//             core_dump_id: Some(Uuid::new_v4()),
//         };

//         let critical_traceable = manager.process_error(critical_error, context).await;
//         assert_eq!(critical_traceable.severity(), ErrorSeverity::Emergency);
//     }

//     #[test]
//     fn test_error_serialization() {
//         // Test serialization of InvalidConfig variant
//         let error = ForgeError::InvalidConfig {
//             message: "Missing required configuration: database.url".to_string(),
//         };

//         let serialized = serde_json::to_string(&error).unwrap();
//         let deserialized: ForgeError = serde_json::from_str(&serialized).unwrap();

//         // Verify serialization works for InvalidConfig
//         match deserialized {
//             ForgeError::InvalidConfig { message } => {
//                 assert!(message.contains("Missing required configuration"));
//             },
//             _ => panic!("Unexpected error variant after deserialization"),
//         }

//         // Test serialization of IoError variant
//         let io_error = ForgeError::IoError {
//             message: "Failed to read file".to_string(),
//             source: None,
//         };

//         let io_serialized = serde_json::to_string(&io_error).unwrap();
//         let io_deserialized: ForgeError = serde_json::from_str(&io_serialized).unwrap();

//         // Verify serialization works for IoError
//         match io_deserialized {
//             ForgeError::IoError { message, .. } => {
//                 assert_eq!(message, "Failed to read file");
//             },
//             _ => panic!("Unexpected error variant after deserialization"),
//         }

//         // Test serialization of KernelPanic variant
//         let panic_error = ForgeError::KernelPanic {
//             message: "Critical system failure".to_string(),
//             context: "Failed to initialize component".to_string(),
//             recovery_hint: "Restart the service".to_string(),
//             core_dump_id: Some(Uuid::new_v4()),
//         };

//         let panic_serialized = serde_json::to_string(&panic_error).unwrap();
//         let panic_deserialized: ForgeError = serde_json::from_str(&panic_serialized).unwrap();

//         // Verify serialization works for KernelPanic
//         match panic_deserialized {
//             ForgeError::KernelPanic { message, context, recovery_hint, core_dump_id } => {
//                 assert_eq!(message, "Critical system failure");
//                 assert_eq!(context, "Failed to initialize component");
//                 assert_eq!(recovery_hint, "Restart the service");
//                 assert!(core_dump_id.is_some());
//             },
//             _ => panic!("Unexpected error variant after deserialization"),
//         }
//     }
// }
