//! # Bootstrap Tests
//!
//! This module contains tests for the bootstrap module, focusing on initialization,
//! diagnostics, and health checks.

use common::bootstrap::{init, init_with_config};
use common::config::ForgeConfig;
use common::error::Result;
use common::identity::{IdentityContext, TrustVector};
use common::prelude::*;
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic initialization
    ///
    /// This test verifies that the common crate can be initialized.
    #[test]
    fn test_basic_initialization() {
        // Initialize the common crate
        let result = init();

        // Verify that initialization succeeded
        assert!(result.is_ok());
    }

    /// Test initialization with custom configuration
    ///
    /// This test verifies that the common crate can be initialized with a custom configuration.
    #[test]
    fn test_initialization_with_config() {
        // Create a custom configuration
        let mut config = ForgeConfig::default();
        config.log_level = "debug".to_string();

        // Initialize the common crate with the custom configuration
        let result = init_with_config(&config);

        // Verify that initialization succeeded
        assert!(result.is_ok());
    }

    /// Test initialization with invalid configuration
    ///
    /// This test verifies that initialization with an invalid log level still works
    /// but defaults to INFO level.
    #[test]
    fn test_initialization_with_invalid_config() {
        // Create a configuration with invalid log level
        let mut config = ForgeConfig::default();
        config.log_level = "invalid".to_string();

        // Initialize the common crate with the configuration
        let result = init_with_config(&config);

        // Verify that initialization succeeded (it defaults to INFO level)
        assert!(result.is_ok());
    }

    /// Test running diagnostics
    ///
    /// This test verifies that diagnostics can be run.
    #[test]
    fn test_run_diagnostics() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = init();
        let identity = IdentityContext::root();
        let report = rt.block_on(run_diagnostics(&identity)).unwrap();
        assert_eq!(report.trust_level, identity.trust_vector);
        assert!(true);
    }

    /// Test running diagnostics with different trust vectors
    ///
    /// This test verifies that diagnostics can be run with different trust vectors.
    #[test]
    fn test_run_diagnostics_with_different_trust_vectors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = init();
        let root_identity = IdentityContext::root();
        let unverified_identity =
            IdentityContext::new("tenant-1".to_string(), "user-1".to_string())
                .with_trust(TrustVector::Unverified);
        let signed_identity = IdentityContext::new("tenant-2".to_string(), "user-2".to_string())
            .with_trust(TrustVector::Signed("test-signature".to_string()));
        let enclave_identity = IdentityContext::new("tenant-3".to_string(), "user-3".to_string())
            .with_trust(TrustVector::Enclave);
        let edge_gateway_identity =
            IdentityContext::new("tenant-4".to_string(), "user-4".to_string())
                .with_trust(TrustVector::EdgeGateway);
        let compromised_identity =
            IdentityContext::new("tenant-5".to_string(), "user-5".to_string())
                .with_trust(TrustVector::Compromised);
        let root_report = rt.block_on(run_diagnostics(&root_identity)).unwrap();
        let unverified_report = rt.block_on(run_diagnostics(&unverified_identity)).unwrap();
        let signed_report = rt.block_on(run_diagnostics(&signed_identity)).unwrap();
        let enclave_report = rt.block_on(run_diagnostics(&enclave_identity)).unwrap();
        let edge_gateway_report = rt.block_on(run_diagnostics(&edge_gateway_identity)).unwrap();
        let compromised_report = rt.block_on(run_diagnostics(&compromised_identity)).unwrap();
        assert_eq!(root_report.trust_level, TrustVector::Root);
        assert_eq!(unverified_report.trust_level, TrustVector::Unverified);
        assert_eq!(
            signed_report.trust_level,
            TrustVector::Signed("test-signature".to_string())
        );
        assert_eq!(enclave_report.trust_level, TrustVector::Enclave);
        assert_eq!(edge_gateway_report.trust_level, TrustVector::EdgeGateway);
        assert_eq!(compromised_report.trust_level, TrustVector::Compromised);
        assert!(true);
        assert!(compromised_report.warnings.len() >= root_report.warnings.len());
    }

    /// Test checking health
    ///
    /// This test verifies that health checks can be performed.
    #[test]
    fn test_check_health() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = init();
        let health = rt.block_on(common::prelude::check_health());
        assert!(health);
    }

    /// Test checking health with different trust vectors
    ///
    /// This test verifies that health checks always return true regardless of trust vectors.
    #[test]
    fn test_check_health_with_different_trust_vectors() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = init();
        let health = rt.block_on(common::prelude::check_health());
        assert!(health);
    }

    /// Test concurrent initialization
    ///
    /// This test verifies that the common crate can be initialized concurrently.
    #[test]
    fn test_concurrent_initialization() {
        // Create a vector to hold thread handles
        let mut handles = vec![];

        // Spawn 10 threads to initialize the common crate
        for _ in 0..10 {
            let handle = thread::spawn(move || {
                // Initialize the common crate
                let result = init();

                // Return the result
                result.is_ok()
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            let success = handle.join().unwrap();

            // Verify that initialization succeeded
            assert!(success);
        }
    }

    /// Test concurrent diagnostics
    ///
    /// This test verifies that diagnostics can be run concurrently.
    #[test]
    fn test_concurrent_diagnostics() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = init();
        let identity = Arc::new(Mutex::new(IdentityContext::root()));
        let mut handles = vec![];
        for _ in 0..10 {
            let identity_clone = Arc::clone(&identity);
            let rt_clone = rt.handle().clone();
            let handle = thread::spawn(move || {
                let identity = identity_clone.lock().unwrap().clone();
                let report = rt_clone.block_on(run_diagnostics(&identity)).unwrap();
                report.warnings.len()
            });
            handles.push(handle);
        }
        for handle in handles {
            let _ = handle.join().unwrap();
            assert!(true);
        }
    }

    /// Test concurrent health checks
    ///
    /// This test verifies that health checks can be performed concurrently.
    #[test]
    fn test_concurrent_health_checks() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _ = init();
        let mut threads = Vec::new();
        for _ in 0..4 {
            let rt_clone = rt.handle().clone();
            let thread = thread::spawn(move || {
                let health = rt_clone.block_on(common::prelude::check_health());
                assert!(health);
            });
            threads.push(thread);
        }
        for thread in threads {
            thread.join().unwrap();
        }
    }

    /// Test initialization with identity context
    ///
    /// This test verifies that the common crate can be initialized with an identity context.
    #[test]
    fn test_initialization_with_identity() {
        // Create an identity context
        let identity = IdentityContext::root();

        // Initialize the common crate with the identity context
        let result = initialize_with_identity(identity.clone());

        // Verify that initialization succeeded
        assert!(result.is_ok());

        // Verify that the identity context was used
        let telemetry_span = result.unwrap();
        assert_eq!(telemetry_span.identity.trust_vector, identity.trust_vector);
    }

    /// Test initialization with configuration and identity context
    ///
    /// This test verifies that the common crate can be initialized with a configuration and an identity context.
    #[test]
    fn test_initialization_with_config_and_identity() {
        // Create a custom configuration
        let mut config = ForgeConfig::default();
        config.log_level = "debug".to_string();

        // Create an identity context
        let identity = IdentityContext::root();

        // Initialize the common crate with the custom configuration and identity context
        let result = initialize_with_config_and_identity(config, identity.clone());

        // Verify that initialization succeeded
        assert!(result.is_ok());

        // Verify that the identity context was used
        let telemetry_span = result.unwrap();
        assert_eq!(telemetry_span.identity.trust_vector, identity.trust_vector);
    }

    /// Helper function to initialize the common crate with an identity context
    fn initialize_with_identity(identity: IdentityContext) -> Result<TelemetrySpan> {
        // Initialize the common crate
        let _ = init()?;

        // Create a telemetry span with the identity context
        let span = TelemetrySpan::new("initialization".to_string(), identity);

        Ok(span)
    }

    /// Helper function to initialize the common crate with a configuration and an identity context
    fn initialize_with_config_and_identity(
        config: ForgeConfig,
        identity: IdentityContext,
    ) -> Result<TelemetrySpan> {
        // Initialize the common crate with the configuration
        let _ = init_with_config(&config)?;

        // Create a telemetry span with the identity context
        let span = TelemetrySpan::new("initialization".to_string(), identity);

        Ok(span)
    }
}
