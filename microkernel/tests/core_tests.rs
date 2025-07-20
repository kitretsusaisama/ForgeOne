//! Tests for core (boot, runtime, scheduler) of the ForgeOne Microkernel

use common::identity::IdentityContext;
use microkernel::config::runtime::RuntimeConfig;
use microkernel::core::{self, boot, runtime, scheduler};

#[test]
fn test_boot_init_and_shutdown() {
    // Test default boot
    let ctx = boot::init().expect("Boot init should succeed");
    assert_eq!(ctx.boot_mode, boot::BootMode::Normal);
    // Test shutdown
    boot::shutdown().expect("Boot shutdown should succeed");
}

#[test]
fn test_boot_init_with_custom_config() {
    let config = RuntimeConfig::default();
    let ctx = boot::init_with_config(&config).expect("Boot init with config should succeed");
    assert_eq!(ctx.boot_mode, boot::BootMode::Normal);
}

#[test]
fn test_trust_anchor_verification() {
    let ctx = boot::init().unwrap();
    assert!(boot::verify_trust_anchor(&ctx.trust_anchor).unwrap());
}

#[test]
fn test_runtime_init_and_shutdown() {
    let ctx = boot::init().unwrap();
    runtime::init(&ctx).expect("Runtime init should succeed");
    runtime::shutdown().expect("Runtime shutdown should succeed");
}

#[test]
fn test_runtime_error_on_uninitialized() {
    // Should error if runtime context is not initialized
    let result = runtime::get_runtime_context();
    assert!(result.is_err());
}

#[test]
fn test_scheduler_init_and_shutdown() {
    let ctx = boot::init().unwrap();
    scheduler::init(&ctx).expect("Scheduler init should succeed");
    scheduler::shutdown().expect("Scheduler shutdown should succeed");
}

#[test]
fn test_scheduler_scheduling() {
    let ctx = boot::init().unwrap();
    scheduler::init(&ctx).unwrap();
    let container_id = uuid::Uuid::new_v4();
    scheduler::schedule(&container_id, scheduler::Priority::Normal).unwrap();
    scheduler::unschedule(&container_id).unwrap();
}
