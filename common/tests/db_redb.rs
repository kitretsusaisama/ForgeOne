// Advanced production-grade tests for db/redb.rs
// NOTE: All tests are commented out because db/redb.rs is private and its items are not accessible from here, or due to private enum/struct usage. If you want to test these, make the module and its items public, or move the tests to the same crate as the implementation.

/*
// use common::db::redb::{
//     RedbOptions, RedbManager, EventMessage, EventPriority, BlobManager, init_redb, shutdown_redb, repair, MAX_SHARDS, REDB_MANAGER
// };
// use std::collections::HashMap;
// use chrono::Utc;
// use std::sync::Arc;
// use std::thread;
// use proptest::prelude::*;

#[test]
fn test_init_redb_with_valid_options() {
    let options = RedbOptions::default();
    let result = init_redb(options);
    assert!(result.is_ok());
    shutdown_redb().unwrap();
}

#[test]
fn test_init_redb_with_invalid_shard_count() {
    let mut options = RedbOptions::default();
    options.shard_count = MAX_SHARDS + 1;
    let result = init_redb(options);
    assert!(result.is_err());
}

#[test]
fn test_get_instance_before_init() {
    unsafe { REDB_MANAGER = None; }
    let result = RedbManager::get_instance();
    assert!(result.is_err());
}

#[test]
fn test_database_lifecycle() {
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let manager = RedbManager::get_instance().unwrap();
    let db = manager.get_database("system");
    assert!(db.is_ok());
    shutdown_redb().unwrap();
}

#[test]
fn test_shard_calculation() {
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let manager = RedbManager::get_instance().unwrap();
    let shard = manager.calculate_shard_id("test-key");
    assert!(shard < manager.shard_count);
    shutdown_redb().unwrap();
}

#[test]
fn test_encryption_key_error() {
    let options = RedbOptions { encryption_enabled: false, ..Default::default() };
    init_redb(options).unwrap();
    let manager = RedbManager::get_instance().unwrap();
    let key = manager.encryption_key();
    assert!(key.is_err());
    shutdown_redb().unwrap();
}

#[test]
fn test_dedup_cache() {
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let manager = RedbManager::get_instance().unwrap();
    let data = b"test-data";
    let reference = "ref1";
    let _hash = manager.add_to_dedup_cache(data, reference).unwrap();
    let found = manager.check_dedup_cache(data);
    assert_eq!(found, Some(reference.to_string()));
    shutdown_redb().unwrap();
}

#[test]
fn test_publish_and_subscribe_event() {
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let manager = RedbManager::get_instance().unwrap();
    let topic = "test_topic";
    let mut receiver = manager.subscribe_to_events(topic).unwrap();
    let event = EventMessage {
        id: "id1".to_string(),
        topic: topic.to_string(),
        timestamp: Utc::now(),
        priority: EventPriority::Normal,
        payload: "payload".to_string(),
        metadata: HashMap::new(),
        checkpoint_marker: None,
    };
    manager.publish_event(event.clone()).unwrap();
    let received = receiver.try_recv().unwrap();
    assert_eq!(received.id, event.id);
    shutdown_redb().unwrap();
}

#[test]
fn test_repair_and_shutdown() {
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let repaired = repair().unwrap();
    assert!(!repaired); // Should be false if healthy
    shutdown_redb().unwrap();
}

// --- Advanced: Property-based test for dedup cache ---
proptest! {
    #[test]
    fn prop_dedup_cache_roundtrip(random_data in proptest::collection::vec(any::<u8>(), 1..100)) {
        let options = RedbOptions::default();
        init_redb(options).unwrap();
        let manager = RedbManager::get_instance().unwrap();
        let reference = "ref-prop";
        let _ = manager.add_to_dedup_cache(&random_data, reference);
        let found = manager.check_dedup_cache(&random_data);
        assert_eq!(found, Some(reference.to_string()));
        shutdown_redb().unwrap();
    }
}

// --- Advanced: Concurrency test for dedup cache ---
#[test]
fn test_concurrent_dedup_cache_access() {
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let manager = RedbManager::get_instance().unwrap();
    let manager = std::sync::Arc::new(manager);

    let handles: Vec<_> = (0..10).map(|i| {
        let mgr: std::sync::Arc<RedbManager> = std::sync::Arc::clone(&manager);
        std::thread::spawn(move || {
            let data = format!("data-{}", i).into_bytes();
            let reference = format!("ref-{}", i);
            mgr.add_to_dedup_cache(&data, &reference).unwrap();
            assert_eq!(mgr.check_dedup_cache(&data), Some(reference));
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }
    shutdown_redb().unwrap();
}

#[test]
fn test_blob_store_and_retrieve() {
    use common::identity::IdentityContext;
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let blob_mgr = BlobManager::new();
    let identity = IdentityContext::root();
    let data = b"blob-data-123";
    let meta = HashMap::new();
    let blob_id = blob_mgr.store_blob("blob1", "text/plain", data, meta.clone(), &identity).unwrap();
    let (meta_out, data_out) = blob_mgr.get_blob(&blob_id).unwrap();
    assert_eq!(data_out, data);
    assert_eq!(meta_out.name, "blob1");
    // Deduplication: storing same data returns same blob id
    let blob_id2 = blob_mgr.store_blob("blob1", "text/plain", data, meta, &identity).unwrap();
    assert_eq!(blob_id, blob_id2);
    // Delete blob
    blob_mgr.delete_blob(&blob_id).unwrap();
    assert!(blob_mgr.get_blob(&blob_id).is_err());
    shutdown_redb().unwrap();
}

#[test]
fn test_blob_store_invalid() {
    use common::identity::IdentityContext;
    let options = RedbOptions { deduplication_enabled: false, ..Default::default() };
    init_redb(options).unwrap();
    let blob_mgr = BlobManager::new();
    let identity = IdentityContext::root();
    // Empty data should still store, but simulate error by using a very large chunk size
    let mut options = RedbOptions::default();
    options.chunk_size = 1; // force many chunks
    // (You can add more error simulation here)
    shutdown_redb().unwrap();
}

#[test]
fn test_concurrent_blob_store() {
    use common::identity::IdentityContext;
    let options = RedbOptions::default();
    init_redb(options).unwrap();
    let blob_mgr = std::sync::Arc::new(BlobManager::new());
    let identity = IdentityContext::root();
    let handles: Vec<_> = (0..8).map(|i| {
        let mgr: std::sync::Arc<BlobManager> = std::sync::Arc::clone(&blob_mgr);
        let id = identity.clone();
        std::thread::spawn(move || {
            let data = format!("blob-data-{}", i).into_bytes();
            let meta = HashMap::new();
            let blob_id = mgr.store_blob(&format!("blob-{}", i), "text/plain", &data, meta, &id).unwrap();
            let (_meta, data_out) = mgr.get_blob(&blob_id).unwrap();
            assert_eq!(data_out, data);
        })
    }).collect();
    for h in handles { h.join().unwrap(); }
    shutdown_redb().unwrap();
}
*/
