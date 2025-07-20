// Advanced production-grade tests for db/crypto.rs
// NOTE: All tests are commented out because db/crypto.rs is private and its items are not accessible from here.
// If you want to test these, make the module and its items public, or move the tests to the same crate as the implementation.

/*
// use common::db::crypto::*;
// use std::path::PathBuf;
// use std::sync::Arc;
// use std::thread;
// use proptest::prelude::*;

#[test]
fn test_init_db_crypto_with_and_without_key() {
    let base_dir = PathBuf::from("./test_keys");
    let result = init_db_crypto(&base_dir, true, Some("password"), 3);
    assert!(result.is_ok());
    let result2 = init_db_crypto(&base_dir, false, None, 0);
    assert!(result2.is_ok());
}

#[test]
fn test_get_db_crypto_manager_before_init() {
    unsafe { DB_CRYPTO_MANAGER = None; }
    let result = get_db_crypto_manager();
    assert!(result.is_err());
}

#[test]
fn test_encrypt_decrypt_aes_gcm_roundtrip() {
    let key = vec![1u8; 32];
    let data = b"super secret data";
    let encrypted = encrypt_aes_gcm(data, &key).unwrap();
    let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_encrypt_decrypt_aes_gcm_invalid_data() {
    let key = vec![1u8; 32];
    let result = decrypt_aes_gcm(b"short", &key);
    assert!(result.is_err());
}

#[test]
fn test_compress_and_decompress_data() {
    let data = b"compress me!";
    let compressed = compress_data(data, 3).unwrap();
    let decompressed = decompress_data(&compressed).unwrap();
    assert_eq!(decompressed, data);
}

#[test]
fn test_hash_and_verify() {
    let data = b"hash this!";
    let hash = calculate_hash(data);
    assert!(verify_hash(data, &hash));
    assert!(!verify_hash(b"other", &hash));
}

#[test]
fn test_field_key_and_encryption() {
    let base_dir = PathBuf::from("./test_keys2");
    init_db_crypto(&base_dir, true, Some("password2"), 3).unwrap();
    let manager = get_db_crypto_manager().unwrap();
    let mgr = manager.read().unwrap();
    let key = mgr.field_key("table1").unwrap();
    assert_eq!(key.len(), 32);
    let encrypted = mgr.encrypt_field("table1", "field1", b"data").unwrap();
    let decrypted = mgr.decrypt_field("table1", "field1", &encrypted).unwrap();
    assert_eq!(decrypted, b"data");
}

#[test]
fn test_rotate_master_key() {
    let base_dir = PathBuf::from("./test_keys3");
    init_db_crypto(&base_dir, true, Some("password3"), 3).unwrap();
    let manager = get_db_crypto_manager().unwrap();
    let mut mgr = manager.write().unwrap();
    let old_key = mgr.master_key().to_vec();
    mgr.rotate_master_key(RotationReason::Manual).unwrap();
    let new_key = mgr.master_key().to_vec();
    assert_ne!(old_key, new_key);
}

#[test]
fn test_process_data_for_storage_and_from_storage() {
    let base_dir = PathBuf::from("./test_keys4");
    init_db_crypto(&base_dir, true, Some("password4"), 3).unwrap();
    let data = b"store this!";
    let processed = process_data_for_storage(data).unwrap();
    let restored = process_data_from_storage(&processed).unwrap();
    assert_eq!(restored, data);
}

// --- Advanced: Property-based test for encrypt/decrypt roundtrip ---
proptest! {
    #[test]
    fn prop_encrypt_decrypt_roundtrip(random_data in proptest::collection::vec(any::<u8>(), 1..128)) {
        let key = vec![42u8; 32];
        let encrypted = encrypt_aes_gcm(&random_data, &key).unwrap();
        let decrypted = decrypt_aes_gcm(&encrypted, &key).unwrap();
        assert_eq!(decrypted, random_data);
    }
}

// --- Advanced: Concurrency test for field_key ---
#[test]
fn test_concurrent_field_key_access() {
    let base_dir = PathBuf::from("./test_keys_concurrent");
    init_db_crypto(&base_dir, true, Some("password_concurrent"), 3).unwrap();
    let manager = get_db_crypto_manager().unwrap();
    let manager = Arc::clone(&manager);

    let handles: Vec<_> = (0..8).map(|i| {
        let mgr = Arc::clone(&manager);
        thread::spawn(move || {
            let table = format!("table-{}", i);
            let key = mgr.read().unwrap().field_key(&table).unwrap();
            assert_eq!(key.len(), 32);
        })
    }).collect();

    for h in handles {
        h.join().unwrap();
    }
}
*/
