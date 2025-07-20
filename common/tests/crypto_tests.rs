//! # Cryptography Tests
//! 
//! This module contains tests for the crypto module, focusing on key generation,
//! signing, verification, hashing, and token generation.

use common::prelude::*;
use std::thread;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test key pair generation
    /// 
    /// This test verifies that key pairs can be generated and that the public and private keys
    /// are different.
    #[test]
    fn test_key_pair_generation() {
        // Generate a key pair
        let key_pair = generate_key_pair().expect("Failed to generate key pair");
        
        // Verify that the keys are not empty
        assert!(!key_pair.public_key.is_empty());
        assert!(!key_pair.private_key.is_empty());
        
        // Verify that the keys are different
        assert_ne!(key_pair.public_key, key_pair.private_key);
    }

    /// Test signing and verification
    /// 
    /// This test verifies that data can be signed and the signature can be verified.
    #[test]
    fn test_signing_and_verification() {
        // Generate a key pair
        let key_pair = generate_key_pair().expect("Failed to generate key pair");
        
        // Create some data to sign
        let data = b"Hello, world!";
        
        // Sign the data
        let signature = sign(data, &key_pair.private_key).expect("Failed to sign data");
        
        // Verify that the signature is not empty
        assert!(!signature.is_empty());
        
        // Verify the signature
        let is_valid = verify(data, &signature, &key_pair.public_key).expect("Failed to verify signature");
        
        // Verify that the signature is valid
        assert!(is_valid, "Signature verification failed");
        
        // Modify the data
        let modified_data = b"Hello, world?";
        
        // Verify that the signature is invalid for the modified data
        let is_valid = verify(modified_data, &signature, &key_pair.public_key).expect("Failed to verify signature");
        assert!(!is_valid, "Signature verification should have failed for modified data");
    }

    /// Test SHA-256 hashing
    /// 
    /// This test verifies that data can be hashed using SHA-256.
    #[test]
    fn test_sha256_hashing() {
        // Create some data to hash
        let data = b"Hello, world!";
        
        // Hash the data
        let hash = hash_sha256(data);
        
        // Verify that the hash is not empty
        assert!(!hash.is_empty());
        
        // Verify that the hash is the correct length (32 bytes for SHA-256)
        assert_eq!(hash.len(), 32);
        
        // Verify that the hash is deterministic
        let hash2 = hash_sha256(data);
        assert_eq!(hash, hash2);
        
        // Verify that different data produces different hashes
        let different_data = b"Hello, world?";
        let different_hash = hash_sha256(different_data);
        assert_ne!(hash, different_hash);
    }

    /// Test device fingerprint generation
    /// 
    /// This test verifies that device fingerprints can be generated.
    #[test]
    fn test_device_fingerprint_generation() {
        // Generate a device fingerprint
        let fingerprint = generate_device_fingerprint();
        
        // Verify that the fingerprint is not empty
        assert!(!fingerprint.is_empty());
        
        // Generate another fingerprint
        let fingerprint2 = generate_device_fingerprint();
        
        // Verify that the fingerprints are different
        assert_ne!(fingerprint, fingerprint2);
    }

    /// Test token generation
    /// 
    /// This test verifies that tokens can be generated.
    #[test]
    fn test_token_generation() {
        // Generate a token with length 32
        let token = generate_token(32);
        
        // Verify that the token is not empty
        assert!(!token.is_empty());
        
        // Generate another token
        let token2 = generate_token(32);
        
        // Verify that the tokens are different
        assert_ne!(token, token2);
    }

    /// Test concurrent key pair generation
    /// 
    /// This test verifies that key pairs can be generated concurrently.
    #[test]
    fn test_concurrent_key_pair_generation() {
        // Create a vector to hold thread handles
        let mut handles = vec![];
        
        // Spawn 10 threads to generate key pairs
        for _ in 0..10 {
            let handle = thread::spawn(move || {
                // Generate a key pair
                let key_pair = generate_key_pair().expect("Failed to generate key pair");
                
                // Return the key pair
                (key_pair.public_key, key_pair.private_key)
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads to complete
        let mut key_pairs = vec![];
        for handle in handles {
            key_pairs.push(handle.join().unwrap());
        }
        
        // Verify that all key pairs were generated
        assert_eq!(key_pairs.len(), 10);
        
        // Verify that all key pairs are unique
        for i in 0..key_pairs.len() {
            for j in i+1..key_pairs.len() {
                assert_ne!(key_pairs[i].0, key_pairs[j].0);
                assert_ne!(key_pairs[i].1, key_pairs[j].1);
            }
        }
    }

    /// Test signing and verification with multiple key pairs
    /// 
    /// This test verifies that multiple key pairs can be used for signing and verification.
    #[test]
    fn test_multiple_key_pairs() {
        // Generate 5 key pairs
        let mut key_pairs = vec![];
        for _ in 0..5 {
            key_pairs.push(generate_key_pair().expect("Failed to generate key pair"));
        }
        
        // Create some data to sign
        let data = b"Hello, world!";
        
        // Sign the data with each private key
        let mut signatures = vec![];
        for key_pair in &key_pairs {
            let signature = sign(data, &key_pair.private_key).expect("Failed to sign data");
            signatures.push(signature);
        }
        
        // Verify each signature with the corresponding public key
        for i in 0..5 {
            let key_pair = &key_pairs[i];
            let signature = &signatures[i];
            
            let is_valid = verify(data, signature, &key_pair.public_key).expect("Failed to verify signature");
            assert!(is_valid, "Signature verification failed for key pair {}", i);
        }
        
        // Verify that signatures don't verify with the wrong public key
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    let key_pair_i = &key_pairs[i];
                    let signature = &signatures[j];
                    
                    let is_valid = verify(data, signature, &key_pair_i.public_key).expect("Failed to verify signature");
                    assert!(!is_valid, "Signature verification should have failed for key pair {} and signature {}", i, j);
                }
            }
        }
    }

    /// Test signing and verification with large data
    /// 
    /// This test verifies that large data can be signed and verified.
    #[test]
    fn test_large_data_signing() {
        // Generate a key pair
        let key_pair = generate_key_pair().expect("Failed to generate key pair");
        
        // Create a large data buffer (1 MB)
        let large_data = vec![0u8; 1024 * 1024];
        
        // Sign the data
        let signature = sign(&large_data, &key_pair.private_key).expect("Failed to sign large data");
        
        // Verify the signature
        let is_valid = verify(&large_data, &signature, &key_pair.public_key).expect("Failed to verify signature");
        
        // Verify that the signature is valid
        assert!(is_valid, "Signature verification failed for large data");
    }

    /// Test signing and verification with empty data
    /// 
    /// This test verifies that empty data can be signed and verified.
    #[test]
    fn test_empty_data_signing() {
        // Generate a key pair
        let key_pair = generate_key_pair().expect("Failed to generate key pair");
        
        // Create an empty data buffer
        let empty_data = b"";
        
        // Sign the data
        let signature = sign(empty_data, &key_pair.private_key).expect("Failed to sign empty data");
        
        // Verify the signature
        let is_valid = verify(empty_data, &signature, &key_pair.public_key).expect("Failed to verify signature");
        
        // Verify that the signature is valid
        assert!(is_valid, "Signature verification failed for empty data");
    }

    /// Test signing with an invalid private key
    /// 
    /// This test verifies that signing with an invalid private key fails.
    #[test]
    fn test_invalid_private_key() {
        // Create an invalid private key (too short)
        let invalid_private_key = vec![0u8; 10]; // Less than 32 bytes
        
        // Create some data to sign
        let data = b"Hello, world!";
        
        // Attempt to sign the data
        let result = sign(data, &invalid_private_key);
        
        // Verify that signing failed
        assert!(result.is_err());
    }

    /// Test verification with an invalid public key
    /// 
    /// This test verifies that verification with an invalid public key fails.
    #[test]
    fn test_invalid_public_key() {
        // Generate a key pair
        let key_pair = generate_key_pair().expect("Failed to generate key pair");
        
        // Create an invalid public key (too short)
        let invalid_public_key = vec![0u8; 10]; // Less than 32 bytes
        
        // Create some data to sign
        let data = b"Hello, world!";
        
        // Sign the data
        let signature = sign(data, &key_pair.private_key).expect("Failed to sign data");
        
        // Attempt to verify the signature
        let result = verify(data, &signature, &invalid_public_key);
        
        // Verify that verification failed
        assert!(result.is_err());
    }

    /// Test verification with an invalid signature
    /// 
    /// This test verifies that verification with an invalid signature fails.
    #[test]
    fn test_invalid_signature() {
        // Generate a key pair
        let key_pair = generate_key_pair().expect("Failed to generate key pair");
        
        // Create an invalid signature (too short)
        let invalid_signature = vec![0u8; 10]; // Less than 64 bytes
        
        // Create some data to verify
        let data = b"Hello, world!";
        
        // Attempt to verify the signature
        let result = verify(data, &invalid_signature, &key_pair.public_key);
        
        // Verify that verification failed
        assert!(result.is_err());
    }
}