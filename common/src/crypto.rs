//! # Cryptographic utilities for ForgeOne
//! Crypto.rs
//! This module provides comprehensive cryptographic functionality for the ForgeOne platform, including:
//! - Digital signatures and verification
//! - Secure key management and derivation
//! - Encryption and decryption (symmetric and asymmetric)
//! - Hashing and message authentication
//! - Random number generation and secure tokens
//! - Password hashing and verification
//! - Key exchange protocols
//! - File encryption utilities

use std::fmt;
use std::sync::{Arc, RwLock, Mutex, Once};
use rand::{RngCore, rngs::OsRng, Rng};
use base64::{Engine as _, engine::general_purpose};
use sha2::{Sha256, Sha512, Digest};
use hmac::{Hmac, Mac};
use aes_gcm::aead::{Aead, KeyInit, generic_array::GenericArray};
use aes_gcm::{Aes256Gcm, Nonce}; // Key is implied as 32 bytes for Aes256Gcm
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use crate::error::{ForgeError, Result};

// Static initialization
static INIT: Once = Once::new();
static mut KEY_MANAGER: Option<Arc<KeyManager>> = None;

/// A key pair for signing and verifying
pub struct KeyPair {
    /// The public key
    pub public_key: Vec<u8>,
    /// The private key
    pub private_key: Vec<u8>,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// A keypair for ed25519 signing operations
pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// Generate a new key pair
pub fn generate_key_pair() -> Result<KeyPair> {
    // Generate a new key pair
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    
    Ok(KeyPair {
        public_key: verifying_key.to_bytes().to_vec(),
        private_key: signing_key.to_bytes().to_vec(),
    })
}

/// Sign data with a private key
pub fn sign(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>> {
    // Ensure we have exactly 32 bytes for the private key
    if private_key.len() < 32 {
        return Err(ForgeError::CryptoError("Private key too short".to_string()));
    }
    
    // Convert slice to array
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&private_key[..32]);
    
    // Parse the private key
    let key = SigningKey::from_bytes(&key_bytes);
    
    // Sign the data
    let signature = key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Verify a signature
pub fn verify(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    // Ensure we have exactly 32 bytes for the public key
    if public_key.len() < 32 {
        return Err(ForgeError::CryptoError("Public key too short".to_string()));
    }
    
    // Ensure we have exactly 64 bytes for the signature
    if signature.len() < 64 {
        return Err(ForgeError::CryptoError("Signature too short".to_string()));
    }
    
    // Convert slices to arrays
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&public_key[..32]);
    
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature[..64]);
    
    // Parse the public key
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ForgeError::CryptoError(format!("Invalid public key: {}", e)))?;
    
    // Parse the signature
    let sig = Signature::from_bytes(&sig_bytes);
    
    // Verify the signature
    match key.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a device fingerprint
pub fn generate_device_fingerprint() -> String {
    // Generate a random fingerprint
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    
    // Encode the fingerprint
    general_purpose::STANDARD.encode(bytes)
}

/// Generate a secure random token
pub fn generate_token(length: usize) -> String {
    // Generate random bytes
    let mut rng = OsRng;
    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes);
    
    // Encode the bytes
    general_purpose::URL_SAFE.encode(bytes)
}

/// Hash data with SHA-256
pub fn hash_sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Encrypt data with AES-GCM
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(ForgeError::CryptoError("AES-GCM key must be 32 bytes".to_string()));
    }
    if nonce.len() != 12 {
        return Err(ForgeError::CryptoError("AES-GCM nonce must be 12 bytes".to_string()));
    }

    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(nonce);
    cipher.encrypt(nonce, data)
        .map_err(|e| ForgeError::CryptoError(e.to_string()))
}

/// Decrypt data with AES-GCM
pub fn decrypt_aes_gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(ForgeError::CryptoError("AES-GCM key must be 32 bytes".to_string()));
    }
    if nonce.len() != 12 {
        return Err(ForgeError::CryptoError("AES-GCM nonce must be 12 bytes".to_string()));
    }

    let key = GenericArray::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce = GenericArray::from_slice(nonce);
    cipher.decrypt(nonce, data)
        .map_err(|e| ForgeError::CryptoError(e.to_string()))
}

/// Encrypt data with a password
pub fn encrypt_with_password(data: &[u8], password: &str, salt: &str) -> Result<Vec<u8>> {
    // Derive key from password
    let key = derive_key_from_password(password, salt, 3, 65536)?;
    
    // Generate random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    
    // Encrypt data
    let ciphertext = encrypt_aes_gcm(data, &key, &nonce)?;
    
    // Combine salt, nonce, and ciphertext
    let salt_bytes = salt.as_bytes();
    let mut result = Vec::with_capacity(4 + salt_bytes.len() + nonce.len() + ciphertext.len());
    
    // Salt length (4 bytes) + salt + nonce + ciphertext
    result.extend_from_slice(&(salt_bytes.len() as u32).to_be_bytes());
    result.extend_from_slice(salt_bytes);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data with a password
pub fn decrypt_with_password(data: &[u8], password: &str) -> Result<Vec<u8>> {
    // Ensure data is long enough
    if data.len() < 4 {
        return Err(ForgeError::CryptoError("Invalid encrypted data".to_string()));
    }
    
    // Extract salt length
    let salt_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    
    // Ensure data is long enough
    if data.len() < 4 + salt_len + 12 {
        return Err(ForgeError::CryptoError("Invalid encrypted data".to_string()));
    }
    
    // Extract salt, nonce, and ciphertext
    let salt = std::str::from_utf8(&data[4..4+salt_len])
        .map_err(|_| ForgeError::CryptoError("Invalid salt encoding".to_string()))?;
    let nonce = &data[4+salt_len..4+salt_len+12];
    let ciphertext = &data[4+salt_len+12..];
    
    // Derive key from password
    let key = derive_key_from_password(password, salt, 3, 65536)?;
    
    // Decrypt data
    decrypt_aes_gcm(ciphertext, &key, nonce)
}

/// Key manager for cryptographic operations
pub struct KeyManager {
    /// Master key for deriving other keys
    master_key: RwLock<Option<Vec<u8>>>,
    
    /// Signing keypair
    signing_keypair: RwLock<Option<Keypair>>,
    
    /// Key exchange keypair
    key_exchange_keypair: RwLock<Option<(X25519StaticSecret, X25519PublicKey)>>,
}

/// Initialize cryptography module
pub fn init_crypto(master_key: Option<&[u8]>) -> Result<()> {
    INIT.call_once(|| {
        // Create key manager
        let manager = KeyManager {
            master_key: RwLock::new(master_key.map(|k| k.to_vec())),
            signing_keypair: RwLock::new(None),
            key_exchange_keypair: RwLock::new(None),
        };
        
        // Generate or derive keys
        if let Some(key) = master_key {
            // Derive keys from master key
            let _ = derive_keys_from_master(&manager, key);
        } else {
            // Generate new keys
            let _ = generate_new_keys(&manager);
        }
        
        // Store manager
        unsafe {
            KEY_MANAGER = Some(Arc::new(manager));
        }
    });
    
    Ok(())
}

/// Get key manager
fn get_key_manager() -> Result<Arc<KeyManager>> {
    unsafe {
        match &KEY_MANAGER {
            Some(manager) => Ok(manager.clone()),
            None => Err(ForgeError::CryptoError("Crypto module not initialized".to_string())),
        }
    }
}

/// Generate new cryptographic keys
fn generate_new_keys(manager: &KeyManager) -> Result<()> {
    // Generate master key
    let master_key = generate_random_bytes(32);
    *manager.master_key.write().unwrap() = Some(master_key.clone());
    
    // Generate signing keypair
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let signing_keypair = Keypair {
        signing_key,
        verifying_key,
    };
    *manager.signing_keypair.write().unwrap() = Some(signing_keypair);
    
    // Generate key exchange keypair
    let key_exchange_secret = X25519StaticSecret::random_from_rng(&mut rng);
    let key_exchange_public = X25519PublicKey::from(&key_exchange_secret);
    *manager.key_exchange_keypair.write().unwrap() = Some((key_exchange_secret, key_exchange_public));
    
    Ok(())
}

/// Derive keys from master key
fn derive_keys_from_master(manager: &KeyManager, master_key: &[u8]) -> Result<()> {
    // Store master key
    *manager.master_key.write().unwrap() = Some(master_key.to_vec());
    
    // Derive signing key
    let signing_seed = derive_key(master_key, b"signing_key", 32)?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    let verifying_key = VerifyingKey::from(&signing_key);
    let signing_keypair = Keypair {
        signing_key,
        verifying_key,
    };
    *manager.signing_keypair.write().unwrap() = Some(signing_keypair);
    
    // Derive key exchange key
    let exchange_seed = derive_key(master_key, b"key_exchange", 32)?;
    let key_exchange_secret = X25519StaticSecret::from(exchange_seed);
    let key_exchange_public = X25519PublicKey::from(&key_exchange_secret);
    *manager.key_exchange_keypair.write().unwrap() = Some((key_exchange_secret, key_exchange_public));
    
    Ok(())
}

/// Generate random bytes
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a cryptographic key of specified length
pub fn generate_key(length: usize) -> Vec<u8> {
    generate_random_bytes(length)
}

/// Derive a key using HKDF
pub fn derive_key(master_key: &[u8], info: &[u8], length: usize) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    
    let salt = b"ForgeOne-HKDF-Salt";
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    
    let mut okm = [0u8; 32];
    hkdf.expand(info, &mut okm)
        .map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    Ok(okm)
}

/// Sign data using the system's signing key
pub fn sign_with_system_key(data: &[u8]) -> Result<Vec<u8>> {
    let manager = get_key_manager()?;
    
    let keypair = manager.signing_keypair.read().unwrap();
    let keypair = keypair.as_ref()
        .ok_or_else(|| ForgeError::CryptoError("Signing keypair not available".to_string()))?;
    
    let signature = keypair.signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Get public signing key
pub fn get_public_signing_key() -> Result<Vec<u8>> {
    let manager = get_key_manager()?;
    
    let keypair = manager.signing_keypair.read().unwrap();
    let keypair = keypair.as_ref()
        .ok_or_else(|| ForgeError::CryptoError("Signing keypair not available".to_string()))?;
    
    Ok(keypair.verifying_key.to_bytes().to_vec())
}

/// Get public key exchange key
pub fn get_public_key_exchange_key() -> Result<Vec<u8>> {
    let manager = get_key_manager()?;
    
    let keypair = manager.key_exchange_keypair.read().unwrap();
    let keypair = keypair.as_ref()
        .ok_or_else(|| ForgeError::CryptoError("Key exchange keypair not available".to_string()))?;
    
    Ok(keypair.1.as_bytes().to_vec())
}

/// Perform key exchange
pub fn key_exchange(peer_public_key: &[u8]) -> Result<Vec<u8>> {
    let manager = get_key_manager()?;
    
    let keypair = manager.key_exchange_keypair.read().unwrap();
    let keypair = keypair.as_ref()
        .ok_or_else(|| ForgeError::CryptoError("Key exchange keypair not available".to_string()))?;
    
    // Parse peer public key
    let peer_public = X25519PublicKey::from(<[u8; 32]>::try_from(peer_public_key)
        .map_err(|_| ForgeError::CryptoError("Invalid peer public key".to_string()))?); 
    
    // Perform key exchange
    let shared_secret = keypair.0.diffie_hellman(&peer_public);
    
    Ok(shared_secret.as_bytes().to_vec())
}

/// Create HMAC signature
pub fn create_hmac(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key)
        .map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    mac.update(data);
    let result = mac.finalize();
    
    Ok(result.into_bytes().to_vec())
}

/// Verify HMAC signature
pub fn verify_hmac(data: &[u8], key: &[u8], signature: &[u8]) -> Result<bool> {
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key)
    .map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    mac.update(data);
    
    mac.verify_slice(signature)
        .map(|_| true)
        .or(Ok(false))
}

/// Hash data with SHA-512
pub fn hash_sha512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Constant-time comparison of strings
pub fn secure_compare(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    
    if a.len() != b.len() {
        return false;
    }
    
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Password-based key derivation using Argon2id
pub fn derive_key_from_password(password: &str, salt: &str, iterations: u32, memory: u32) -> Result<Vec<u8>> {
    use argon2::{Argon2, PasswordHasher};
    use argon2::password_hash::{SaltString, PasswordHash};
    
    // Create salt
    let salt = SaltString::from_b64(salt)
        .map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    // Configure Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(memory, iterations, 1, Some(32))
            .map_err(|e| ForgeError::CryptoError(e.to_string()))?,
    );
    
    // Derive key
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    // Extract key
    let hash = password_hash.hash
        .ok_or_else(|| ForgeError::CryptoError("Failed to extract hash".to_string()))?;
    
    Ok(hash.as_bytes().to_vec())
}

/// Generate a secure random password
pub fn generate_password(length: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
    
    let mut rng = OsRng;
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    password
}

/// Encrypt a file
pub fn encrypt_file(input_path: &str, output_path: &str, key: &[u8]) -> Result<()> {
    use std::fs::File;
    use std::io::{Read, Write};
    
    // Read input file
    let mut input_file = File::open(input_path)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    // Generate random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    
    // Encrypt data
    let encrypted = encrypt_aes_gcm(&data, key, &nonce)?;
    
    // Write output file
    let mut output_file = File::create(output_path)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    // Write nonce and encrypted data
    output_file.write_all(&nonce)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    output_file.write_all(&encrypted)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    Ok(())
}

/// Decrypt a file
pub fn decrypt_file(input_path: &str, output_path: &str, key: &[u8]) -> Result<()> {
    use std::fs::File;
    use std::io::{Read, Write};
    
    // Read input file
    let mut input_file = File::open(input_path)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    let mut data = Vec::new();
    input_file.read_to_end(&mut data)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    // Ensure file is long enough
    if data.len() < 12 {
        return Err(ForgeError::CryptoError("Invalid encrypted file".to_string()));
    }
    
    // Extract nonce and ciphertext
    let nonce = &data[0..12];
    let ciphertext = &data[12..];
    
    // Decrypt data
    let decrypted = decrypt_aes_gcm(ciphertext, key, nonce)?;
    
    // Write output file
    let mut output_file = File::create(output_path)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    output_file.write_all(&decrypted)
        .map_err(|e| ForgeError::IoError { message: e.to_string(), source: None })?;
    
    Ok(())
}

/// Generate a UUID v4
pub fn generate_uuid() -> String {
    use uuid::Uuid;
    Uuid::new_v4().to_string()
}

/// Generate a secure JWT token
pub fn generate_jwt(claims: &serde_json::Value, secret: &str, expiry_seconds: u64) -> Result<String> {
    use jsonwebtoken::{encode, Header, EncodingKey};
    
    // Add expiry to claims
    let mut claims = claims.clone();
    let exp = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::seconds(expiry_seconds as i64))
        .ok_or_else(|| ForgeError::CryptoError("Failed to calculate expiry".to_string()))?
        .timestamp();
    
    claims["exp"] = serde_json::Value::Number(serde_json::Number::from(exp));
    
    // Encode JWT
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ).map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    Ok(token)
}

/// Verify a JWT token
pub fn verify_jwt(token: &str, secret: &str) -> Result<serde_json::Value> {
    use jsonwebtoken::{decode, DecodingKey, Validation};
    
    let token_data = decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    ).map_err(|e| ForgeError::CryptoError(e.to_string()))?;
    
    Ok(token_data.claims)
}