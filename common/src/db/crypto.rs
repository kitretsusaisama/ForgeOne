//! # Database Cryptography Module
//!
//! This module provides cryptographic functionality for the database system, including:
//! - Field-level encryption and decryption
//! - Key management for database encryption
//! - Secure key derivation and rotation
//! - Cryptographic checksums and verification

use std::sync::{Arc, RwLock, Once};
use std::collections::HashMap;
use std::path::PathBuf;
use rand::{RngCore, rngs::OsRng};
use blake3::Hasher;
use zstd;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

use crate::error::{ForgeError, Result};
use crate::crypto::{encrypt_aes_gcm as crypto_encrypt_aes_gcm, decrypt_aes_gcm as crypto_decrypt_aes_gcm};

// Static initialization
static INIT: Once = Once::new();
static mut DB_CRYPTO_MANAGER: Option<Arc<RwLock<DbCryptoManager>>> = None;

/// Database cryptography manager
pub struct DbCryptoManager {
    /// Master encryption key
    master_key: Vec<u8>,
    /// Field encryption keys by table
    field_keys: HashMap<String, Vec<u8>>,
    /// Key rotation history
    key_history: Vec<KeyRotationEvent>,
    /// Base directory for key storage
    base_dir: PathBuf,
    /// Whether encryption is enabled
    encryption_enabled: bool,
    /// Compression level
    compression_level: i32,
}

/// Key rotation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    /// Event ID
    pub id: String,
    /// Key ID
    pub key_id: String,
    /// Rotation timestamp
    pub timestamp: DateTime<Utc>,
    /// Key type
    pub key_type: KeyType,
    /// Reason for rotation
    pub reason: RotationReason,
}

/// Key type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    /// Master key
    Master,
    /// Field key
    Field(String),
}

/// Rotation reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RotationReason {
    /// Scheduled rotation
    Scheduled,
    /// Manual rotation
    Manual,
    /// Emergency rotation
    Emergency(String),
}

/// Initialize database cryptography
pub fn init_db_crypto(base_dir: &PathBuf, encryption_enabled: bool, encryption_key: Option<&str>, compression_level: i32) -> Result<()> {
    INIT.call_once(|| {
        // Create base directory if it doesn't exist
        let keys_dir = base_dir.join("keys");
        if !keys_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&keys_dir) {
                eprintln!("Failed to create keys directory: {}", e);
                return;
            }
        }
        
        // Initialize master key
        let master_key = match encryption_key {
            Some(key) => {
                // Derive key from provided encryption key
                let salt = "ForgeOne-DB-Salt";
                match crate::crypto::derive_key_from_password(key, salt, 3, 65536) {
                    Ok(derived_key) => derived_key,
                    Err(e) => {
                        eprintln!("Failed to derive key: {}", e);
                        return;
                    }
                }
            },
            None => {
                // Generate a new random key
                let mut key = vec![0u8; 32];
                OsRng.fill_bytes(&mut key);
                
                // Save the key to disk if encryption is enabled
                if encryption_enabled {
                    let key_path = keys_dir.join("master.key");
                    if let Err(e) = std::fs::write(&key_path, &key) {
                        eprintln!("Failed to write master key: {}", e);
                        return;
                    }
                }
                
                key
            }
        };
        
        // Create manager
        let manager = DbCryptoManager {
            master_key,
            field_keys: HashMap::new(),
            key_history: Vec::new(),
            base_dir: base_dir.clone(),
            encryption_enabled,
            compression_level,
        };
        
        // Store manager
        unsafe {
            DB_CRYPTO_MANAGER = Some(Arc::new(RwLock::new(manager)));
        }
    });
    
    Ok(())
}

/// Get database cryptography manager
pub fn get_db_crypto_manager() -> Result<Arc<RwLock<DbCryptoManager>>> {
    unsafe {
        match &DB_CRYPTO_MANAGER {
            Some(manager) => Ok(manager.clone()),
            None => Err(ForgeError::CryptoError("Database cryptography not initialized".to_string())),
        }
    }
}

/// Encrypt data with AES-GCM
pub fn encrypt_aes_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Generate random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    
    // Encrypt data
    let ciphertext = crypto_encrypt_aes_gcm(data, key, &nonce)?;
    
    // Combine nonce and ciphertext
    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt data with AES-GCM
pub fn decrypt_aes_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    // Ensure data is long enough
    if data.len() < 12 {
        return Err(ForgeError::CryptoError("Invalid encrypted data".to_string()));
    }
    
    // Extract nonce and ciphertext
    let nonce = &data[0..12];
    let ciphertext = &data[12..];
    
    // Decrypt data
    crypto_decrypt_aes_gcm(ciphertext, key, nonce)
}

/// Compress data with Zstd
pub fn compress_data(data: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::encode_all(data, level)
        .map_err(|e| ForgeError::DatabaseEncryptionError(format!("Compression error: {}", e)))
}

/// Decompress data with Zstd
pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| ForgeError::DatabaseEncryptionError(format!("Decompression error: {}", e)))
}

/// Calculate BLAKE3 hash
pub fn calculate_hash(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hash.to_hex().to_string()
}

/// Verify BLAKE3 hash
pub fn verify_hash(data: &[u8], hash: &str) -> bool {
    let calculated_hash = calculate_hash(data);
    calculated_hash == hash
}

impl DbCryptoManager {
    /// Get master key
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }
    
    /// Get field key
    pub fn field_key(&self, table: &str) -> Result<Vec<u8>> {
        if let Some(key) = self.field_keys.get(table) {
            Ok(key.clone())
        } else {
            // Derive a new key for this table
            let mut hasher = Hasher::new();
            hasher.update(&self.master_key);
            hasher.update(table.as_bytes());
            let key = hasher.finalize().as_bytes().to_vec();
            
            // Store the key
            let manager_arc = get_db_crypto_manager()?;
            let mut manager = manager_arc.write().unwrap();
            manager.field_keys.insert(table.to_string(), key.clone());
            
            Ok(key)
        }
    }
    
    /// Encrypt a field
    pub fn encrypt_field(&self, table: &str, field: &str, value: &[u8]) -> Result<String> {
        if !self.encryption_enabled {
            return Ok(general_purpose::STANDARD.encode(value));
        }
        
        // Get field key
        let key = self.field_key(table)?;
        
        // Encrypt value
        let encrypted = encrypt_aes_gcm(value, &key)?;
        
        // Encode as base64
        Ok(general_purpose::STANDARD.encode(encrypted))
    }
    
    /// Decrypt a field
    pub fn decrypt_field(&self, table: &str, field: &str, value: &str) -> Result<Vec<u8>> {
        // Decode from base64
        let data = general_purpose::STANDARD.decode(value)
            .map_err(|e| ForgeError::DatabaseEncryptionError(format!("Base64 decode error: {}", e)))?;
        
        if !self.encryption_enabled {
            return Ok(data);
        }
        
        // Get field key
        let key = self.field_key(table)?;
        
        // Decrypt value
        decrypt_aes_gcm(&data, &key)
    }
    
    /// Rotate master key
    pub fn rotate_master_key(&mut self, reason: RotationReason) -> Result<()> {
        // Generate a new master key
        let mut new_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut new_key);
        
        // Save the old key
        let old_key = self.master_key.clone();
        let key_id = Uuid::new_v4().to_string();
        
        // Record rotation event
        let event = KeyRotationEvent {
            id: Uuid::new_v4().to_string(),
            key_id: key_id.clone(),
            timestamp: Utc::now(),
            key_type: KeyType::Master,
            reason: reason.clone(),
        };
        
        self.key_history.push(event);
        
        // Save the new key to disk if encryption is enabled
        if self.encryption_enabled {
            let keys_dir = self.base_dir.join("keys");
            let key_path = keys_dir.join("master.key");
            let backup_path = keys_dir.join(format!("master.key.{}", key_id));
            // Backup old key
            std::fs::write(&backup_path, &old_key)
                .map_err(|e| ForgeError::IoError { message: format!("Failed to backup master key: {}", e), source: None })?;
            // Write new key
            std::fs::write(&key_path, &new_key)
                .map_err(|e| ForgeError::IoError { message: format!("Failed to write master key: {}", e), source: None })?;
        }
        
        // Update master key
        self.master_key = new_key;
        
        // Clear field keys to force regeneration
        self.field_keys.clear();
        
        Ok(())
    }
    
    /// Check if encryption is enabled
    pub fn is_encryption_enabled(&self) -> bool {
        self.encryption_enabled
    }
    
    /// Get compression level
    pub fn compression_level(&self) -> i32 {
        self.compression_level
    }
    
    /// Set compression level
    pub fn set_compression_level(&mut self, level: i32) {
        self.compression_level = level;
    }
    
    /// Get key rotation history
    pub fn key_rotation_history(&self) -> &[KeyRotationEvent] {
        &self.key_history
    }
}

/// Process data for storage (compress and encrypt)
pub fn process_data_for_storage(data: &[u8]) -> Result<Vec<u8>> {
    let manager_arc = get_db_crypto_manager()?;
    let manager = manager_arc.read().unwrap();
    
    // Compress if enabled
    let processed_data = if manager.compression_level() != 0 {
        compress_data(data, manager.compression_level())?
    } else {
        data.to_vec()
    };
    
    // Encrypt if enabled
    let final_data = if manager.is_encryption_enabled() {
        encrypt_aes_gcm(&processed_data, manager.master_key())?
    } else {
        processed_data
    };
    
    Ok(final_data)
}

/// Process data from storage (decrypt and decompress)
pub fn process_data_from_storage(data: &[u8]) -> Result<Vec<u8>> {
    let manager_arc = get_db_crypto_manager()?;
    let manager = manager_arc.read().unwrap();
    
    // Decrypt if enabled
    let decrypted_data = if manager.is_encryption_enabled() {
        decrypt_aes_gcm(data, manager.master_key())?
    } else {
        data.to_vec()
    };
    
    // Decompress if enabled
    let final_data = if manager.compression_level() != 0 {
        decompress_data(&decrypted_data)?
    } else {
        decrypted_data
    };
    
    Ok(final_data)
}