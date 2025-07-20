# Cryptographic Utilities

## Overview
The Crypto module provides comprehensive cryptographic functionality for the ForgeOne platform, ensuring secure operations across the system.

## Key Features
- Digital signatures and verification
- Secure key management and derivation
- Encryption and decryption (symmetric and asymmetric)
- Hashing and message authentication
- Random number generation and secure tokens
- Password hashing and verification
- Key exchange protocols
- File encryption utilities

## Core Components

### KeyPair
A key pair for signing and verifying:
- `public_key` - The public key
- `private_key` - The private key

### Keypair
A keypair for ed25519 signing operations:
- `signing_key` - The signing key
- `verifying_key` - The verifying key

## Key Functions

### Key Management
- `generate_key_pair()` - Generate a new key pair

### Signing and Verification
- `sign()` - Sign data with a private key
- `verify()` - Verify a signature

### Encryption and Decryption
- Symmetric encryption using AES-GCM
- Asymmetric encryption using X25519

### Hashing
- SHA-256 and SHA-512 hashing functions
- HMAC authentication

## Security Considerations
- All private keys are protected and never exposed in logs or error messages
- Cryptographic operations use secure random number generation
- Modern algorithms are used for all cryptographic operations
- Key rotation and management is handled securely

## Usage Example
```rust
// Generate a new key pair
let key_pair = generate_key_pair()?;

// Sign data
let data = b"Hello, world!";
let signature = sign(data, &key_pair.private_key)?;

// Verify signature
let is_valid = verify(data, &signature, &key_pair.public_key)?;
assert!(is_valid);
```

## Related Modules
- [Config](./config.md)
- [Identity](./identity.md)
- [Trust](./trust.md)
- [Audit](./audit.md)