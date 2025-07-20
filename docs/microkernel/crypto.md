# Microkernel Crypto Module

## Overview
The Crypto module provides cryptographic functionality for the ForgeOne microkernel, including signature verification and `.forgepkg` validation. It ensures the integrity, authenticity, and confidentiality of all cryptographic operations within the microkernel.

## Key Features

### Signature Verification
- **Ed25519/SHA3**: Implements modern, high-security signature algorithms
- **Key Management**: Securely manages cryptographic keys
- **Signature Validation**: Verifies digital signatures for code and data
- **Trust Chain**: Maintains a chain of trust for all signed components

### Quantum `.forgepkg` Validation
- **Package Integrity**: Verifies the integrity of `.forgepkg` packages
- **Manifest Validation**: Ensures manifest contents match package contents
- **Multi-Signature Support**: Validates packages signed by multiple parties
- **Lattice-Sealed ACLs**: Implements quantum-resistant access controls

## Core Components

### Signature Module
```rust
pub struct SignatureContext {
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

pub enum SignatureAlgorithm {
    Ed25519,
    Ed25519_Sha3,
    RSA_PSS_SHA256,
    ECDSA_P256_SHA256,
    Custom(String),
}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Option<Vec<u8>>,
    pub algorithm: SignatureAlgorithm,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

pub struct VerificationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}
```

### ForgePkg Module
```rust
pub struct ForgePkg {
    pub manifest: ForgePkgManifest,
    pub signature: String,
    pub multi_signatures: Option<Vec<MultiSignature>>,
    pub content: HashMap<String, Vec<u8>>,
}

pub struct ForgePkgManifest {
    pub name: String,
    pub version: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub created_by: String,
    pub content_hashes: HashMap<String, String>,
    pub intent_hash: String,
    pub metadata: HashMap<String, String>,
    pub acl: Option<AccessControlList>,
}

pub struct MultiSignature {
    pub signer_id: String,
    pub signature: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

pub struct AccessControlList {
    pub readers: Vec<String>,
    pub executors: Vec<String>,
    pub administrators: Vec<String>,
    pub lattice_seal: Option<LatticeSeal>,
}

pub struct LatticeSeal {
    pub algorithm: String,
    pub public_parameters: Vec<u8>,
    pub sealed_data: Vec<u8>,
}
```

## Usage Examples

### Verifying Signatures
```rust
use microkernel::crypto::signature;

// Create a signature context
let context = signature::SignatureContext {
    algorithm: signature::SignatureAlgorithm::Ed25519_Sha3,
    public_key: public_key.to_vec(),
    signature: signature.to_vec(),
    data: data.to_vec(),
    metadata: HashMap::new(),
};

// Verify the signature
let result = signature::verify(context)?;

// Check the result
if result.valid {
    println!("Signature verified successfully");
} else {
    println!("Signature verification failed: {}", result.reason.unwrap_or_default());
}

// Generate a key pair
let key_pair = signature::generate_key_pair(signature::SignatureAlgorithm::Ed25519_Sha3)?;
println!("Generated public key: {:?}", key_pair.public_key);
```

### Validating ForgePkg Packages
```rust
use microkernel::crypto::forgepkg;

// Load a ForgePkg from a file
let pkg = forgepkg::load_from_file("package.forgepkg")?;

// Validate the package
let result = forgepkg::validate(&pkg, &public_key)?;

// Check the result
if result.valid {
    println!("Package validated successfully");
    println!("Package name: {}", pkg.manifest.name);
    println!("Package version: {}", pkg.manifest.version);
} else {
    println!("Package validation failed: {}", result.reason.unwrap_or_default());
}

// Create a new ForgePkg
let mut manifest = forgepkg::ForgePkgManifest {
    name: "my-package".to_string(),
    version: "1.0.0".to_string(),
    created_at: chrono::Utc::now(),
    created_by: "user@example.com".to_string(),
    content_hashes: HashMap::new(),
    intent_hash: "".to_string(),
    metadata: HashMap::new(),
    acl: None,
};

let mut content = HashMap::new();
content.insert("file1.txt".to_string(), b"Hello, world!".to_vec());

let pkg = forgepkg::create(
    manifest,
    content,
    &private_key,
    signature::SignatureAlgorithm::Ed25519_Sha3,
)?;

// Save the package to a file
forgepkg::save_to_file(&pkg, "new-package.forgepkg")?;
```

### Working with Multi-Signatures
```rust
use microkernel::crypto::forgepkg;

// Load a ForgePkg from a file
let mut pkg = forgepkg::load_from_file("package.forgepkg")?;

// Add a signature
let signature = forgepkg::sign_package(
    &pkg,
    &private_key,
    signature::SignatureAlgorithm::Ed25519_Sha3,
    "signer@example.com",
)?;

// Add the signature to the package
if let Some(ref mut signatures) = pkg.multi_signatures {
    signatures.push(signature);
} else {
    pkg.multi_signatures = Some(vec![signature]);
}

// Validate with quorum requirement (2 of 3 signatures)
let public_keys = vec![
    ("signer1@example.com".to_string(), public_key1.to_vec()),
    ("signer2@example.com".to_string(), public_key2.to_vec()),
    ("signer3@example.com".to_string(), public_key3.to_vec()),
];

let result = forgepkg::validate_with_quorum(&pkg, public_keys, 2)?;

// Check the result
if result.valid {
    println!("Package validated with quorum");
} else {
    println!("Package validation failed: {}", result.reason.unwrap_or_default());
}
```

## Related Modules
- [Core Module](./core.md) - Uses Crypto module for secure boot
- [Execution Module](./execution.md) - Uses Crypto module for validating WASM modules
- [Trust Module](./trust.md) - Integrates with Crypto module for policy validation
- [Common Crypto Module](../common/crypto.md) - Provides additional cryptographic functionality
- [Common Identity Module](../common/identity.md) - Uses Crypto module for identity verification