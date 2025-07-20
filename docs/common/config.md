# Configuration System

## Overview
The Configuration system provides a multi-layer configuration system with attestation for the ForgeOne platform. It handles loading, validating, and attesting configurations.

## Key Features
- Multi-layer configuration management
- Configuration attestation and signing
- Support for JSON and YAML formats
- Environment-specific configuration
- Secure configuration handling

## Core Components

### ForgeConfig
The main configuration structure for ForgeOne with the following properties:
- `name` - The name of this configuration
- `version` - The version of this configuration
- `environment` - The environment of this configuration (development, production, etc.)
- `log_level` - The log level of this configuration
- `telemetry_endpoint` - The telemetry endpoint of this configuration
- `audit_log_path` - The audit log path of this configuration
- `policy_file_path` - The policy file path of this configuration
- `enable_llm_tracing` - Whether to enable LLM tracing
- `enable_crypto_verification` - Whether to enable cryptographic verification
- `trusted_public_keys` - The trusted public keys for verification

### SignedConfig
A signed configuration with attestation:
- `content` - The content of this configuration
- `signature` - The signature of this configuration
- `issued_by` - The issuer of this configuration
- `timestamp` - The timestamp of this configuration

## Functions
- `load_config()` - Load a configuration from a file
- `load_signed_config()` - Load a signed configuration from a file

## Usage Example
```rust
// Load configuration from a file
let config = load_config("config.json")?;

// Load signed configuration from a file
let signed_config: SignedConfig<ForgeConfig> = load_signed_config("signed_config.json")?;
```

## Related Modules
- [Bootstrap](./bootstrap.md)
- [Crypto](./crypto.md)
- [Error](./error.md)