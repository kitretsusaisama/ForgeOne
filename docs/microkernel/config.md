# Microkernel Config Module

## Overview
The Config module provides a flexible, secure, and dynamic configuration system for the ForgeOne microkernel. It enables runtime configuration changes, policy-driven configuration management, and secure storage of sensitive configuration values.

## Key Features

### Runtime Configuration
- **Dynamic Updates**: Configuration can be updated at runtime without restarting
- **Hot Reloading**: Components can subscribe to configuration changes
- **Validation**: Configuration values are validated against schemas
- **Defaults**: Sensible defaults are provided for all configuration values

### Policy-Driven Configuration
- **Policy Enforcement**: Configuration changes are validated against policies
- **Audit Trail**: All configuration changes are logged and auditable
- **Rollback**: Configuration changes can be rolled back if needed
- **Versioning**: Configuration versions are tracked and can be compared

### Secure Storage
- **Encryption**: Sensitive configuration values are encrypted at rest
- **Access Control**: Configuration access is controlled by identity and permissions
- **Secrets Management**: Integration with external secrets management systems
- **Tamper Detection**: Configuration integrity is verified

## Core Components

### Runtime Module
```rust
pub struct ConfigContext {
    pub values: HashMap<String, ConfigValue>,
    pub schemas: HashMap<String, ConfigSchema>,
    pub subscribers: HashMap<String, Vec<Box<dyn ConfigSubscriber>>>,
    pub history: Vec<ConfigChange>,
    pub policies: Vec<Box<dyn ConfigPolicy>>,
    pub storage: Box<dyn ConfigStorage>,
}

pub enum ConfigValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Array(Vec<ConfigValue>),
    Object(HashMap<String, ConfigValue>),
    Secret(SecretValue),
    Null,
}

pub struct SecretValue {
    encrypted_value: Vec<u8>,
    key_id: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct ConfigSchema {
    pub name: String,
    pub description: String,
    pub value_type: ConfigValueType,
    pub default_value: Option<ConfigValue>,
    pub constraints: Vec<Box<dyn ConfigConstraint>>,
    pub metadata: HashMap<String, String>,
}

pub enum ConfigValueType {
    String,
    Integer,
    Float,
    Boolean,
    Array(Box<ConfigValueType>),
    Object(HashMap<String, ConfigSchema>),
    Secret,
    Any,
}

pub trait ConfigConstraint: Send + Sync {
    fn validate(&self, value: &ConfigValue) -> Result<(), ConfigError>;
    fn description(&self) -> String;
}

pub struct ConfigChange {
    pub path: String,
    pub old_value: Option<ConfigValue>,
    pub new_value: Option<ConfigValue>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub identity: IdentityContext,
    pub reason: String,
}

pub trait ConfigSubscriber: Send + Sync {
    fn on_change(&self, path: &str, old_value: &Option<ConfigValue>, new_value: &Option<ConfigValue>);
}

pub trait ConfigPolicy: Send + Sync {
    fn evaluate(
        &self,
        path: &str,
        old_value: &Option<ConfigValue>,
        new_value: &Option<ConfigValue>,
        identity: &IdentityContext,
    ) -> Result<(), ConfigError>;
}

pub trait ConfigStorage: Send + Sync {
    fn load(&self) -> Result<HashMap<String, ConfigValue>, ConfigError>;
    fn save(&self, values: &HashMap<String, ConfigValue>) -> Result<(), ConfigError>;
    fn get_history(&self) -> Result<Vec<ConfigChange>, ConfigError>;
}

pub struct ConfigError {
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub details: Option<HashMap<String, String>>,
}
```

## Usage Examples

### Basic Configuration Management
```rust
use microkernel::config::runtime::{ConfigContext, ConfigValue};

// Get the config context
let config_context = ConfigContext::get_instance();

// Get a configuration value
let log_level = config_context.get::<String>("logging.level")?;
println!("Current log level: {}", log_level);

// Set a configuration value
config_context.set(
    "logging.level",
    ConfigValue::String("debug".to_string()),
    "Enabling debug logging for troubleshooting".to_string(),
)?;

// Get multiple configuration values
let logging_config = config_context.get_object("logging")?;
println!("Logging configuration: {:?}", logging_config);

// Check if a configuration value exists
if config_context.exists("feature_flags.experimental_mode") {
    let experimental_mode = config_context.get::<bool>("feature_flags.experimental_mode")?;
    println!("Experimental mode: {}", experimental_mode);
}
```

### Working with Configuration Schemas
```rust
use microkernel::config::runtime::{ConfigContext, ConfigSchema, ConfigValueType, ConfigValue};
use microkernel::config::constraints::{RangeConstraint, RegexConstraint};

// Define a configuration schema
let schema = ConfigSchema {
    name: "http.port".to_string(),
    description: "The port to listen on for HTTP requests".to_string(),
    value_type: ConfigValueType::Integer,
    default_value: Some(ConfigValue::Integer(8080)),
    constraints: vec![
        Box::new(RangeConstraint::new(1024, 65535)),
    ],
    metadata: hashmap!{
        "category".to_string() => "network".to_string(),
        "restart_required".to_string() => "true".to_string(),
    },
};

// Register the schema
let config_context = ConfigContext::get_instance();
config_context.register_schema(schema)?;

// Set a value that will be validated against the schema
config_context.set(
    "http.port",
    ConfigValue::Integer(8443),
    "Changing to HTTPS port".to_string(),
)?;

// This will fail validation
let result = config_context.set(
    "http.port",
    ConfigValue::Integer(80),
    "Changing to privileged port".to_string(),
);
assert!(result.is_err());
```

### Subscribing to Configuration Changes
```rust
use microkernel::config::runtime::{ConfigContext, ConfigSubscriber, ConfigValue};

// Define a configuration subscriber
struct LogLevelSubscriber;

impl ConfigSubscriber for LogLevelSubscriber {
    fn on_change(&self, path: &str, old_value: &Option<ConfigValue>, new_value: &Option<ConfigValue>) {
        if let Some(ConfigValue::String(new_level)) = new_value {
            println!("Log level changed to: {}", new_level);
            // Update the logger configuration
            update_log_level(new_level);
        }
    }
}

// Subscribe to configuration changes
let config_context = ConfigContext::get_instance();
config_context.subscribe("logging.level", Box::new(LogLevelSubscriber))?;

// When this configuration changes, the subscriber will be notified
config_context.set(
    "logging.level",
    ConfigValue::String("trace".to_string()),
    "Enabling trace logging for detailed debugging".to_string(),
)?;

fn update_log_level(level: &str) {
    // Implementation to update the log level
    // ...
}
```

### Working with Secure Configuration
```rust
use microkernel::config::runtime::{ConfigContext, ConfigValue, SecretValue};
use microkernel::crypto::encryption::{encrypt, decrypt};

// Store a secret configuration value
let config_context = ConfigContext::get_instance();

// The secret will be automatically encrypted
config_context.set_secret(
    "database.password",
    "very-secret-password",
    Some(chrono::Duration::days(30)),
    "Updating database password".to_string(),
)?;

// Retrieve and use a secret
let db_password = config_context.get_secret("database.password")?;
println!("Database password: {}", db_password);

// Check if a secret is expired
if config_context.is_secret_expired("database.password")? {
    println!("Database password has expired and should be rotated");
}

// Rotate a secret
config_context.rotate_secret(
    "database.password",
    "new-very-secret-password",
    Some(chrono::Duration::days(30)),
    "Rotating database password".to_string(),
)?;
```

## Related Modules
- [Core Module](./core.md) - Uses configuration for boot and runtime behavior
- [Trust Module](./trust.md) - Enforces policies on configuration changes
- [Crypto Module](./crypto.md) - Provides encryption for secure configuration values
- [Common Config Module](../common/config.md) - Integrates with the Common configuration system
- [API Documentation](../api/config.md) - Provides API documentation for configuration endpoints