# Microkernel Interface Module

## Overview
The Interface module provides the external API and prelude for the ForgeOne microkernel. It serves as the primary interaction point for external systems and applications, offering a clean, consistent, and secure interface to the microkernel's functionality.

## Key Features

### External API
- **Comprehensive Endpoints**: Provides access to all microkernel functionality
- **Versioned Interface**: Ensures backward compatibility
- **Authentication and Authorization**: Secures API access
- **Rate Limiting and Throttling**: Prevents API abuse

### Prelude
- **Centralized Imports**: Simplifies access to commonly used types and functions
- **Type Safety**: Ensures correct usage of microkernel components
- **Controlled Access**: Limits exposure of internal implementation details
- **Consistent Interface**: Provides a uniform way to interact with the microkernel

## Core Components

### API Module
```rust
pub struct ApiContext {
    pub version: String,
    pub endpoints: HashMap<String, ApiEndpoint>,
    pub middleware: Vec<Box<dyn ApiMiddleware>>,
    pub rate_limits: HashMap<String, RateLimit>,
    pub status: ApiStatus,
}

pub struct ApiEndpoint {
    pub path: String,
    pub method: HttpMethod,
    pub handler: Box<dyn ApiHandler>,
    pub auth_required: bool,
    pub rate_limit_key: Option<String>,
    pub documentation: ApiDocumentation,
}

pub enum HttpMethod {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS,
    HEAD,
}

pub trait ApiHandler: Send + Sync {
    fn handle(
        &self,
        request: &ApiRequest,
        context: &RequestContext,
    ) -> Result<ApiResponse, ApiError>;
}

pub trait ApiMiddleware: Send + Sync {
    fn process(
        &self,
        request: &mut ApiRequest,
        context: &mut RequestContext,
    ) -> Result<(), ApiError>;
}

pub struct ApiRequest {
    pub path: String,
    pub method: HttpMethod,
    pub headers: HashMap<String, String>,
    pub query_params: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub client_info: ClientInfo,
}

pub struct ApiResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub metadata: HashMap<String, String>,
}

pub struct ApiError {
    pub status_code: u16,
    pub error_code: String,
    pub message: String,
    pub details: Option<HashMap<String, String>>,
}

pub struct RequestContext {
    pub request_id: Uuid,
    pub identity: Option<IdentityContext>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub trace_context: Option<TraceContext>,
    pub custom_data: HashMap<String, String>,
}
```

### Prelude Module
```rust
// Re-exports from core module
pub use crate::core::boot::{BootContext, TrustAnchor};
pub use crate::core::runtime::{RuntimeContext, ContainerContext};
pub use crate::core::scheduler::{SchedulerContext, Workload, Priority};

// Re-exports from execution module
pub use crate::execution::wasm_host::{WasmHost, WasmModule};
pub use crate::execution::plugin_host::{PluginHost, Plugin, CapabilitySet};
pub use crate::execution::syscall::{SyscallContext, SyscallResult};

// Re-exports from trust module
pub use crate::trust::zta_policy::{ZtaPolicyGraph, SyscallPolicy};
pub use crate::trust::syscall_enforcer::{SyscallEnforcer, EnforcementMode};
pub use crate::trust::redzone::{Redzone, QuarantinedProcess};

// Re-exports from observer module
pub use crate::observer::trace::{TraceContext, TraceEvent, LlmSummary};
pub use crate::observer::forensic::{ForensicContext, ReplayEnvironment};
pub use crate::observer::snapshot::{SnapshotContext, MemoryRegion};

// Re-exports from crypto module
pub use crate::crypto::signature::{SignatureContext, SignatureAlgorithm};
pub use crate::crypto::forgepkg::{ForgePkg, ForgePkgManifest};

// Re-exports from diagnostics module
pub use crate::diagnostics::self_test::{SelfTestContext, TestResult};
pub use crate::diagnostics::anomaly::{AnomalyContext, Anomaly};

// Re-exports from config module
pub use crate::config::runtime::{ConfigContext, ConfigValue};

// Re-exports from common module
pub use common::identity::{IdentityContext, TrustVector};
pub use common::error::{Error, Result};
pub use common::telemetry::{TelemetryContext, Span};

// Convenience functions
pub fn init() -> Result<()> {
    // Initialize the microkernel
    crate::core::boot::init()
}

pub fn shutdown() -> Result<()> {
    // Shutdown the microkernel
    crate::core::runtime::shutdown()
}

pub fn launch_container(config: ContainerConfig) -> Result<Uuid> {
    // Launch a container
    crate::core::runtime::launch_container(config)
}

pub fn secure_syscall(
    syscall: &str,
    args: &[&str],
    identity: &IdentityContext,
) -> Result<SyscallResult> {
    // Execute a syscall with ZTA enforcement
    let graph = crate::trust::zta_policy::get_policy_graph();
    let mut execution_dna = crate::observer::trace::get_execution_dna(identity);
    crate::execution::syscall::secure_syscall(
        syscall,
        args,
        identity,
        &graph,
        &mut execution_dna,
    )
}
```

## Usage Examples

### Using the API
```rust
use microkernel::interface::api;

// Define an API handler
struct ContainerHandler;

impl api::ApiHandler for ContainerHandler {
    fn handle(
        &self,
        request: &api::ApiRequest,
        context: &api::RequestContext,
    ) -> Result<api::ApiResponse, api::ApiError> {
        match (request.method, request.path.as_str()) {
            (api::HttpMethod::GET, "/containers") => {
                // List containers
                let containers = microkernel::core::runtime::list_containers()?;
                let body = serde_json::to_vec(&containers)?;
                
                Ok(api::ApiResponse {
                    status_code: 200,
                    headers: hashmap!{
                        "Content-Type".to_string() => "application/json".to_string(),
                    },
                    body: Some(body),
                    metadata: HashMap::new(),
                })
            },
            (api::HttpMethod::POST, "/containers") => {
                // Create a container
                let config: ContainerConfig = serde_json::from_slice(
                    request.body.as_ref().ok_or_else(|| api::ApiError {
                        status_code: 400,
                        error_code: "MISSING_BODY".to_string(),
                        message: "Request body is required".to_string(),
                        details: None,
                    })?
                )?;
                
                let container_id = microkernel::core::runtime::launch_container(config)?;
                let body = serde_json::to_vec(&container_id)?;
                
                Ok(api::ApiResponse {
                    status_code: 201,
                    headers: hashmap!{
                        "Content-Type".to_string() => "application/json".to_string(),
                    },
                    body: Some(body),
                    metadata: HashMap::new(),
                })
            },
            _ => Err(api::ApiError {
                status_code: 404,
                error_code: "NOT_FOUND".to_string(),
                message: "Endpoint not found".to_string(),
                details: None,
            }),
        }
    }
}

// Register the API endpoint
api::register_endpoint(api::ApiEndpoint {
    path: "/containers".to_string(),
    method: api::HttpMethod::GET,
    handler: Box::new(ContainerHandler),
    auth_required: true,
    rate_limit_key: Some("containers".to_string()),
    documentation: api::ApiDocumentation {
        summary: "List containers".to_string(),
        description: "Returns a list of all containers".to_string(),
        parameters: vec![],
        responses: hashmap!{
            200 => "List of containers".to_string(),
            401 => "Unauthorized".to_string(),
            500 => "Internal server error".to_string(),
        },
    },
})?;

// Start the API server
api::start_server("0.0.0.0:8080")?;
```

### Using the Prelude
```rust
// Import the prelude
use microkernel::interface::prelude::*;

// Initialize the microkernel
init()?;

// Launch a container
let container_config = ContainerConfig::new("my-container");
let container_id = launch_container(container_config)?;

// Execute a syscall
let identity = IdentityContext::new("user@example.com");
let result = secure_syscall(
    "open_file",
    &["path/to/file", "r"],
    &identity,
)?;

// Check the result
match result {
    SyscallResult::Success(data) => {
        println!("Syscall succeeded: {:?}", data);
    },
    SyscallResult::Failure(error) => {
        println!("Syscall failed: {}", error.message);
    },
    SyscallResult::Blocked(reason) => {
        println!("Syscall blocked: {}", reason);
    },
    SyscallResult::Quarantined(reason) => {
        println!("Process quarantined: {}", reason);
    },
}

// Shutdown the microkernel
shutdown()?;
```

### Creating a Custom API Client
```rust
use microkernel::interface::api;

// Create a client
let client = api::ApiClient::new(
    "https://microkernel-api.example.com",
    Some("api-key"),
);

// List containers
let response = client.get("/containers", None)?;
let containers: Vec<ContainerInfo> = serde_json::from_slice(&response.body.unwrap())?;
println!("Containers: {:?}", containers);

// Create a container
let config = ContainerConfig::new("my-container");
let body = serde_json::to_vec(&config)?;
let response = client.post("/containers", Some(body), None)?;
let container_id: Uuid = serde_json::from_slice(&response.body.unwrap())?;
println!("Created container: {}", container_id);

// Stop a container
let response = client.delete(
    &format!("/containers/{}", container_id),
    None,
)?;
println!("Container stopped: {}", response.status_code == 204);
```

## Related Modules
- [Core Module](./core.md) - Provides functionality exposed through the Interface module
- [Execution Module](./execution.md) - Exposes syscall and container execution through the Interface
- [Trust Module](./trust.md) - Enforces security policies for Interface operations
- [Common Prelude Module](../common/prelude.md) - Integrates with the Microkernel Prelude
- [API Documentation](../api/README.md) - Provides detailed API documentation