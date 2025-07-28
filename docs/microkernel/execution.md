# Microkernel Execution Module

*This document is production-ready, MNC-grade, and compliance-focused. All features, processes, and responsibilities are mapped to SOC2, ISO 27001, GDPR, and enterprise SLAs. Security, audit, and evidence generation are integral to every step.*

---

## Overview
The Execution module is responsible for securely running containers and plugins within the ForgeOne microkernel. It provides a sandboxed WASM runtime, plugin execution capabilities, and a secure syscall entrypoint with comprehensive Zero Trust Architecture (ZTA) enforcement. All actions are logged and exportable for audit and compliance.

## Key Features

### WASM Runtime (Sandboxed)
- **Secure Isolation**: Executes WebAssembly modules in a sandboxed environment
- **Memory Safety**: Enforces strict memory boundaries and prevents unauthorized access
- **Resource Limiting**: Applies configurable resource constraints to WASM modules
- **Hot Reloading**: Supports dynamic loading and unloading of WASM modules
- **Auditability**: All WASM module loads, executions, and failures are logged and exportable

### Plugin Execution & ABI Adapter
- **Plugin Lifecycle Management**: Controls the complete lifecycle of plugins
- **ABI Translation**: Provides a consistent Application Binary Interface for plugins
- **Capability-Based Access**: Restricts plugin capabilities based on trust level
- **Version Compatibility**: Ensures compatibility between plugins and the microkernel
- **Auditability**: All plugin lifecycle events and capability changes are logged and exportable

### Secure Syscall Entrypoint
- **ZTA Enforcement**: Applies Zero Trust policies to all syscalls
- **Comprehensive Auditing**: Records all syscall attempts and outcomes
- **Context-Aware Decisions**: Considers identity, trust vector, and execution history
- **Automatic Quarantine**: Isolates compromised processes upon policy violations
- **Auditability**: All syscall events, denials, and quarantines are logged and exportable

## Core Components

### WASM Host Module
```rust
pub struct WasmHost {
    pub id: Uuid,
    pub engine: WasmEngine,
    pub modules: HashMap<String, WasmModule>,
    pub memory_limit: usize,
    pub execution_timeout: Duration,
    pub status: WasmHostStatus,
}

pub enum WasmEngine {
    Wasmtime(wasmtime::Engine),
    Wasmer(wasmer::Engine),
    Custom(Box<dyn WasmEngineInterface>),
}

pub struct WasmModule {
    pub name: String,
    pub hash: String,
    pub instance: WasmInstance,
    pub exports: Vec<WasmExport>,
    pub imports: Vec<WasmImport>,
    pub memory_usage: usize,
    pub load_time: chrono::DateTime<chrono::Utc>,
}

pub enum WasmHostStatus {
    Initializing,
    Ready,
    Running,
    Error(String),
    Terminated,
}
```

### Plugin Host Module
```rust
pub struct PluginHost {
    pub id: Uuid,
    pub plugins: HashMap<Uuid, Plugin>,
    pub capabilities: CapabilitySet,
    pub status: PluginHostStatus,
}

pub struct Plugin {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub wasm_module: Option<String>,
    pub native_library: Option<String>,
    pub capabilities: CapabilitySet,
    pub trust_level: TrustLevel,
    pub status: PluginStatus,
}

pub struct CapabilitySet {
    pub syscalls: HashSet<String>,
    pub resources: HashSet<String>,
    pub apis: HashSet<String>,
    pub custom: HashMap<String, String>,
}

pub enum TrustLevel {
    Core,
    Trusted,
    Standard,
    Limited,
    Quarantined,
}

pub enum PluginStatus {
    Loading,
    Active,
    Paused,
    Failed(String),
    Unloaded,
}
```

### Syscall Module
```rust
pub struct SyscallContext {
    pub syscall: String,
    pub args: Vec<String>,
    pub identity: IdentityContext,
    pub trust_vector: TrustVector,
    pub execution_dna: Option<&mut ExecutionDNA>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

pub enum SyscallResult {
    Success(Option<Vec<u8>>),
    Failure(SyscallError),
    Blocked(String),
    Quarantined(String),
}

pub struct SyscallError {
    pub code: i32,
    pub message: String,
    pub context: HashMap<String, String>,
}

pub struct SyscallRegistry {
    pub syscalls: HashMap<String, SyscallHandler>,
    pub policies: HashMap<String, SyscallPolicy>,
}

pub type SyscallHandler = fn(SyscallContext) -> Result<Option<Vec<u8>>, SyscallError>;

pub struct SyscallPolicy {
    pub syscall: String,
    pub min_trust_level: TrustLevel,
    pub allowed_identities: Option<HashSet<String>>,
    pub denied_identities: Option<HashSet<String>>,
    pub arg_constraints: HashMap<usize, String>,
    pub custom_validator: Option<fn(&SyscallContext) -> bool>,
}
```

## Usage Examples

### Loading and Executing WASM Modules
```rust
use microkernel::execution::wasm_host;

// Create a new WASM host
let mut host = wasm_host::WasmHost::new()?;

// Load a WASM module
let module_bytes = std::fs::read("my_module.wasm")?;
let module = host.load_module("my_module", &module_bytes)?;

// Call a function in the WASM module
let result = host.call_function("my_module", "add", &[1.into(), 2.into()])?;
println!("Result: {:?}", result);

// Unload the module
host.unload_module("my_module")?;
```

### Managing Plugins
```rust
use microkernel::execution::plugin_host;

// Create a new plugin host
let mut host = plugin_host::PluginHost::new()?;

// Define plugin capabilities
let mut capabilities = plugin_host::CapabilitySet::new();
capabilities.syscalls.insert("read_file".to_string());
capabilities.syscalls.insert("write_file".to_string());

// Load a plugin
let plugin_config = plugin_host::PluginConfig {
    name: "my_plugin".to_string(),
    version: "1.0.0".to_string(),
    wasm_module: Some("my_plugin.wasm".to_string()),
    capabilities,
    trust_level: plugin_host::TrustLevel::Standard,
};

let plugin_id = host.load_plugin(plugin_config)?;

// Start the plugin
host.start_plugin(plugin_id)?;

// Stop and unload the plugin
host.stop_plugin(plugin_id)?;
host.unload_plugin(plugin_id)?;
```

### Executing Syscalls with ZTA Enforcement
```rust
use microkernel::execution::syscall;
use microkernel::trust::zta_policy;

// Create a syscall context
let mut execution_dna = ExecutionDNA::new(container_id, identity.clone());
let syscall_context = syscall::SyscallContext {
    syscall: "open_file".to_string(),
    args: vec!["path/to/file".to_string(), "r".to_string()],
    identity: identity.clone(),
    trust_vector: identity.trust_vector.clone(),
    execution_dna: Some(&mut execution_dna),
    timestamp: chrono::Utc::now(),
};

// Get the ZTA policy graph
let policy_graph = zta_policy::get_policy_graph();

// Execute the syscall with ZTA enforcement
let result = syscall::secure_syscall(syscall_context, &policy_graph);

// Handle the result
match result {
    syscall::SyscallResult::Success(data) => {
        println!("Syscall succeeded: {:?}", data);
    },
    syscall::SyscallResult::Failure(error) => {
        println!("Syscall failed: {}", error.message);
    },
    syscall::SyscallResult::Blocked(reason) => {
        println!("Syscall blocked: {}", reason);
    },
    syscall::SyscallResult::Quarantined(reason) => {
        println!("Process quarantined: {}", reason);
    },
}
```

## Operational & Compliance Guarantees
- **All WASM, plugin, and syscall actions are logged, versioned, and exportable for audit and regulatory review.**
- **Security Note:** Never embed secrets or credentials in code or configuration. Use environment variables and secure storage only.
- **Error Handling:** All API calls and module functions return detailed error types. All errors are logged and can be exported for audit.
- **Integration:** The execution module exposes a stable ABI and API for integration with external systems, plugins, and observability tools.
- **Review:** All procedures and code are reviewed quarterly and after every major incident or regulatory change.

## Troubleshooting
- **WASM Module Load Failure:** Ensure the module is valid, signed if required, and compatible with the selected engine. Check logs for error details.
- **Plugin Failure:** Validate plugin configuration, capabilities, and trust level. All failures are logged with full context.
- **Syscall Denied/Quarantined:** Review ZTA policy and trust vector. All denials and quarantines are logged and exportable.
- **Audit/Compliance Issues:** Ensure all logs and evidence are retained and accessible for review.

## Related Modules
- [Core Module](./core.md) - Provides the runtime orchestration used by the Execution module
- [Trust Module](./trust.md) - Supplies the ZTA policies enforced by the Execution module
- [Observer Module](./observer.md) - Records and analyzes execution activities
- [Common Identity Module](../common/identity.md) - Provides identity context for execution
- [Common Trust Module](../common/trust.md) - Supplies trust vectors for execution decisions

---

*This document is reviewed quarterly and after every major incident or regulatory change. For questions, contact the ForgeOne compliance or platform engineering team.*