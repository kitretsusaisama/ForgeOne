//! Execution interface for the ForgeOne Plugin Manager
//!
//! Provides a unified interface for executing WebAssembly plugins with
//! different runtime engines.

use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Plugin runtime engine type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineType {
    /// Wasmtime runtime engine
    Wasmtime,
    /// Wasmer runtime engine
    Wasmer,
}

/// Plugin runtime context
#[derive(Debug)]
pub struct PluginContext {
    /// Plugin ID
    pub plugin_id: uuid::Uuid,
    /// Plugin name
    pub plugin_name: String,
    /// Plugin memory limit in bytes
    pub memory_limit: usize,
    /// Plugin execution time limit in milliseconds
    pub time_limit: u64,
    /// Plugin identity context
    pub identity: Arc<IdentityContext>,
    /// Plugin environment variables
    pub env_vars: HashMap<String, String>,
    /// Plugin state
    pub state: HashMap<String, Vec<u8>>,
    /// Plugin instruction limit
    pub instruction_limit: Option<u64>,
    /// Plugin thread limit
    pub thread_limit: Option<u32>,
    /// Plugin file descriptor limit
    pub fd_limit: Option<u32>,
    /// Plugin CPU limit in percentage (0-100)
    pub cpu_limit: Option<u32>,
    /// Plugin I/O operations per second limit
    pub io_ops_limit: Option<u32>,
    /// Plugin network bandwidth limit in bytes per second
    pub network_bandwidth_limit: Option<u64>,
    /// Plugin filesystem access
    pub filesystem_access: bool,
    /// Plugin network access
    pub network_access: bool,
    /// Plugin process access
    pub process_access: bool,
    /// Plugin allowed syscalls
    pub allowed_syscalls: Option<Vec<String>>,
    /// Plugin namespace isolation (Linux only)
    #[cfg(target_os = "linux")]
    pub namespace_isolation: bool,
    /// Plugin seccomp filtering (Linux only)
    #[cfg(target_os = "linux")]
    pub seccomp_filtering: bool,
    /// Plugin capability dropping (Linux only)
    #[cfg(target_os = "linux")]
    pub capability_dropping: bool,
    /// Plugin temporary directory
    pub temp_directory: Option<std::path::PathBuf>,
}

/// Plugin runtime
#[derive(Debug)]
pub struct PluginRuntime {
    /// Runtime engine type
    pub engine_type: EngineType,
    /// Runtime context
    pub context: Arc<Mutex<PluginContext>>,
    /// Runtime instance
    #[cfg(feature = "wasmtime-runtime")]
    pub wasmtime_instance: Option<wasmtime::Instance>,
    #[cfg(feature = "wasmer-runtime")]
    pub wasmer_instance: Option<wasmer::Instance>,
    /// Runtime module
    #[cfg(feature = "wasmtime-runtime")]
    pub wasmtime_module: Option<wasmtime::Module>,
    #[cfg(feature = "wasmer-runtime")]
    pub wasmer_module: Option<wasmer::Module>,
    /// Runtime store
    #[cfg(feature = "wasmtime-runtime")]
    pub wasmtime_store: Option<wasmtime::Store<PluginContext>>,
    #[cfg(feature = "wasmer-runtime")]
    pub wasmer_store: Option<wasmer::Store>,
}

impl Clone for PluginContext {
    fn clone(&self) -> Self {
        Self {
            plugin_id: self.plugin_id.clone(),
            plugin_name: self.plugin_name.clone(),
            memory_limit: self.memory_limit,
            time_limit: self.time_limit,
            identity: self.identity.clone(),
            env_vars: self.env_vars.clone(),
            state: self.state.clone(),
            instruction_limit: self.instruction_limit,
            thread_limit: self.thread_limit,
            fd_limit: self.fd_limit,
            cpu_limit: self.cpu_limit,
            io_ops_limit: self.io_ops_limit,
            network_bandwidth_limit: self.network_bandwidth_limit,
            filesystem_access: self.filesystem_access,
            network_access: self.network_access,
            process_access: self.process_access,
            allowed_syscalls: self.allowed_syscalls.clone(),
            #[cfg(target_os = "linux")]
            namespace_isolation: self.namespace_isolation,
            #[cfg(target_os = "linux")]
            seccomp_filtering: self.seccomp_filtering,
            #[cfg(target_os = "linux")]
            capability_dropping: self.capability_dropping,
            temp_directory: self.temp_directory.clone(),
        }
    }
}

impl Clone for PluginRuntime {
    fn clone(&self) -> Self {
        Self {
            engine_type: self.engine_type,
            context: self.context.clone(),
            #[cfg(feature = "wasmtime-runtime")]
            wasmtime_instance: None,
            #[cfg(feature = "wasmer-runtime")]
            wasmer_instance: None,
            #[cfg(feature = "wasmtime-runtime")]
            wasmtime_module: None,
            #[cfg(feature = "wasmer-runtime")]
            wasmer_module: None,
            #[cfg(feature = "wasmtime-runtime")]
            wasmtime_store: None,
            #[cfg(feature = "wasmer-runtime")]
            wasmer_store: None,
        }
    }
}

impl PluginRuntime {
    /// Create a new plugin runtime
    pub fn new(engine_type: EngineType, context: PluginContext) -> Self {
        Self {
            engine_type,
            context: Arc::new(Mutex::new(context)),
            #[cfg(feature = "wasmtime-runtime")]
            wasmtime_instance: None,
            #[cfg(feature = "wasmer-runtime")]
            wasmer_instance: None,
            #[cfg(feature = "wasmtime-runtime")]
            wasmtime_module: None,
            #[cfg(feature = "wasmer-runtime")]
            wasmer_module: None,
            #[cfg(feature = "wasmtime-runtime")]
            wasmtime_store: None,
            #[cfg(feature = "wasmer-runtime")]
            wasmer_store: None,
        }
    }

    /// Load a WebAssembly module
    pub fn load_module<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        match self.engine_type {
            #[cfg(feature = "wasmtime-runtime")]
            EngineType::Wasmtime => {
                crate::runtime::wasmtime_engine::load_module(self, path.as_ref())?;
            }
            #[cfg(feature = "wasmer-runtime")]
            EngineType::Wasmer => {
                crate::runtime::wasmer_engine::load_module(self, path.as_ref())?;
            }
            _ => {
                return Err(ForgeError::NotImplemented(format!(
                    "Engine type {:?} not supported in this build",
                    self.engine_type
                )));
            }
        }
        Ok(())
    }

    /// Instantiate a WebAssembly module
    pub fn instantiate(&mut self) -> Result<()> {
        match self.engine_type {
            #[cfg(feature = "wasmtime-runtime")]
            EngineType::Wasmtime => {
                crate::runtime::wasmtime_engine::instantiate(self)?;
            }
            #[cfg(feature = "wasmer-runtime")]
            EngineType::Wasmer => {
                crate::runtime::wasmer_engine::instantiate(self)?;
            }
            _ => {
                return Err(ForgeError::NotImplemented(format!(
                    "Engine type {:?} not supported or not compiled in",
                    self.engine_type
                )));
            }
        }
        Ok(())
    }
    /// Call a function in the WebAssembly module
    pub fn call_func(&mut self, name: &str, args: &[Val]) -> Result<Vec<Val>> {
        match self.engine_type {
            EngineType::Wasmtime => {
                #[cfg(feature = "wasmtime-runtime")]
                {
                    crate::runtime::wasmtime_engine::call_func(self, name, args)
                }
                #[cfg(not(feature = "wasmtime-runtime"))]
                {
                    Err(ForgeError::NotImplemented(
                        "Wasmtime not compiled in".into(),
                    ))
                }
            }
            EngineType::Wasmer => {
                #[cfg(feature = "wasmer-runtime")]
                {
                    crate::runtime::wasmer_engine::call_func(self, name, args)
                }
                #[cfg(not(feature = "wasmer-runtime"))]
                {
                    Err(ForgeError::NotImplemented("Wasmer not compiled in".into()))
                }
            }
        }
    }
}

/// WebAssembly value
#[derive(Debug, Clone)]
pub enum Val {
    /// 32-bit integer
    I32(i32),
    /// 64-bit integer
    I64(i64),
    /// 32-bit float
    F32(f32),
    /// 64-bit float
    F64(f64),
    /// Reference
    Ref(u32),
    /// String
    String(String),
    /// Bytes
    Bytes(Vec<u8>),
}

impl PluginContext {
    /// Create a new plugin context
    pub fn new(plugin_id: uuid::Uuid, plugin_name: String, identity: Arc<IdentityContext>) -> Self {
        Self {
            plugin_id,
            plugin_name,
            memory_limit: 128 * 1024 * 1024, // 128 MB default
            time_limit: 30000,               // 30 seconds default
            identity,
            env_vars: HashMap::new(),
            state: HashMap::new(),
            instruction_limit: None,
            thread_limit: None,
            fd_limit: None,
            cpu_limit: None,
            io_ops_limit: None,
            network_bandwidth_limit: None,
            filesystem_access: false,
            network_access: false,
            process_access: false,
            allowed_syscalls: None,
            #[cfg(target_os = "linux")]
            namespace_isolation: false,
            #[cfg(target_os = "linux")]
            seccomp_filtering: false,
            #[cfg(target_os = "linux")]
            capability_dropping: false,
            temp_directory: None,
        }
    }

    /// Set instruction limit
    pub fn set_instruction_limit(&mut self, limit: u64) {
        self.instruction_limit = Some(limit);
    }

    /// Set thread limit
    pub fn set_thread_limit(&mut self, limit: u32) {
        self.thread_limit = Some(limit);
    }

    /// Set file descriptor limit
    pub fn set_fd_limit(&mut self, limit: u32) {
        self.fd_limit = Some(limit);
    }

    /// Set CPU limit
    pub fn set_cpu_limit(&mut self, limit: u32) {
        self.cpu_limit = Some(limit);
    }

    /// Set I/O operations limit
    pub fn set_io_ops_limit(&mut self, limit: u32) {
        self.io_ops_limit = Some(limit);
    }

    /// Set network bandwidth limit
    pub fn set_network_bandwidth_limit(&mut self, limit: u64) {
        self.network_bandwidth_limit = Some(limit);
    }

    /// Set filesystem access
    pub fn set_filesystem_access(&mut self, access: bool) {
        self.filesystem_access = access;
    }

    /// Set network access
    pub fn set_network_access(&mut self, access: bool) {
        self.network_access = access;
    }

    /// Set process access
    pub fn set_process_access(&mut self, access: bool) {
        self.process_access = access;
    }

    /// Set allowed syscalls
    pub fn set_allowed_syscalls(&mut self, syscalls: Vec<String>) {
        self.allowed_syscalls = Some(syscalls);
    }

    /// Set environment variable
    pub fn set_env_var(&mut self, key: &str, value: &str) {
        self.env_vars.insert(key.to_string(), value.to_string());
    }

    /// Set temporary directory
    pub fn set_temp_directory(&mut self, dir: std::path::PathBuf) {
        self.temp_directory = Some(dir);
    }

    #[cfg(target_os = "linux")]
    /// Set namespace isolation
    pub fn set_namespace_isolation(&mut self, enabled: bool) {
        self.namespace_isolation = enabled;
    }

    #[cfg(target_os = "linux")]
    /// Set seccomp filtering
    pub fn set_seccomp_filtering(&mut self, enabled: bool) {
        self.seccomp_filtering = enabled;
    }

    #[cfg(target_os = "linux")]
    /// Set capability dropping
    pub fn set_capability_dropping(&mut self, enabled: bool) {
        self.capability_dropping = enabled;
    }
}
