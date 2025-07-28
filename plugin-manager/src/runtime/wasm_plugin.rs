//! WebAssembly Plugin Support for ForgeOne Plugin Manager
//!
//! This module provides support for loading and executing WebAssembly (WASM) plugins
//! in a secure, sandboxed environment. It integrates with the ForgeOne Microkernel
//! for secure syscall execution and trust evaluation.

use crate::plugin::{Plugin, PluginInstance, PluginManifest, PluginState};
use crate::runtime::execution::{EngineType, PluginContext, PluginRuntime, Val};
use crate::sandbox::{self, SandboxConfig};
use common::error::{ForgeError, Result};
use common::identity::IdentityContext;
use common::telemetry::{self, MetricType};
use microkernel::trust::{self, ViolationAction};
use std::any::Any;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// WebAssembly Plugin
#[derive(Debug)]
pub struct WasmPlugin {
    /// Plugin instance
    instance: PluginInstance,
    /// Plugin runtime
    runtime: PluginRuntime,
    /// Plugin sandbox configuration
    sandbox_config: SandboxConfig,
    /// Plugin WASM module path
    module_path: PathBuf,
    /// Plugin identity context (used for trust evaluation)
    identity: Arc<IdentityContext>,
}

impl WasmPlugin {
    /// Create a new WebAssembly plugin
    pub fn new(
        manifest: PluginManifest,
        module_path: PathBuf,
        engine_type: EngineType,
        sandbox_config: SandboxConfig,
        tenant_id: String,
        user_id: String,
    ) -> Result<Self> {
        // Create identity context
        let identity = Arc::new(IdentityContext::new(tenant_id, user_id));

        // Create plugin context
        let context = PluginContext::new(
            uuid::Uuid::new_v4(),
            manifest.name.clone(),
            identity.clone(),
        );

        // Create plugin runtime
        let runtime = PluginRuntime::new(engine_type, context);

        // Create plugin instance
        let instance = PluginInstance::new(
            manifest,
            runtime.clone(),
            module_path.clone(),
            (*identity).clone(),
        );

        Ok(Self {
            instance,
            runtime,
            sandbox_config,
            module_path,
            identity,
        })
    }

    /// Load the WebAssembly module
    pub fn load(&mut self) -> Result<()> {
        // Use PerformanceTimer for timing
        let timer =
            telemetry::PerformanceTimer::new(format!("plugin_load_{}", self.instance.name()), true);

        let mut context = self.runtime.context.lock().unwrap();
        let sandboxed_context = sandbox::create_sandbox(
            (*context).clone(),
            self.sandbox_config.clone(),
            &self.instance,
        )?;
        *context = sandboxed_context;

        drop(context);

        // Load module
        self.runtime.load_module(&self.module_path)?;

        // Instantiate module
        self.runtime.instantiate()?;

        // Timer auto-reports on drop
        drop(timer);

        Ok(())
    }

    /// Call a function in the WebAssembly module
    pub fn call_function(&mut self, name: &str, args: &[Val]) -> Result<Vec<Val>> {
        // Start execution timer
        let start_time = Instant::now();

        // Evaluate trust before executing
        let syscall_name = format!("wasm_call_{}", name);
        let args_str: Vec<String> = args.iter().map(|v| format!("{:?}", v)).collect();
        let action = trust::evaluate_syscall(&syscall_name, &args_str, (*self.identity).clone())
            .map_err(|e| ForgeError::Other(format!("Trust evaluation failed: {e}")))?;

        match action {
            ViolationAction::Allow | ViolationAction::Warn => {
                // Execute function in sandbox
                let context = {
                    let guard = self.runtime.context.lock().unwrap();
                    guard.clone()
                };
                let result = sandbox::execute_in_sandbox(&context, &self.instance, || {
                    self.runtime.call_func(name, args)
                })?;

                // Record telemetry (histogram)
                let execution_time = start_time.elapsed().as_secs_f64();
                let mut labels = HashMap::new();
                labels.insert("plugin_id".to_string(), self.instance.id.to_string());
                labels.insert("plugin_name".to_string(), self.instance.name().to_string());
                labels.insert("function".to_string(), name.to_string());
                let _ = telemetry::record_histogram(
                    "plugin_wasm_function_call",
                    "Execution time of WASM plugin function call",
                    vec![execution_time],
                    labels,
                );

                Ok(result)
            }
            _ => Err(ForgeError::SecurityError(format!(
                "Trust evaluation denied function call: {} (action: {:?})",
                name, action
            ))),
        }
    }

    pub fn instance(&self) -> &PluginInstance {
        &self.instance
    }
}

impl Plugin for WasmPlugin {
    fn id(&self) -> uuid::Uuid {
        self.instance.id
    }

    fn name(&self) -> &str {
        self.instance.name()
    }

    fn version(&self) -> &str {
        self.instance.version()
    }

    fn description(&self) -> &str {
        self.instance.description()
    }

    fn initialize(&mut self) -> Result<()> {
        self.call_function("_initialize", &[])?;
        Ok(())
    }

    fn start(&mut self) -> Result<()> {
        self.call_function("_start", &[])?;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.call_function("_stop", &[])?;
        Ok(())
    }

    fn pause(&mut self) -> Result<()> {
        self.call_function("_pause", &[])?;
        Ok(())
    }

    fn resume(&mut self) -> Result<()> {
        self.call_function("_resume", &[])?;
        Ok(())
    }

    fn shutdown(&mut self) -> Result<()> {
        // Call shutdown function if it exists
        let _ = self.call_function("_shutdown", &[]);

        // Clean up sandbox
        sandbox::cleanup_sandbox(&self.runtime.context.lock().unwrap(), &self.instance)?;

        Ok(())
    }

    fn capabilities(&self) -> Vec<String> {
        self.instance
            .manifest
            .capabilities
            .clone()
            .unwrap_or_default()
    }

    fn permissions(&self) -> Vec<String> {
        self.instance
            .manifest
            .permissions
            .clone()
            .unwrap_or_default()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn identity(&self) -> Arc<IdentityContext> {
        self.identity.clone()
    }

    fn state(&self) -> PluginState {
        self.instance.state
    }

    fn call_function(&mut self, function_name: &str, args: Vec<String>) -> Result<String> {
        let args_val: Vec<Val> = args.into_iter().map(Val::String).collect();
        let result_vec = self.runtime.call_func(function_name, &args_val)?;
        let result_str = result_vec
            .into_iter()
            .map(|v| format!("{:?}", v))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(result_str)
    }
}

/// Create a new WebAssembly plugin from a WASM file
pub fn load_wasm_plugin(
    manifest_path: &Path,
    wasm_path: &Path,
    tenant_id: String,
    user_id: String,
) -> Result<WasmPlugin> {
    // Load manifest
    let manifest = PluginManifest::from_file(manifest_path)?;

    // Create sandbox config
    let sandbox_config = SandboxConfig::default();

    // Create WASM plugin
    let mut plugin = WasmPlugin::new(
        manifest,
        wasm_path.to_path_buf(),
        EngineType::Wasmtime, // Default to Wasmtime
        sandbox_config,
        tenant_id,
        user_id,
    )?;

    // Load plugin
    plugin.load()?;

    Ok(plugin)
}
