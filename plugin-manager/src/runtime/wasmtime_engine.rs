//! Wasmtime runtime engine for the ForgeOne Plugin Manager
//!
//! Provides a Wasmtime-based runtime engine for executing WebAssembly plugins.

#[cfg(feature = "wasmtime-runtime")]
use crate::runtime::execution::{PluginRuntime, Val};
#[cfg(feature = "wasmtime-runtime")]
use common::error::{ForgeError, Result};
#[cfg(feature = "wasmtime-runtime")]
use std::path::Path;
#[cfg(feature = "wasmtime-runtime")]
use wasmtime::{Engine, Linker, Module, Store};

#[cfg(feature = "wasmtime-runtime")]
/// Load a WebAssembly module using Wasmtime
pub fn load_module(runtime: &mut PluginRuntime, path: &Path) -> Result<()> {
    // Create engine
    let engine = Engine::default();

    // Create store
    let context = runtime.context.lock().unwrap().clone();
    let store = Store::new(&engine, context);
    runtime.wasmtime_store = Some(store);

    // Load module
    let module = Module::from_file(&engine, path)
        .map_err(|e| ForgeError::IoError(format!("Failed to load module: {}", e)))?;
    runtime.wasmtime_module = Some(module);

    Ok(())
}

#[cfg(feature = "wasmtime-runtime")]
/// Instantiate a WebAssembly module using Wasmtime
pub fn instantiate(runtime: &mut PluginRuntime) -> Result<()> {
    // Get module and store
    let module = runtime
        .wasmtime_module
        .as_ref()
        .ok_or_else(|| ForgeError::InvalidState("Module not loaded".to_string()))?;
    let mut store = runtime
        .wasmtime_store
        .take()
        .ok_or_else(|| ForgeError::InvalidState("Store not created".to_string()))?;

    // Create linker
    let mut linker = Linker::new(store.engine());

    // Link ABI functions
    crate::abi::vm::link_abi(&mut linker, &mut store)
        .map_err(|e| ForgeError::Other(format!("ABI link error: {}", e)))?;

    // Instantiate module
    let instance = linker
        .instantiate(&mut store, module)
        .map_err(|e| ForgeError::Other(format!("Failed to instantiate module: {}", e)))?;

    // Store instance and store
    runtime.wasmtime_instance = Some(instance);
    runtime.wasmtime_store = Some(store);

    Ok(())
}

#[cfg(feature = "wasmtime-runtime")]
/// Call a function in a WebAssembly module using Wasmtime
pub fn call_func(runtime: &mut PluginRuntime, name: &str, args: &[Val]) -> Result<Vec<Val>> {
    // Get instance and store
    let instance = runtime
        .wasmtime_instance
        .as_ref()
        .ok_or_else(|| ForgeError::Other("Instance not created".to_string()))?;
    let mut store = runtime
        .wasmtime_store
        .take()
        .ok_or_else(|| ForgeError::Other("Store not created".to_string()))?;

    // Get function
    let func = instance
        .get_func(&mut store, name)
        .ok_or_else(|| ForgeError::NotFound(format!("Function '{}' not found", name)))?;

    // Convert arguments
    let wasmtime_args = args
        .iter()
        .map(|arg| match arg {
            Val::I32(v) => wasmtime::Val::I32(*v),
            Val::I64(v) => wasmtime::Val::I64(*v),
            Val::F32(v) => wasmtime::Val::F32(v.to_bits()),
            Val::F64(v) => wasmtime::Val::F64(v.to_bits()),
            _ => wasmtime::Val::I32(0), // Default for unsupported types
        })
        .collect::<Vec<_>>();

    // Prepare result buffer
    let func_type = func.ty(&store);
    let result_count = func_type.results().len();
    let mut results = vec![wasmtime::Val::I32(0); result_count];

    // Call function
    func.call(&mut store, &wasmtime_args, &mut results)
        .map_err(|e| ForgeError::Other(format!("Failed to call function: {}", e)))?;

    // Convert results
    let results = results
        .into_iter()
        .map(|result| match result {
            wasmtime::Val::I32(v) => Val::I32(v),
            wasmtime::Val::I64(v) => Val::I64(v),
            wasmtime::Val::F32(v) => Val::F32(f32::from_bits(v)),
            wasmtime::Val::F64(v) => Val::F64(f64::from_bits(v)),
            _ => Val::I32(0), // Default for unsupported types
        })
        .collect::<Vec<_>>();

    // Restore store
    runtime.wasmtime_store = Some(store);

    Ok(results)
}

#[cfg(not(feature = "wasmtime-runtime"))]
pub fn load_module(
    _runtime: &mut crate::runtime::execution::PluginRuntime,
    _path: &std::path::Path,
) -> common::error::Result<()> {
    Err(common::error::ForgeError::NotImplemented(
        "Wasmtime runtime not enabled".to_string(),
    ))
}

#[cfg(not(feature = "wasmtime-runtime"))]
pub fn instantiate(
    _runtime: &mut crate::runtime::execution::PluginRuntime,
) -> common::error::Result<()> {
    Err(common::error::ForgeError::NotImplemented(
        "Wasmtime runtime not enabled".to_string(),
    ))
}

#[cfg(not(feature = "wasmtime-runtime"))]
pub fn call_func(
    _runtime: &mut crate::runtime::execution::PluginRuntime,
    _name: &str,
    _args: &[crate::runtime::execution::Val],
) -> common::error::Result<Vec<crate::runtime::execution::Val>> {
    Err(common::error::ForgeError::NotImplemented(
        "Wasmtime runtime not enabled".to_string(),
    ))
}
