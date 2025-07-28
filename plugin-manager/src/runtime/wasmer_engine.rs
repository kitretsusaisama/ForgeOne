//! Wasmer runtime engine for the ForgeOne Plugin Manager
//!
//! Provides a Wasmer-based runtime engine for executing WebAssembly plugins.

#[cfg(feature = "wasmer-runtime")]
use crate::runtime::execution::{PluginRuntime, Val};
#[cfg(feature = "wasmer-runtime")]
use common::error::{ForgeError, Result};
#[cfg(feature = "wasmer-runtime")]
use std::path::Path;
#[cfg(feature = "wasmer-runtime")]
use wasmer::{imports, Function, Instance, Module, Store};

#[cfg(feature = "wasmer-runtime")]
/// Load a WebAssembly module using Wasmer
pub fn load_module(runtime: &mut PluginRuntime, path: &Path) -> Result<()> {
    // Create store
    let store = Store::default();
    runtime.wasmer_store = Some(store.clone());

    // Load module
    let module = Module::from_file(&store, path)
        .map_err(|e| ForgeError::InvalidInput(format!("Failed to load module: {}", e)))?;
    runtime.wasmer_module = Some(module);

    Ok(())
}

#[cfg(feature = "wasmer-runtime")]
/// Instantiate a WebAssembly module using Wasmer
pub fn instantiate(runtime: &mut PluginRuntime) -> Result<()> {
    // Get module and store
    let module = runtime.wasmer_module.as_ref().ok_or_else(|| {
        ForgeError::InvalidState("Module not loaded".to_string())
    })?;
    let store = runtime.wasmer_store.as_ref().ok_or_else(|| {
        ForgeError::InvalidState("Store not created".to_string())
    })?;

    // Create import object
    let import_object = imports! {};

    // Instantiate module
    let instance = Instance::new(module, &import_object)
        .map_err(|e| ForgeError::RuntimeError(format!("Failed to instantiate module: {}", e)))?;

    // Store instance
    runtime.wasmer_instance = Some(instance);

    Ok(())
}

#[cfg(feature = "wasmer-runtime")]
/// Call a function in a WebAssembly module using Wasmer
pub fn call_func(runtime: &mut PluginRuntime, name: &str, args: &[Val]) -> Result<Vec<Val>> {
    // Get instance
    let instance = runtime.wasmer_instance.as_ref().ok_or_else(|| {
        ForgeError::InvalidState("Instance not created".to_string())
    })?;

    // Get function
    let func = instance
        .exports
        .get_function(name)
        .map_err(|e| ForgeError::NotFound(format!("Function '{}' not found: {}", name, e)))?;

    // Convert arguments
    let wasmer_args = args
        .iter()
        .map(|arg| match arg {
            Val::I32(v) => wasmer::Value::I32(*v),
            Val::I64(v) => wasmer::Value::I64(*v),
            Val::F32(v) => wasmer::Value::F32(*v),
            Val::F64(v) => wasmer::Value::F64(*v),
            _ => wasmer::Value::I32(0), // Default for unsupported types
        })
        .collect::<Vec<_>>();

    // Call function
    let results = func
        .call(&wasmer_args)
        .map_err(|e| ForgeError::RuntimeError(format!("Failed to call function: {}", e)))?;

    // Convert results
    let results = results
        .into_iter()
        .map(|result| match result {
            wasmer::Value::I32(v) => Val::I32(v),
            wasmer::Value::I64(v) => Val::I64(v),
            wasmer::Value::F32(v) => Val::F32(v),
            wasmer::Value::F64(v) => Val::F64(v),
            _ => Val::I32(0), // Default for unsupported types
        })
        .collect::<Vec<_>>();

    Ok(results)
}

#[cfg(not(feature = "wasmer-runtime"))]
pub fn load_module(_runtime: &mut crate::runtime::execution::PluginRuntime, _path: &std::path::Path) -> common::error::Result<()> {
    Err(common::error::ForgeError::NotImplemented(
        "Wasmer runtime not enabled".to_string(),
    ))
}

#[cfg(not(feature = "wasmer-runtime"))]
pub fn instantiate(_runtime: &mut crate::runtime::execution::PluginRuntime) -> common::error::Result<()> {
    Err(common::error::ForgeError::NotImplemented(
        "Wasmer runtime not enabled".to_string(),
    ))
}

#[cfg(not(feature = "wasmer-runtime"))]
pub fn call_func(
    _runtime: &mut crate::runtime::execution::PluginRuntime,
    _name: &str,
    _args: &[crate::runtime::execution::Val],
) -> common::error::Result<Vec<crate::runtime::execution::Val>> {
    Err(common::error::ForgeError::NotImplemented(
        "Wasmer runtime not enabled".to_string(),
    ))
}