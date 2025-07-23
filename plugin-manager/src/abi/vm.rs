//! VM ABI for the ForgeOne Plugin Manager
//!
//! Provides the Application Binary Interface (ABI) for communication between
//! the host and WebAssembly plugins, including memory access and function calls.

use crate::runtime::execution::PluginContext;
use common::error::{ForgeError, Result};
use std::sync::Arc;
use wasmtime::Trap;

#[cfg(feature = "wasmtime-runtime")]
use wasmtime::{Caller, Linker};

/// Link ABI functions to a Wasmtime linker
#[cfg(feature = "wasmtime-runtime")]
pub fn link_abi(
    linker: &mut Linker<PluginContext>,
    store: &mut wasmtime::Store<PluginContext>,
) -> wasmtime::Result<()> {
    // Log function
    linker.func_wrap(
        "env",
        "log",
        |mut caller: Caller<'_, PluginContext>, ptr: i32, len: i32| -> wasmtime::Result<()> {
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(memory)) => memory,
                _ => return Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            };

            let data = match read_memory(&mut caller, memory, ptr as usize, len as usize) {
                Ok(data) => data,
                Err(_) => return Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            };

            let message = match std::str::from_utf8(&data) {
                Ok(s) => s,
                Err(_) => return Err(wasmtime::Error::new(Trap::BadConversionToInteger)),
            };

            let context = caller.data();
            tracing::info!(plugin_id = %context.plugin_id, plugin_name = %context.plugin_name, message = %message, "Plugin log");

            Ok(())
        },
    )?;

    // Get environment variable function
    linker.func_wrap(
        "env",
        "get_env",
        |mut caller: Caller<'_, PluginContext>,
         key_ptr: i32,
         key_len: i32,
         value_ptr: i32,
         value_len: i32|
         -> wasmtime::Result<i32> {
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(memory)) => memory,
                _ => return Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            };

            let key_data =
                match read_memory(&mut caller, memory, key_ptr as usize, key_len as usize) {
                    Ok(data) => data,
                    Err(_) => return Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
                };

            let key = match std::str::from_utf8(&key_data) {
                Ok(s) => s,
                Err(_) => return Err(wasmtime::Error::new(Trap::BadConversionToInteger)),
            };

            let context = caller.data();
            let value = match context.env_vars.get(key) {
                Some(value) => value.clone(), // clone here
                None => return Ok(0),
            };
            let value_bytes = value.as_bytes();
            if value_bytes.len() > value_len as usize {
                return Ok(-1); // Buffer too small
            }

            match write_memory(&mut caller, memory, value_ptr as usize, value_bytes) {
                Ok(_) => Ok(value_bytes.len() as i32),
                Err(_) => Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            }
        },
    )?;

    // Syscall function
    linker.func_wrap(
        "env",
        "syscall",
        |mut caller: Caller<'_, PluginContext>,
         syscall_ptr: i32,
         syscall_len: i32,
         result_ptr: i32,
         result_len: i32|
         -> wasmtime::Result<i32> {
            let memory = match caller.get_export("memory") {
                Some(wasmtime::Extern::Memory(memory)) => memory,
                _ => return Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            };

            let syscall_data = match read_memory(
                &mut caller,
                memory,
                syscall_ptr as usize,
                syscall_len as usize,
            ) {
                Ok(data) => data,
                Err(_) => return Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            };

            let syscall = match std::str::from_utf8(&syscall_data) {
                Ok(s) => s,
                Err(_) => return Err(wasmtime::Error::new(Trap::BadConversionToInteger)),
            };

            let context = caller.data();
            let parts: Vec<&str> = syscall.split_whitespace().collect();
            if parts.is_empty() {
                return Err(wasmtime::Error::new(Trap::UnreachableCodeReached));
            }
            let syscall_name = parts[0];
            let args = &parts[1..];
            // TODO: Implement actual syscall logic or stub as needed
            let result = match syscall_name {
                _ => format!("error: Unknown syscall '{}'.", syscall_name),
            };
            let result_bytes = result.as_bytes();
            if result_bytes.len() > result_len as usize {
                return Ok(-1); // Buffer too small
            }

            match write_memory(&mut caller, memory, result_ptr as usize, result_bytes) {
                Ok(_) => Ok(result_bytes.len() as i32),
                Err(_) => Err(wasmtime::Error::new(Trap::MemoryOutOfBounds)),
            }
        },
    )?;

    Ok(())
}

/// Read memory from a WebAssembly module
#[cfg(feature = "wasmtime-runtime")]
fn read_memory(
    caller: &mut Caller<'_, PluginContext>,
    memory: wasmtime::Memory,
    offset: usize,
    len: usize,
) -> wasmtime::Result<Vec<u8>> {
    let mut buffer = vec![0; len];
    memory
        .read(caller, offset, &mut buffer)
        .map_err(|e| wasmtime::Error::msg(format!("Failed to read memory: {}", e)))?;
    Ok(buffer)
}

/// Write memory to a WebAssembly module
#[cfg(feature = "wasmtime-runtime")]
fn write_memory(
    caller: &mut Caller<'_, PluginContext>,
    memory: wasmtime::Memory,
    offset: usize,
    data: &[u8],
) -> wasmtime::Result<()> {
    memory
        .write(caller, offset, data)
        .map_err(|e| wasmtime::Error::msg(format!("Failed to write memory: {}", e)))?;
    Ok(())
}

/// Link ABI functions to a Wasmer instance
#[cfg(feature = "wasmer-runtime")]
pub fn link_abi(_instance: &wasmer::Instance) -> Result<()> {
    // TODO: Implement Wasmer ABI linking
    Err(ForgeError::NotImplemented(
        "Wasmer ABI linking not implemented".to_string(),
    ))
}

#[cfg(not(any(feature = "wasmtime-runtime", feature = "wasmer-runtime")))]
pub fn link_abi() -> Result<()> {
    Err(ForgeError::NotImplemented(
        "No WebAssembly runtime engine available".to_string(),
    ))
}
