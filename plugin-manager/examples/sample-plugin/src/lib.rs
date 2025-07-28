//! Sample ForgeOne Plugin
//!
//! This is a sample plugin for the ForgeOne Plugin Manager.

// Export the required functions
#[no_mangle]
pub extern "C" fn init() -> i32 {
    // Initialize the plugin
    log("Initializing sample plugin");
    0 // Success
}

#[no_mangle]
pub extern "C" fn start() -> i32 {
    // Start the plugin
    log("Starting sample plugin");

    // Get an environment variable
    let mut buffer = [0u8; 256];
    let len = get_env("FORGE_ENV", buffer.as_mut_ptr(), buffer.len() as i32);
    if len > 0 {
        let env_value = std::str::from_utf8(&buffer[0..len as usize]).unwrap_or("<invalid utf8>");
        log(&format!("Environment variable FORGE_ENV = {}", env_value));
    } else {
        log("Environment variable FORGE_ENV not found");
    }

    // Make a syscall
    let mut result_buffer = [0u8; 256];
    let syscall_result = syscall(
        "file_open /tmp/test.txt",
        result_buffer.as_mut_ptr(),
        result_buffer.len() as i32,
    );
    if syscall_result > 0 {
        let result = std::str::from_utf8(&result_buffer[0..syscall_result as usize])
            .unwrap_or("<invalid utf8>");
        log(&format!("Syscall result: {}", result));
    } else {
        log("Syscall failed");
    }

    0 // Success
}

#[no_mangle]
pub extern "C" fn stop() -> i32 {
    // Stop the plugin
    log("Stopping sample plugin");
    0 // Success
}

#[no_mangle]
pub extern "C" fn pause() -> i32 {
    // Pause the plugin
    log("Pausing sample plugin");
    0 // Success
}

#[no_mangle]
pub extern "C" fn resume() -> i32 {
    // Resume the plugin
    log("Resuming sample plugin");
    0 // Success
}

#[no_mangle]
pub extern "C" fn unload() -> i32 {
    // Unload the plugin
    log("Unloading sample plugin");
    0 // Success
}

// Host functions

/// Log a message to the host
fn log(message: &str) {
    unsafe {
        __log(message.as_ptr() as i32, message.len() as i32);
    }
}

/// Get an environment variable from the host
fn get_env(key: &str, value_ptr: *mut u8, value_len: i32) -> i32 {
    unsafe {
        __get_env(
            key.as_ptr() as i32,
            key.len() as i32,
            value_ptr as i32,
            value_len,
        )
    }
}

/// Make a syscall to the host
fn syscall(call: &str, result_ptr: *mut u8, result_len: i32) -> i32 {
    unsafe {
        __syscall(
            call.as_ptr() as i32,
            call.len() as i32,
            result_ptr as i32,
            result_len,
        )
    }
}

// External host functions
extern "C" {
    fn __log(ptr: i32, len: i32);
    fn __get_env(key_ptr: i32, key_len: i32, value_ptr: i32, value_len: i32) -> i32;
    fn __syscall(call_ptr: i32, call_len: i32, result_ptr: i32, result_len: i32) -> i32;
}