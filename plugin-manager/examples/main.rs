//! Example usage of the ForgeOne Plugin Manager

use common::identity::IdentityContext as Identity;
use plugin_manager::registry::PluginRegistry;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Initialize the plugin manager
    plugin_manager::init()?;

    // Create a plugin registry
    let mut registry = PluginRegistry::new();

    // Create an identity for verification
    let identity = Identity::new(
        "plugin-manager-example".to_string(),
        "plugin-manager-example".to_string(),
    );

    // Get the path to the sample plugin
    let plugin_path = get_sample_plugin_path()?;
    info!("Loading plugin from {}", plugin_path.display());

    // Load the plugin
    let _plugin = registry.load_plugin(plugin_path, identity)?;

    // Initialize all plugins
    registry.initialize_all()?;
    info!("Initialized all plugins");

    // Start all plugins
    registry.start_all()?;
    info!("Started all plugins");

    // Wait for a bit
    info!("Waiting for 5 seconds...");
    std::thread::sleep(Duration::from_secs(5));

    // Stop all plugins
    registry.stop_all()?;
    info!("Stopped all plugins");

    // Unload all plugins
    registry.unload_all()?;
    info!("Unloaded all plugins");

    Ok(())
}

/// Get the path to the sample plugin
fn get_sample_plugin_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
    // In a real application, this would be a path to a .forgepkg file
    // For this example, we'll use a path to the sample plugin directory
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("examples");
    path.push("sample-plugin");
    path.push("target");
    path.push("wasm32-unknown-unknown");
    path.push("release");
    path.push("sample_plugin.wasm");

    if !path.exists() {
        return Err(format!(
            "Sample plugin not found at {}. Did you build it with 'cargo build --target wasm32-unknown-unknown --release'?",
            path.display()
        ).into());
    }

    Ok(path)
}
