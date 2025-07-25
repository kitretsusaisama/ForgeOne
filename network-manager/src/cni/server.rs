//! # CNI Server Implementation
//!
//! This module implements a CNI server that listens on a Unix socket and handles CNI requests
//! from container runtimes.

use super::{CniCommand, CniConfig, CniError, CniResult, CniVersion};
use crate::model::VirtualNetwork;
use crate::vnet::VNetManager;
use common::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// CNI server request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniRequest {
    /// CNI command
    pub command: CniCommand,
    /// Container ID
    pub container_id: String,
    /// Network namespace path
    pub netns_path: String,
    /// Interface name
    pub ifname: String,
    /// Network name
    pub network_name: String,
    /// Additional arguments
    pub args: serde_json::Value,
}

/// CNI server response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniResponse {
    /// Success flag
    pub success: bool,
    /// Result (if success)
    pub result: Option<CniResult>,
    /// Error (if not success)
    pub error: Option<CniError>,
}

/// CNI server
pub struct CniServer {
    /// Configuration
    config: CniConfig,
    /// Virtual network manager
    vnet_manager: Arc<RwLock<VNetManager>>,
    /// Listener
    listener: Option<UnixListener>,
    /// Running flag
    running: bool,
}

impl CniServer {
    /// Create a new CNI server
    pub fn new(config: CniConfig, vnet_manager: Arc<RwLock<VNetManager>>) -> Self {
        Self {
            config,
            vnet_manager,
            listener: None,
            running: false,
        }
    }

    /// Start the CNI server
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        info!("Starting CNI server on {}", self.config.socket_path.display());

        // Create the socket directory if it doesn't exist
        if let Some(parent) = self.config.socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    ForgeError::NetworkError(format!(
                        "Failed to create socket directory: {}",
                        e
                    ))
                })?;
            }
        }

        // Remove the socket file if it exists
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path).map_err(|e| {
                ForgeError::NetworkError(format!("Failed to remove socket file: {}", e))
            })?;
        }

        // Create the listener
        #[cfg(target_family = "unix")]
        {
            self.listener = Some(
                UnixListener::bind(&self.config.socket_path).map_err(|e| {
                    ForgeError::NetworkError(format!("Failed to bind socket: {}", e))
                })?,
            );
        }

        #[cfg(not(target_family = "unix"))]
        {
            warn!("Unix sockets are not supported on this platform. CNI server will not start.");
            return Ok(());
        }

        self.running = true;

        // Start the server loop
        self.run_server_loop().await
    }

    /// Run the server loop
    async fn run_server_loop(&mut self) -> Result<()> {
        #[cfg(target_family = "unix")]
        {
            let listener = self.listener.as_ref().unwrap();
            let vnet_manager = self.vnet_manager.clone();
            let config = self.config.clone();

            // Spawn a task to handle connections
            tokio::spawn(async move {
                info!("CNI server loop started");

                loop {
                    match listener.accept().await {
                        Ok((stream, _addr)) => {
                            let vnet_manager = vnet_manager.clone();
                            let config = config.clone();

                            // Spawn a task to handle the connection
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, vnet_manager, config).await {
                                    error!("Error handling CNI connection: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Error accepting CNI connection: {}", e);
                        }
                    }
                }
            });
        }

        Ok(())
    }

    /// Stop the CNI server
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("Stopping CNI server");

        self.running = false;
        self.listener = None;

        // Remove the socket file
        if self.config.socket_path.exists() {
            std::fs::remove_file(&self.config.socket_path).map_err(|e| {
                ForgeError::NetworkError(format!("Failed to remove socket file: {}", e))
            })?;
        }

        Ok(())
    }
}

/// Handle a CNI connection
#[cfg(target_family = "unix")]
async fn handle_connection(
    mut stream: UnixStream,
    vnet_manager: Arc<RwLock<VNetManager>>,
    config: CniConfig,
) -> Result<()> {
    // Read the request
    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer).await.map_err(|e| {
        ForgeError::NetworkError(format!("Failed to read from socket: {}", e))
    })?;

    // Parse the request
    let request: CniRequest = serde_json::from_slice(&buffer).map_err(|e| {
        ForgeError::NetworkError(format!("Failed to parse CNI request: {}", e))
    })?;

    // Handle the request
    let response = handle_request(request, vnet_manager, config).await;

    // Serialize the response
    let response_json = serde_json::to_vec(&response).map_err(|e| {
        ForgeError::NetworkError(format!("Failed to serialize CNI response: {}", e))
    })?;

    // Write the response
    stream.write_all(&response_json).await.map_err(|e| {
        ForgeError::NetworkError(format!("Failed to write to socket: {}", e))
    })?;

    Ok(())
}

/// Handle a CNI request
async fn handle_request(
    request: CniRequest,
    vnet_manager: Arc<RwLock<VNetManager>>,
    config: CniConfig,
) -> CniResponse {
    info!(
        "Handling CNI request: {:?} for container {} on network {}",
        request.command, request.container_id, request.network_name
    );

    match request.command {
        CniCommand::Add => handle_add(request, vnet_manager, config).await,
        CniCommand::Del => handle_del(request, vnet_manager, config).await,
        CniCommand::Check => handle_check(request, vnet_manager, config).await,
        CniCommand::Version => handle_version(config),
    }
}

/// Handle a CNI ADD request
async fn handle_add(
    request: CniRequest,
    vnet_manager: Arc<RwLock<VNetManager>>,
    config: CniConfig,
) -> CniResponse {
    // Get the network
    let vnet_manager = vnet_manager.read().await;
    let network = match vnet_manager.get_network(&request.network_name) {
        Some(network) => network,
        None => {
            return CniResponse {
                success: false,
                result: None,
                error: Some(CniError {
                    cni_version: config.cni_version.to_string(),
                    code: 100,
                    msg: format!("Network {} not found", request.network_name),
                    details: None,
                }),
            }
        }
    };

    // In a real implementation, this would connect the container to the network
    // For now, we'll just return a dummy result

    let result = CniResult {
        cni_version: config.cni_version.to_string(),
        interfaces: Some({
            let mut interfaces = std::collections::HashMap::new();
            interfaces.insert(
                request.ifname.clone(),
                super::CniInterface {
                    name: request.ifname.clone(),
                    mac: "02:42:ac:11:00:02".to_string(),
                    sandbox: request.netns_path.clone(),
                },
            );
            interfaces
        }),
        ips: Some(vec![super::CniIpConfig {
            version: "4".to_string(),
            address: "172.17.0.2/16".to_string(),
            gateway: Some(network.gateway.to_string()),
        }]),
        routes: Some(vec![super::CniRoute {
            dst: "0.0.0.0/0".to_string(),
            gw: Some(network.gateway.to_string()),
        }]),
        dns: Some(super::CniDns {
            nameservers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            search: Some(vec!["quantum.local".to_string()]),
            options: None,
        }),
    };

    CniResponse {
        success: true,
        result: Some(result),
        error: None,
    }
}

/// Handle a CNI DEL request
async fn handle_del(
    request: CniRequest,
    vnet_manager: Arc<RwLock<VNetManager>>,
    config: CniConfig,
) -> CniResponse {
    // Get the network
    let vnet_manager = vnet_manager.read().await;
    let network = match vnet_manager.get_network(&request.network_name) {
        Some(network) => network,
        None => {
            // If the network doesn't exist, that's not an error for DEL
            return CniResponse {
                success: true,
                result: Some(CniResult {
                    cni_version: config.cni_version.to_string(),
                    interfaces: None,
                    ips: None,
                    routes: None,
                    dns: None,
                }),
                error: None,
            };
        }
    };

    // In a real implementation, this would disconnect the container from the network
    // For now, we'll just return success

    CniResponse {
        success: true,
        result: Some(CniResult {
            cni_version: config.cni_version.to_string(),
            interfaces: None,
            ips: None,
            routes: None,
            dns: None,
        }),
        error: None,
    }
}

/// Handle a CNI CHECK request
async fn handle_check(
    request: CniRequest,
    vnet_manager: Arc<RwLock<VNetManager>>,
    config: CniConfig,
) -> CniResponse {
    // Get the network
    let vnet_manager = vnet_manager.read().await;
    let network = match vnet_manager.get_network(&request.network_name) {
        Some(network) => network,
        None => {
            return CniResponse {
                success: false,
                result: None,
                error: Some(CniError {
                    cni_version: config.cni_version.to_string(),
                    code: 100,
                    msg: format!("Network {} not found", request.network_name),
                    details: None,
                }),
            }
        }
    };

    // In a real implementation, this would check the container's networking
    // For now, we'll just return success

    CniResponse {
        success: true,
        result: Some(CniResult {
            cni_version: config.cni_version.to_string(),
            interfaces: None,
            ips: None,
            routes: None,
            dns: None,
        }),
        error: None,
    }
}

/// Handle a CNI VERSION request
fn handle_version(config: CniConfig) -> CniResponse {
    let version_info = super::CniVersionInfo {
        cni_versions: vec![config.cni_version.to_string()],
        supported_versions: Some(vec![
            "0.3.0".to_string(),
            "0.3.1".to_string(),
            "0.4.0".to_string(),
            "1.0.0".to_string(),
        ]),
    };

    CniResponse {
        success: true,
        result: Some(CniResult {
            cni_version: config.cni_version.to_string(),
            interfaces: None,
            ips: None,
            routes: None,
            dns: None,
        }),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cni_request_serialization() {
        let request = CniRequest {
            command: CniCommand::Add,
            container_id: "test-container".to_string(),
            netns_path: "/var/run/netns/test".to_string(),
            ifname: "eth0".to_string(),
            network_name: "test-network".to_string(),
            args: serde_json::json!({
                "K8S_POD_NAME": "test-pod",
                "K8S_POD_NAMESPACE": "default"
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: CniRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.command, CniCommand::Add);
        assert_eq!(deserialized.container_id, "test-container");
        assert_eq!(deserialized.netns_path, "/var/run/netns/test");
        assert_eq!(deserialized.ifname, "eth0");
        assert_eq!(deserialized.network_name, "test-network");
    }

    #[test]
    fn test_cni_response_serialization() {
        let response = CniResponse {
            success: true,
            result: Some(CniResult {
                cni_version: "1.0.0".to_string(),
                interfaces: None,
                ips: None,
                routes: None,
                dns: None,
            }),
            error: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: CniResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.success, true);
        assert!(deserialized.result.is_some());
        assert!(deserialized.error.is_none());
    }
}