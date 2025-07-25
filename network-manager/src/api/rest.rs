//! # REST API Implementation
//!
//! This module implements the REST API for the network manager.

use super::{ApiConfig, CreateNetworkRequest, CreateNetworkResponse, DeleteNetworkRequest, DeleteNetworkResponse};
use crate::model::{IsolationLevel, NetworkDriverType, VirtualNetwork};
use crate::vnet::VNetManager;
use common::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// REST API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Success flag
    pub success: bool,
    /// Response data
    pub data: Option<T>,
    /// Error message
    pub error: Option<String>,
}

/// REST API server
pub struct RestApiServer {
    /// Configuration
    config: ApiConfig,
    /// Virtual network manager
    vnet_manager: Arc<RwLock<VNetManager>>,
    /// Running flag
    running: bool,
}

impl RestApiServer {
    /// Create a new REST API server
    pub fn new(config: ApiConfig, vnet_manager: Arc<RwLock<VNetManager>>) -> Self {
        Self {
            config,
            vnet_manager,
            running: false,
        }
    }

    /// Start the REST API server
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        info!(
            "Starting REST API server on {}:{}",
            self.config.address, self.config.port
        );

        // In a real implementation, this would start a REST API server using a framework like warp or axum
        // For now, we'll just set the running flag

        self.running = true;

        Ok(())
    }

    /// Stop the REST API server
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("Stopping REST API server");

        self.running = false;

        Ok(())
    }

    /// Handle create network request
    pub async fn handle_create_network(
        &self,
        request: CreateNetworkRequest,
    ) -> Result<ApiResponse<CreateNetworkResponse>> {
        info!("Handling create network request for network {}", request.name);

        let mut vnet_manager = self.vnet_manager.write().await;

        match vnet_manager
            .create_network(
                request.name.clone(),
                request.cidr.clone(),
                request.gateway,
                request.driver,
                request.isolation_mode,
            )
            .await
        {
            Ok(network) => {
                let response = CreateNetworkResponse {
                    id: network.id.clone(),
                    name: network.name.clone(),
                    cidr: network.cidr.clone(),
                    gateway: network.gateway,
                };

                Ok(ApiResponse {
                    success: true,
                    data: Some(response),
                    error: None,
                })
            }
            Err(e) => Ok(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        }
    }

    /// Handle delete network request
    pub async fn handle_delete_network(
        &self,
        request: DeleteNetworkRequest,
    ) -> Result<ApiResponse<DeleteNetworkResponse>> {
        info!("Handling delete network request for network {}", request.network_id);

        let mut vnet_manager = self.vnet_manager.write().await;

        match vnet_manager.delete_network(&request.network_id).await {
            Ok(_) => Ok(ApiResponse {
                success: true,
                data: Some(DeleteNetworkResponse { success: true }),
                error: None,
            }),
            Err(e) => Ok(ApiResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
            }),
        }
    }

    /// Handle list networks request
    pub async fn handle_list_networks(&self) -> Result<ApiResponse<Vec<VirtualNetwork>>> {
        info!("Handling list networks request");

        let vnet_manager = self.vnet_manager.read().await;
        let networks = vnet_manager.list_networks();

        Ok(ApiResponse {
            success: true,
            data: Some(networks),
            error: None,
        })
    }

    /// Handle get network request
    pub async fn handle_get_network(&self, network_id: &str) -> Result<ApiResponse<VirtualNetwork>> {
        info!("Handling get network request for network {}", network_id);

        let vnet_manager = self.vnet_manager.read().await;

        match vnet_manager.get_network(network_id) {
            Some(network) => Ok(ApiResponse {
                success: true,
                data: Some(network.clone()),
                error: None,
            }),
            None => Ok(ApiResponse {
                success: false,
                data: None,
                error: Some(format!("Network {} not found", network_id)),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_response_serialization() {
        let response: ApiResponse<String> = ApiResponse {
            success: true,
            data: Some("test".to_string()),
            error: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        let expected = r#"{"success":true,"data":"test","error":null}"#;
        assert_eq!(json, expected);

        let error_response: ApiResponse<String> = ApiResponse {
            success: false,
            data: None,
            error: Some("Error message".to_string()),
        };

        let json = serde_json::to_string(&error_response).unwrap();
        let expected = r#"{"success":false,"data":null,"error":"Error message"}"#;
        assert_eq!(json, expected);
    }
}