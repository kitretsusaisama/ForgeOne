//! # Network Manager API
//!
//! This module provides the API for the network manager, including REST and gRPC interfaces.

pub mod grpc;
pub mod proto;
pub mod rest;
pub mod server;

use crate::cni::{CniConfig, CniManager, CniServer};
use crate::model::{IsolationLevel, NetworkDriverType, VirtualNetwork};
use crate::vnet::VNetManager;
use common::error::{ForgeError, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// API configuration
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// API server address
    pub address: String,
    /// API server port
    pub port: u16,
    /// Enable TLS
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// Enable authentication
    pub auth_enabled: bool,
    /// Authentication token
    pub auth_token: Option<String>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1".to_string(),
            port: 9443,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            auth_enabled: false,
            auth_token: None,
        }
    }
}

/// Create network request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNetworkRequest {
    /// Network name
    pub name: String,
    /// Network CIDR
    pub cidr: String,
    /// Network gateway
    pub gateway: Option<IpAddr>,
    /// Network driver
    pub driver: NetworkDriverType,
    /// Network isolation level
    pub isolation_mode: IsolationLevel,
    /// Network options
    pub options: Option<std::collections::HashMap<String, String>>,
    /// Network labels
    pub labels: Option<std::collections::HashMap<String, String>>,
}

/// Create network response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNetworkResponse {
    /// Network ID
    pub id: String,
    /// Network name
    pub name: String,
    /// Network CIDR
    pub cidr: String,
    /// Network gateway
    pub gateway: IpAddr,
}

/// Delete network request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteNetworkRequest {
    /// Network ID or name
    pub network_id: String,
}

/// Delete network response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteNetworkResponse {
    /// Success flag
    pub success: bool,
}

/// Connect container request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectContainerRequest {
    /// Container ID
    pub container_id: String,
    /// Network ID or name
    pub network_id: String,
    /// Container namespace path
    pub namespace_path: String,
    /// Interface name
    pub interface_name: String,
    /// Static IP address
    pub static_ip: Option<IpAddr>,
}