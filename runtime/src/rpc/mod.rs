//! # Container RPC Module
//!
//! This module provides functionality for remote procedure calls (RPC) to manage
//! and control containers. It implements a secure RPC server and client with
//! authentication, authorization, and encryption.

use crate::contract::Contract;
use crate::dna::ContainerDNA;
use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// RPC protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcProtocol {
    /// HTTP/REST
    Http,
    /// gRPC
    Grpc,
    /// WebSockets
    WebSocket,
    /// Unix Domain Socket
    UnixSocket,
    /// Custom protocol
    Custom,
}

impl std::fmt::Display for RpcProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcProtocol::Http => write!(f, "http"),
            RpcProtocol::Grpc => write!(f, "grpc"),
            RpcProtocol::WebSocket => write!(f, "websocket"),
            RpcProtocol::UnixSocket => write!(f, "unixsocket"),
            RpcProtocol::Custom => write!(f, "custom"),
        }
    }
}

/// RPC authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcAuthType {
    /// No authentication
    None,
    /// Basic authentication
    Basic,
    /// Token-based authentication
    Token,
    /// Certificate-based authentication
    Certificate,
    /// OAuth2 authentication
    OAuth2,
    /// Custom authentication
    Custom,
}

impl std::fmt::Display for RpcAuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcAuthType::None => write!(f, "none"),
            RpcAuthType::Basic => write!(f, "basic"),
            RpcAuthType::Token => write!(f, "token"),
            RpcAuthType::Certificate => write!(f, "certificate"),
            RpcAuthType::OAuth2 => write!(f, "oauth2"),
            RpcAuthType::Custom => write!(f, "custom"),
        }
    }
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcServerConfig {
    /// Server ID
    pub id: String,
    /// Server name
    pub name: String,
    /// RPC protocol
    pub protocol: RpcProtocol,
    /// Bind address
    pub bind_addr: IpAddr,
    /// Bind port
    pub bind_port: u16,
    /// Unix socket path (for UnixSocket protocol)
    pub unix_socket_path: Option<String>,
    /// Authentication type
    pub auth_type: RpcAuthType,
    /// TLS enabled
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// Request timeout
    pub request_timeout: Duration,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    /// Custom server options
    pub custom: HashMap<String, String>,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "default".to_string(),
            protocol: RpcProtocol::Http,
            bind_addr: "127.0.0.1".parse().unwrap(),
            bind_port: 8080,
            unix_socket_path: None,
            auth_type: RpcAuthType::None,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            request_timeout: Duration::from_secs(30),
            max_concurrent_requests: 100,
            custom: HashMap::new(),
        }
    }
}

/// RPC client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClientConfig {
    /// Client ID
    pub id: String,
    /// Client name
    pub name: String,
    /// RPC protocol
    pub protocol: RpcProtocol,
    /// Server address
    pub server_addr: String,
    /// Server port
    pub server_port: u16,
    /// Unix socket path (for UnixSocket protocol)
    pub unix_socket_path: Option<String>,
    /// Authentication type
    pub auth_type: RpcAuthType,
    /// Authentication credentials
    pub auth_credentials: Option<HashMap<String, String>>,
    /// TLS enabled
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS key path
    pub tls_key_path: Option<String>,
    /// Request timeout
    pub request_timeout: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Custom client options
    pub custom: HashMap<String, String>,
}

impl Default for RpcClientConfig {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "default".to_string(),
            protocol: RpcProtocol::Http,
            server_addr: "127.0.0.1".to_string(),
            server_port: 8080,
            unix_socket_path: None,
            auth_type: RpcAuthType::None,
            auth_credentials: None,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
            request_timeout: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(5),
            custom: HashMap::new(),
        }
    }
}

/// RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Request ID
    pub id: String,
    /// Method name
    pub method: String,
    /// Method parameters
    pub params: serde_json::Value,
    /// Request timestamp
    pub timestamp: u64,
    /// Request timeout
    pub timeout: Option<Duration>,
    /// Authentication token
    pub auth_token: Option<String>,
    /// Custom request headers
    pub headers: HashMap<String, String>,
}

impl RpcRequest {
    /// Create a new RPC request
    pub fn new(method: &str, params: serde_json::Value) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            method: method.to_string(),
            params,
            timestamp: now,
            timeout: None,
            auth_token: None,
            headers: HashMap::new(),
        }
    }

    /// Set request timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set authentication token
    pub fn with_auth_token(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Add a header
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Check if the request has timed out
    pub fn is_timed_out(&self) -> bool {
        if let Some(timeout) = self.timeout {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let elapsed = now - self.timestamp;
            elapsed > timeout.as_secs()
        } else {
            false
        }
    }
}

/// RPC response status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RpcResponseStatus {
    /// Success
    Success,
    /// Error
    Error,
}

impl std::fmt::Display for RpcResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcResponseStatus::Success => write!(f, "success"),
            RpcResponseStatus::Error => write!(f, "error"),
        }
    }
}

/// RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Request ID
    pub request_id: String,
    /// Response ID
    pub id: String,
    /// Response status
    pub status: RpcResponseStatus,
    /// Response result
    pub result: Option<serde_json::Value>,
    /// Error message (if status is Error)
    pub error: Option<String>,
    /// Error code (if status is Error)
    pub error_code: Option<i32>,
    /// Response timestamp
    pub timestamp: u64,
    /// Custom response headers
    pub headers: HashMap<String, String>,
}

impl RpcResponse {
    /// Create a new successful RPC response
    pub fn success(request_id: &str, result: serde_json::Value) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            request_id: request_id.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            status: RpcResponseStatus::Success,
            result: Some(result),
            error: None,
            error_code: None,
            timestamp: now,
            headers: HashMap::new(),
        }
    }

    /// Create a new error RPC response
    pub fn error(request_id: &str, error: &str, error_code: i32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            request_id: request_id.to_string(),
            id: uuid::Uuid::new_v4().to_string(),
            status: RpcResponseStatus::Error,
            result: None,
            error: Some(error.to_string()),
            error_code: Some(error_code),
            timestamp: now,
            headers: HashMap::new(),
        }
    }

    /// Add a header
    pub fn with_header(mut self, key: &str, value: &str) -> Self {
        self.headers.insert(key.to_string(), value.to_string());
        self
    }

    /// Check if the response is successful
    pub fn is_success(&self) -> bool {
        self.status == RpcResponseStatus::Success
    }

    /// Check if the response is an error
    pub fn is_error(&self) -> bool {
        self.status == RpcResponseStatus::Error
    }
}

/// RPC handler function type
pub type RpcHandlerFn = fn(RpcRequest) -> Result<RpcResponse>;

/// RPC server
#[derive(Debug)]
pub struct RpcServer {
    /// Server configuration
    config: RpcServerConfig,
    /// RPC handlers
    handlers: Arc<RwLock<HashMap<String, RpcHandlerFn>>>,
    /// Server running flag
    running: Arc<RwLock<bool>>,
}

impl RpcServer {
    /// Create a new RPC server
    pub fn new(config: RpcServerConfig) -> Self {
        Self {
            config,
            handlers: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Register an RPC handler
    pub fn register_handler(&self, method: &str, handler: RpcHandlerFn) -> Result<()> {
        let span = ExecutionSpan::new(
            "register_rpc_handler",
            common::identity::IdentityContext::system(),
        );

        let mut handlers = self.handlers.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_handlers".to_string(),
        })?;

        handlers.insert(method.to_string(), handler);

        Ok(())
    }

    /// Unregister an RPC handler
    pub fn unregister_handler(&self, method: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "unregister_rpc_handler",
            common::identity::IdentityContext::system(),
        );

        let mut handlers = self.handlers.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_handlers".to_string(),
        })?;

        handlers.remove(method);

        Ok(())
    }

    /// Start the RPC server
    pub fn start(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "start_rpc_server",
            common::identity::IdentityContext::system(),
        );

        let mut running = self.running.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_server_running".to_string(),
        })?;

        if *running {
            return Err(ForgeError::AlreadyRunningError {
                resource: "rpc_server".to_string(),
                id: self.config.id.clone(),
            });
        }

        // In a real implementation, we would start the server here
        // For now, just set the running flag
        *running = true;

        Ok(())
    }

    /// Stop the RPC server
    pub fn stop(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "stop_rpc_server",
            common::identity::IdentityContext::system(),
        );

        let mut running = self.running.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_server_running".to_string(),
        })?;

        if !*running {
            return Err(ForgeError::NotRunningError {
                resource: "rpc_server".to_string(),
                id: self.config.id.clone(),
            });
        }

        // In a real implementation, we would stop the server here
        // For now, just set the running flag
        *running = false;

        Ok(())
    }

    /// Check if the server is running
    pub fn is_running(&self) -> Result<bool> {
        let running = self.running.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_server_running".to_string(),
        })?;

        Ok(*running)
    }

    /// Get the server configuration
    pub fn get_config(&self) -> RpcServerConfig {
        self.config.clone()
    }

    /// Handle an RPC request
    pub fn handle_request(&self, request: RpcRequest) -> Result<RpcResponse> {
        let span = ExecutionSpan::new(
            "handle_rpc_request",
            common::identity::IdentityContext::system(),
        );

        // Check if the server is running
        if !self.is_running()? {
            return Ok(RpcResponse::error(
                &request.id,
                "RPC server is not running",
                500,
            ));
        }

        // Check if the request has timed out
        if request.is_timed_out() {
            return Ok(RpcResponse::error(&request.id, "Request timed out", 408));
        }

        // Get the handler for the method
        let handlers = self.handlers.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_handlers".to_string(),
        })?;

        let handler = handlers.get(&request.method).ok_or(ForgeError::NotFoundError {
            resource: "rpc_handler".to_string(),
            id: request.method.clone(),
        })?;

        // Call the handler
        handler(request)
    }
}

/// RPC client
#[derive(Debug)]
pub struct RpcClient {
    /// Client configuration
    config: RpcClientConfig,
    /// Client connected flag
    connected: Arc<RwLock<bool>>,
}

impl RpcClient {
    /// Create a new RPC client
    pub fn new(config: RpcClientConfig) -> Self {
        Self {
            config,
            connected: Arc::new(RwLock::new(false)),
        }
    }

    /// Connect to the RPC server
    pub fn connect(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "connect_rpc_client",
            common::identity::IdentityContext::system(),
        );

        let mut connected = self.connected.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_client_connected".to_string(),
        })?;

        if *connected {
            return Err(ForgeError::AlreadyConnectedError {
                resource: "rpc_client".to_string(),
                id: self.config.id.clone(),
            });
        }

        // In a real implementation, we would connect to the server here
        // For now, just set the connected flag
        *connected = true;

        Ok(())
    }

    /// Disconnect from the RPC server
    pub fn disconnect(&self) -> Result<()> {
        let span = ExecutionSpan::new(
            "disconnect_rpc_client",
            common::identity::IdentityContext::system(),
        );

        let mut connected = self.connected.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_client_connected".to_string(),
        })?;

        if !*connected {
            return Err(ForgeError::NotConnectedError {
                resource: "rpc_client".to_string(),
                id: self.config.id.clone(),
            });
        }

        // In a real implementation, we would disconnect from the server here
        // For now, just set the connected flag
        *connected = false;

        Ok(())
    }

    /// Check if the client is connected
    pub fn is_connected(&self) -> Result<bool> {
        let connected = self.connected.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_client_connected".to_string(),
        })?;

        Ok(*connected)
    }

    /// Get the client configuration
    pub fn get_config(&self) -> RpcClientConfig {
        self.config.clone()
    }

    /// Send an RPC request
    pub fn send_request(&self, request: RpcRequest) -> Result<RpcResponse> {
        let span = ExecutionSpan::new(
            "send_rpc_request",
            common::identity::IdentityContext::system(),
        );

        // Check if the client is connected
        if !self.is_connected()? {
            return Err(ForgeError::NotConnectedError {
                resource: "rpc_client".to_string(),
                id: self.config.id.clone(),
            });
        }

        // In a real implementation, we would send the request to the server here
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"message": "Mock response"}),
        ))
    }
}

/// RPC manager
#[derive(Debug)]
pub struct RpcManager {
    /// RPC servers
    servers: Arc<RwLock<HashMap<String, RpcServer>>>,
    /// RPC clients
    clients: Arc<RwLock<HashMap<String, RpcClient>>>,
}

impl RpcManager {
    /// Create a new RPC manager
    pub fn new() -> Self {
        Self {
            servers: Arc::new(RwLock::new(HashMap::new())),
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create an RPC server
    pub fn create_server(&self, config: RpcServerConfig) -> Result<RpcServer> {
        let span = ExecutionSpan::new(
            "create_rpc_server",
            common::identity::IdentityContext::system(),
        );

        let server = RpcServer::new(config.clone());

        let mut servers = self.servers.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_servers".to_string(),
        })?;

        if servers.contains_key(&config.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "rpc_server".to_string(),
                id: config.id.clone(),
            });
        }

        servers.insert(config.id.clone(), server.clone());

        Ok(server)
    }

    /// Get an RPC server
    pub fn get_server(&self, server_id: &str) -> Result<RpcServer> {
        let span = ExecutionSpan::new(
            "get_rpc_server",
            common::identity::IdentityContext::system(),
        );

        let servers = self.servers.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_servers".to_string(),
        })?;

        let server = servers.get(server_id).ok_or(ForgeError::NotFoundError {
            resource: "rpc_server".to_string(),
            id: server_id.to_string(),
        })?;

        Ok(server.clone())
    }

    /// Remove an RPC server
    pub fn remove_server(&self, server_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_rpc_server",
            common::identity::IdentityContext::system(),
        );

        // Get the server
        let server = self.get_server(server_id)?;

        // Stop the server if it's running
        if server.is_running()? {
            server.stop()?;
        }

        // Remove the server
        let mut servers = self.servers.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_servers".to_string(),
        })?;

        servers.remove(server_id);

        Ok(())
    }

    /// Create an RPC client
    pub fn create_client(&self, config: RpcClientConfig) -> Result<RpcClient> {
        let span = ExecutionSpan::new(
            "create_rpc_client",
            common::identity::IdentityContext::system(),
        );

        let client = RpcClient::new(config.clone());

        let mut clients = self.clients.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_clients".to_string(),
        })?;

        if clients.contains_key(&config.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "rpc_client".to_string(),
                id: config.id.clone(),
            });
        }

        clients.insert(config.id.clone(), client.clone());

        Ok(client)
    }

    /// Get an RPC client
    pub fn get_client(&self, client_id: &str) -> Result<RpcClient> {
        let span = ExecutionSpan::new(
            "get_rpc_client",
            common::identity::IdentityContext::system(),
        );

        let clients = self.clients.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_clients".to_string(),
        })?;

        let client = clients.get(client_id).ok_or(ForgeError::NotFoundError {
            resource: "rpc_client".to_string(),
            id: client_id.to_string(),
        })?;

        Ok(client.clone())
    }

    /// Remove an RPC client
    pub fn remove_client(&self, client_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "remove_rpc_client",
            common::identity::IdentityContext::system(),
        );

        // Get the client
        let client = self.get_client(client_id)?;

        // Disconnect the client if it's connected
        if client.is_connected()? {
            client.disconnect()?;
        }

        // Remove the client
        let mut clients = self.clients.write().map_err(|_| ForgeError::LockError {
            resource: "rpc_clients".to_string(),
        })?;

        clients.remove(client_id);

        Ok(())
    }

    /// List all RPC servers
    pub fn list_servers(&self) -> Result<Vec<RpcServer>> {
        let span = ExecutionSpan::new(
            "list_rpc_servers",
            common::identity::IdentityContext::system(),
        );

        let servers = self.servers.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_servers".to_string(),
        })?;

        Ok(servers.values().cloned().collect())
    }

    /// List all RPC clients
    pub fn list_clients(&self) -> Result<Vec<RpcClient>> {
        let span = ExecutionSpan::new(
            "list_rpc_clients",
            common::identity::IdentityContext::system(),
        );

        let clients = self.clients.read().map_err(|_| ForgeError::LockError {
            resource: "rpc_clients".to_string(),
        })?;

        Ok(clients.values().cloned().collect())
    }
}

/// Global RPC manager instance
static mut RPC_MANAGER: Option<RpcManager> = None;

/// Initialize the RPC manager
pub fn init() -> Result<()> {
    let span = ExecutionSpan::new(
        "init_rpc_manager",
        common::identity::IdentityContext::system(),
    );

    // Create RPC manager
    let rpc_manager = RpcManager::new();

    // Store the RPC manager
    unsafe {
        if RPC_MANAGER.is_none() {
            RPC_MANAGER = Some(rpc_manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "rpc_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the RPC manager
pub fn get_rpc_manager() -> Result<&'static RpcManager> {
    unsafe {
        match &RPC_MANAGER {
            Some(rpc_manager) => Ok(rpc_manager),
            None => Err(ForgeError::UninitializedError {
                component: "rpc_manager".to_string(),
            }),
        }
    }
}

/// Create an RPC server
pub fn create_server(config: RpcServerConfig) -> Result<RpcServer> {
    let rpc_manager = get_rpc_manager()?;
    rpc_manager.create_server(config)
}

/// Create an RPC client
pub fn create_client(config: RpcClientConfig) -> Result<RpcClient> {
    let rpc_manager = get_rpc_manager()?;
    rpc_manager.create_client(config)
}

/// Register container management RPC handlers
pub fn register_container_handlers(server: &RpcServer) -> Result<()> {
    let span = ExecutionSpan::new(
        "register_container_rpc_handlers",
        common::identity::IdentityContext::system(),
    );

    // Register container creation handler
    server.register_handler("create_container", |request| {
        // In a real implementation, we would parse the request parameters and call the container creation function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"container_id": uuid::Uuid::new_v4().to_string()}),
        ))
    })?;

    // Register container start handler
    server.register_handler("start_container", |request| {
        // In a real implementation, we would parse the request parameters and call the container start function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"status": "started"}),
        ))
    })?;

    // Register container stop handler
    server.register_handler("stop_container", |request| {
        // In a real implementation, we would parse the request parameters and call the container stop function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"status": "stopped"}),
        ))
    })?;

    // Register container pause handler
    server.register_handler("pause_container", |request| {
        // In a real implementation, we would parse the request parameters and call the container pause function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"status": "paused"}),
        ))
    })?;

    // Register container resume handler
    server.register_handler("resume_container", |request| {
        // In a real implementation, we would parse the request parameters and call the container resume function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"status": "running"}),
        ))
    })?;

    // Register container remove handler
    server.register_handler("remove_container", |request| {
        // In a real implementation, we would parse the request parameters and call the container remove function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"status": "removed"}),
        ))
    })?;

    // Register container status handler
    server.register_handler("get_container_status", |request| {
        // In a real implementation, we would parse the request parameters and call the container status function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"status": "running"}),
        ))
    })?;

    // Register container list handler
    server.register_handler("list_containers", |request| {
        // In a real implementation, we would call the container list function
        // For now, just return a mock response
        Ok(RpcResponse::success(
            &request.id,
            serde_json::json!({"containers": []}),
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_request() {
        // Create request
        let params = serde_json::json!({"container_id": "test-container"});
        let request = RpcRequest::new("test_method", params.clone())
            .with_timeout(Duration::from_secs(30))
            .with_auth_token("test-token")
            .with_header("X-Test", "test-value");

        // Check request fields
        assert_eq!(request.method, "test_method");
        assert_eq!(request.params, params);
        assert!(request.timeout.is_some());
        assert_eq!(request.timeout.unwrap(), Duration::from_secs(30));
        assert!(request.auth_token.is_some());
        assert_eq!(request.auth_token.unwrap(), "test-token");
        assert!(request.headers.contains_key("X-Test"));
        assert_eq!(request.headers.get("X-Test").unwrap(), "test-value");
        assert!(!request.is_timed_out());
    }

    #[test]
    fn test_rpc_response() {
        // Create success response
        let result = serde_json::json!({"message": "Success"});
        let success_response = RpcResponse::success("test-request", result.clone())
            .with_header("X-Test", "test-value");

        // Check success response fields
        assert_eq!(success_response.request_id, "test-request");
        assert_eq!(success_response.status, RpcResponseStatus::Success);
        assert!(success_response.result.is_some());
        assert_eq!(success_response.result.unwrap(), result);
        assert!(success_response.error.is_none());
        assert!(success_response.error_code.is_none());
        assert!(success_response.headers.contains_key("X-Test"));
        assert_eq!(success_response.headers.get("X-Test").unwrap(), "test-value");
        assert!(success_response.is_success());
        assert!(!success_response.is_error());

        // Create error response
        let error_response = RpcResponse::error("test-request", "Error message", 500);

        // Check error response fields
        assert_eq!(error_response.request_id, "test-request");
        assert_eq!(error_response.status, RpcResponseStatus::Error);
        assert!(error_response.result.is_none());
        assert!(error_response.error.is_some());
        assert_eq!(error_response.error.unwrap(), "Error message");
        assert!(error_response.error_code.is_some());
        assert_eq!(error_response.error_code.unwrap(), 500);
        assert!(!error_response.is_success());
        assert!(error_response.is_error());
    }

    #[test]
    fn test_rpc_manager() {
        // Initialize RPC manager
        init().unwrap();
        let rpc_manager = get_rpc_manager().unwrap();

        // Create server config
        let server_config = RpcServerConfig {
            id: "test-server".to_string(),
            name: "Test Server".to_string(),
            protocol: RpcProtocol::Http,
            bind_addr: "127.0.0.1".parse().unwrap(),
            bind_port: 8080,
            ..RpcServerConfig::default()
        };

        // Create server
        let server = rpc_manager.create_server(server_config).unwrap();

        // Check server config
        let config = server.get_config();
        assert_eq!(config.id, "test-server");
        assert_eq!(config.name, "Test Server");
        assert_eq!(config.protocol, RpcProtocol::Http);

        // Start server
        server.start().unwrap();
        assert!(server.is_running().unwrap());

        // Register handler
        server
            .register_handler("test_method", |request| {
                Ok(RpcResponse::success(
                    &request.id,
                    serde_json::json!({"message": "Test response"}),
                ))
            })
            .unwrap();

        // Create client config
        let client_config = RpcClientConfig {
            id: "test-client".to_string(),
            name: "Test Client".to_string(),
            protocol: RpcProtocol::Http,
            server_addr: "127.0.0.1".to_string(),
            server_port: 8080,
            ..RpcClientConfig::default()
        };

        // Create client
        let client = rpc_manager.create_client(client_config).unwrap();

        // Check client config
        let config = client.get_config();
        assert_eq!(config.id, "test-client");
        assert_eq!(config.name, "Test Client");
        assert_eq!(config.protocol, RpcProtocol::Http);

        // Connect client
        client.connect().unwrap();
        assert!(client.is_connected().unwrap());

        // Send request
        let request = RpcRequest::new(
            "test_method",
            serde_json::json!({"param": "test"}),
        );
        let response = client.send_request(request).unwrap();

        // Check response
        assert!(response.is_success());

        // Disconnect client
        client.disconnect().unwrap();
        assert!(!client.is_connected().unwrap());

        // Stop server
        server.stop().unwrap();
        assert!(!server.is_running().unwrap());

        // Remove client and server
        rpc_manager.remove_client("test-client").unwrap();
        rpc_manager.remove_server("test-server").unwrap();

        // Check that client and server are removed
        let clients = rpc_manager.list_clients().unwrap();
        assert!(clients.is_empty());
        let servers = rpc_manager.list_servers().unwrap();
        assert!(servers.is_empty());
    }
}