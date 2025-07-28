//! # gRPC API Implementation
//!
//! This module implements the gRPC API for the network manager using tonic.

use super::ApiConfig;
use crate::api::proto::*;
use crate::model::{
    IsolationLevel, NetworkDriverType, NetworkStats as ModelNetworkStats, VirtualNetwork,
};
use crate::vnet::VNetManager;
use common::error::{ForgeError, Result};
use prost_types::Timestamp;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tonic::{transport::Server, Request, Response, Status};
use tracing::{debug, error, info, warn};

/// gRPC API server
pub struct GrpcApiServer {
    /// Configuration
    config: ApiConfig,
    /// Virtual network manager
    vnet_manager: Arc<RwLock<VNetManager>>,
    /// Running flag
    running: bool,
    /// Shutdown signal sender
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl GrpcApiServer {
    /// Create a new gRPC API server
    pub fn new(config: ApiConfig, vnet_manager: Arc<RwLock<VNetManager>>) -> Self {
        Self {
            config,
            vnet_manager,
            running: false,
            shutdown_tx: None,
        }
    }

    /// Start the gRPC API server
    pub async fn start(&mut self) -> Result<()> {
        if self.running {
            return Ok(());
        }

        let addr = format!("{0}:{1}", self.config.address, self.config.port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                ForgeError::InvalidConfiguration(format!("Invalid socket address: {}", e))
            })?;

        info!("Starting gRPC API server on {}", addr);

        // Create a channel for shutdown signal
        let (tx, rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(tx);

        // Create the network service
        let network_service = NetworkServiceImpl {
            vnet_manager: self.vnet_manager.clone(),
        };

        // Spawn the server task
        let server_future = Server::builder()
            .add_service(NetworkServiceServer::new(network_service))
            .serve_with_shutdown(addr, async {
                rx.await.ok();
                info!("Received shutdown signal for gRPC server");
            });

        // Start the server in a separate task
        tokio::spawn(async move {
            match server_future.await {
                Ok(_) => info!("gRPC server shutdown complete"),
                Err(e) => error!("gRPC server error: {}", e),
            }
        });

        self.running = true;

        Ok(())
    }

    /// Stop the gRPC API server
    pub async fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Ok(());
        }

        info!("Stopping gRPC API server");

        // Send shutdown signal
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }

        self.running = false;

        Ok(())
    }

    /// Create a network
    pub async fn create_network(
        &self,
        name: String,
        cidr: String,
        gateway: Option<std::net::IpAddr>,
        driver: NetworkDriverType,
        isolation_mode: IsolationLevel,
    ) -> Result<VirtualNetwork> {
        info!("Creating network {}", name);

        let mut vnet_manager = self.vnet_manager.write().await;
        vnet_manager
            .create_network(&name, Some(driver), Some(cidr), Some(isolation_mode))
            .await
    }

    /// Delete a network
    pub async fn delete_network(&self, network_id: &str) -> Result<()> {
        info!("Deleting network {}", network_id);

        let mut vnet_manager = self.vnet_manager.write().await;
        vnet_manager.delete_network(network_id).await
    }

    /// List networks
    pub async fn list_networks(&self) -> Vec<VirtualNetwork> {
        info!("Listing networks");

        let vnet_manager = self.vnet_manager.read().await;
        vnet_manager.list_networks()
    }
}

/// Implementation of the NetworkService gRPC service
pub struct NetworkServiceImpl {
    /// Virtual network manager
    vnet_manager: Arc<RwLock<VNetManager>>,
}

/// Helper function to convert a chrono DateTime to a protobuf Timestamp
fn chrono_to_timestamp(dt: chrono::DateTime<chrono::Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

/// Helper function to convert a VirtualNetwork model to a protobuf Network
fn virtual_network_to_proto(network: &VirtualNetwork) -> Network {
    Network {
        id: network.id.clone(),
        name: network.name.clone(),
        cidr: network.cidr.clone(),
        gateway: network.gateway.to_string(),
        driver: match network.driver {
            NetworkDriverType::Bridge => NetworkDriverType::DriverBridge as i32,
            NetworkDriverType::Host => NetworkDriverType::DriverHost as i32,
            NetworkDriverType::Overlay => NetworkDriverType::DriverOverlay as i32,
            NetworkDriverType::Macvlan => NetworkDriverType::DriverMacvlan as i32,
            NetworkDriverType::IPvlan => NetworkDriverType::DriverIpvlan as i32,
            NetworkDriverType::None => NetworkDriverType::DriverNone as i32,
        },
        isolation_mode: match network.isolation_mode {
            IsolationLevel::None => IsolationLevel::IsolationNone as i32,
            IsolationLevel::Full => IsolationLevel::IsolationFull as i32,
            IsolationLevel::PeerOnly => IsolationLevel::IsolationPeerOnly as i32,
            IsolationLevel::MeshOnly => IsolationLevel::IsolationMeshOnly as i32,
        },
        options: network.options.clone(),
        labels: network.labels.clone(),
        created_at: Some(chrono_to_timestamp(network.created_at)),
    }
}

/// Helper function to convert a ModelNetworkStats to a protobuf NetworkStats
fn model_stats_to_proto(stats: &ModelNetworkStats) -> NetworkStats {
    NetworkStats {
        bytes_in: stats.bytes_in,
        bytes_out: stats.bytes_out,
        packets_in: stats.packets_in,
        packets_out: stats.packets_out,
        dns_queries: stats.dns_queries,
        firewall_blocks: stats.firewall_blocks,
        last_updated: Some(chrono_to_timestamp(stats.last_updated)),
    }
}

/// Helper function to convert a proto NetworkDriverType to a model NetworkDriverType
fn proto_to_network_driver_type(driver: i32) -> Result<NetworkDriverType, Status> {
    match driver {
        x if x == NetworkDriverType::DriverNone as i32 => Ok(NetworkDriverType::None),
        x if x == NetworkDriverType::DriverBridge as i32 => Ok(NetworkDriverType::Bridge),
        x if x == NetworkDriverType::DriverHost as i32 => Ok(NetworkDriverType::Host),
        x if x == NetworkDriverType::DriverOverlay as i32 => Ok(NetworkDriverType::Overlay),
        x if x == NetworkDriverType::DriverMacvlan as i32 => Ok(NetworkDriverType::Macvlan),
        x if x == NetworkDriverType::DriverIpvlan as i32 => Ok(NetworkDriverType::IPvlan),
        _ => Err(Status::invalid_argument("Invalid network driver type")),
    }
}

/// Helper function to convert a proto IsolationLevel to a model IsolationLevel
fn proto_to_isolation_level(isolation: i32) -> Result<IsolationLevel, Status> {
    match isolation {
        x if x == IsolationLevel::IsolationNone as i32 => Ok(IsolationLevel::None),
        x if x == IsolationLevel::IsolationFull as i32 => Ok(IsolationLevel::Full),
        x if x == IsolationLevel::IsolationPeerOnly as i32 => Ok(IsolationLevel::PeerOnly),
        x if x == IsolationLevel::IsolationMeshOnly as i32 => Ok(IsolationLevel::MeshOnly),
        _ => Err(Status::invalid_argument("Invalid isolation level")),
    }
}

#[tonic::async_trait]
impl NetworkService for NetworkServiceImpl {
    async fn create_network(
        &self,
        request: Request<CreateNetworkRequest>,
    ) -> std::result::Result<Response<Network>, Status> {
        let req = request.into_inner();
        info!("gRPC: Creating network {}", req.name);

        // Parse gateway if provided
        let gateway = if req.gateway.is_empty() {
            None
        } else {
            match IpAddr::from_str(&req.gateway) {
                Ok(ip) => Some(ip),
                Err(_) => return Err(Status::invalid_argument("Invalid gateway IP address")),
            }
        };

        // Convert driver type
        let driver = proto_to_network_driver_type(req.driver)?;

        // Convert isolation level
        let isolation = proto_to_isolation_level(req.isolation_mode)?;

        // Create the network
        let mut vnet_manager = self.vnet_manager.write().await;
        match vnet_manager
            .create_network(req.name, gateway, driver, isolation)
            .await
        {
            Ok(network) => Ok(Response::new(virtual_network_to_proto(&network))),
            Err(e) => Err(Status::internal(format!("Failed to create network: {}", e))),
        }
    }

    async fn get_network(
        &self,
        request: Request<GetNetworkRequest>,
    ) -> std::result::Result<Response<Network>, Status> {
        let req = request.into_inner();
        info!("gRPC: Getting network {}", req.id);

        let vnet_manager = self.vnet_manager.read().await;
        match vnet_manager.get_network(&req.id) {
            Some(network) => Ok(Response::new(virtual_network_to_proto(network))),
            None => Err(Status::not_found(format!("Network {} not found", req.id))),
        }
    }

    async fn list_networks(
        &self,
        _request: Request<prost_types::Empty>,
    ) -> std::result::Result<Response<ListNetworksResponse>, Status> {
        info!("gRPC: Listing networks");

        let vnet_manager = self.vnet_manager.read().await;
        let networks = vnet_manager.list_networks();
        let proto_networks = networks
            .iter()
            .map(|n| virtual_network_to_proto(n))
            .collect();

        Ok(Response::new(ListNetworksResponse {
            networks: proto_networks,
        }))
    }

    async fn delete_network(
        &self,
        request: Request<DeleteNetworkRequest>,
    ) -> std::result::Result<Response<prost_types::Empty>, Status> {
        let req = request.into_inner();
        info!("gRPC: Deleting network {}", req.id);

        let mut vnet_manager = self.vnet_manager.write().await;
        match vnet_manager.delete_network(&req.id).await {
            Ok(_) => Ok(Response::new(prost_types::Empty {})),
            Err(e) => Err(Status::internal(format!("Failed to delete network: {}", e))),
        }
    }

    async fn connect_container(
        &self,
        request: Request<ConnectContainerRequest>,
    ) -> std::result::Result<Response<ConnectContainerResponse>, Status> {
        let req = request.into_inner();
        info!(
            "gRPC: Connecting container {} to network {}",
            req.container_id, req.network_id
        );

        // Parse static IP if provided
        let static_ip = if req.static_ip.is_empty() {
            None
        } else {
            match IpAddr::from_str(&req.static_ip) {
                Ok(ip) => Some(ip),
                Err(_) => return Err(Status::invalid_argument("Invalid static IP address")),
            }
        };

        let mut vnet_manager = self.vnet_manager.write().await;
        match vnet_manager
            .connect_container(&req.network_id, &req.container_id, static_ip)
            .await
        {
            Ok(ip) => {
                // Get the endpoint to retrieve MAC and interface
                let endpoint = vnet_manager
                    .get_endpoint(&req.container_id, &req.network_id)
                    .ok_or_else(|| Status::internal("Failed to get endpoint after connection"))?;

                Ok(Response::new(ConnectContainerResponse {
                    ip: ip.to_string(),
                    mac: endpoint.mac.clone(),
                    interface: endpoint.interface.clone(),
                }))
            }
            Err(e) => Err(Status::internal(format!(
                "Failed to connect container: {}",
                e
            ))),
        }
    }

    async fn disconnect_container(
        &self,
        request: Request<DisconnectContainerRequest>,
    ) -> std::result::Result<Response<prost_types::Empty>, Status> {
        let req = request.into_inner();
        info!(
            "gRPC: Disconnecting container {} from network {}",
            req.container_id, req.network_id
        );

        let mut vnet_manager = self.vnet_manager.write().await;
        match vnet_manager
            .disconnect_container(&req.container_id, &req.network_id)
            .await
        {
            Ok(_) => Ok(Response::new(prost_types::Empty {})),
            Err(e) => Err(Status::internal(format!(
                "Failed to disconnect container: {}",
                e
            ))),
        }
    }

    async fn get_network_stats(
        &self,
        request: Request<GetNetworkRequest>,
    ) -> std::result::Result<Response<NetworkStats>, Status> {
        let req = request.into_inner();
        info!("gRPC: Getting network stats for {}", req.id);

        let vnet_manager = self.vnet_manager.read().await;
        match vnet_manager.get_network_stats(&req.id) {
            Some(stats) => Ok(Response::new(model_stats_to_proto(stats))),
            None => Err(Status::not_found(format!(
                "Network stats for {} not found",
                req.id
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_api_server_creation() {
        let config = ApiConfig::default();
        let vnet_manager = Arc::new(RwLock::new(VNetManager::new()));
        let server = GrpcApiServer::new(config, vnet_manager);

        assert_eq!(server.running, false);
        assert!(server.shutdown_tx.is_none());
    }
}
