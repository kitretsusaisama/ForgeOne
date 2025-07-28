# Network Manager API

This module provides the API for the Quantum-Network Fabric Layer, including REST and gRPC interfaces for managing networks, containers, and CNI functionality.

## Overview

The API module provides the following functionality:

- REST API for managing networks and containers
- gRPC API for programmatic access to network management functions
- Integration with the CNI module for container runtime integration
- Authentication and TLS support for secure API access

## Components

### API Server

The `ApiServer` is the main entry point for the API module. It initializes and manages the REST and gRPC servers, as well as the CNI server. It provides the following functionality:

- Starting and stopping the API servers
- Handling network and container management requests
- Integrating with the CNI module for container runtime integration

### REST API

The `RestApiServer` provides a RESTful API for managing networks and containers. It supports the following endpoints:

- `POST /networks`: Create a new network
- `DELETE /networks/{id}`: Delete a network
- `GET /networks`: List all networks
- `GET /networks/{id}`: Get a specific network
- `POST /networks/{id}/containers`: Connect a container to a network
- `DELETE /networks/{id}/containers/{container_id}`: Disconnect a container from a network

### gRPC API

The `GrpcApiServer` provides a gRPC API for programmatic access to network management functions. It supports the following methods:

- `CreateNetwork`: Create a new network
- `DeleteNetwork`: Delete a network
- `ListNetworks`: List all networks
- `GetNetwork`: Get a specific network
- `ConnectContainer`: Connect a container to a network
- `DisconnectContainer`: Disconnect a container from a network

## Usage

### Initialization

To initialize the API module, create an `ApiConfig` and an `ApiServer`:

```rust
let api_config = ApiConfig::default();
let vnet_manager = Arc::new(RwLock::new(VNetManager::new()));
let mut api_server = ApiServer::new(api_config, vnet_manager);
api_server.init().await?;
api_server.start().await?;
```

### Creating a Network

To create a network using the API:

```rust
let request = CreateNetworkRequest {
    name: "my-network".to_string(),
    cidr: "172.17.0.0/16".to_string(),
    gateway: Some("172.17.0.1".parse()?),
    driver: NetworkDriverType::Bridge,
    isolation_mode: IsolationLevel::None,
    options: None,
    labels: None,
};

let response = api_server.create_network(
    request.name,
    request.cidr,
    request.gateway,
    request.driver,
    request.isolation_mode,
).await?;
```

### Connecting a Container

To connect a container to a network using the API:

```rust
let ip = api_server.connect_container(
    "my-container",
    "my-network",
    "/var/run/netns/my-container",
    "eth0",
    None,
).await?;
```

## API Configuration

The API configuration is controlled by the `ApiConfig` struct, which includes the following options:

- `address`: The API server address (default: "127.0.0.1")
- `port`: The API server port (default: 9443)
- `tls_enabled`: Whether TLS is enabled (default: false)
- `tls_cert_path`: The path to the TLS certificate (optional)
- `tls_key_path`: The path to the TLS key (optional)
- `auth_enabled`: Whether authentication is enabled (default: false)
- `auth_token`: The authentication token (optional)

## Security

The API module supports the following security features:

- TLS encryption for secure communication
- Token-based authentication for API access control
- Integration with the Zero Trust Architecture (ZTA) for policy enforcement

## Integration with CNI

The API module integrates with the CNI module to provide container runtime integration. When a network is created or deleted, the API server automatically generates and installs or uninstalls the corresponding CNI configuration.

## References

- [REST API Best Practices](https://restfulapi.net/)
- [gRPC Documentation](https://grpc.io/docs/)
- [CNI Specification](https://github.com/containernetworking/cni/blob/master/SPEC.md)