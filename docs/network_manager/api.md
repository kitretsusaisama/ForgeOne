# API Module Documentation

## Overview

The API Module provides a comprehensive interface for managing the Quantum-Network Fabric Layer. It exposes both REST and gRPC endpoints that allow clients to create, manage, and monitor virtual networks and container connections.

## Architecture

The API Module consists of the following components:

- **REST API Server**: Provides HTTP/HTTPS endpoints for network management
- **gRPC API Server**: Provides high-performance RPC endpoints for network management
- **API Configuration**: Manages TLS, authentication, and server settings
- **Request/Response Models**: Defines the data structures for API communication

## Configuration

The API Module can be configured through the `ApiConfig` structure:

```rust
pub struct ApiConfig {
    pub host: String,
    pub port: u16,
    pub tls_enabled: bool,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub auth_enabled: bool,
    pub auth_type: AuthType,
    pub jwt_secret: Option<String>,
    pub metrics_enabled: bool,
}
```

Default configuration:
- Host: 127.0.0.1
- Port: 9443
- TLS: Disabled by default
- Authentication: Disabled by default

## REST API Endpoints

### Network Management

#### Create Network

```
POST /api/v1/networks
```

Request Body:
```json
{
  "name": "example-network",
  "driver": "bridge",
  "subnet": "172.20.0.0/16",
  "gateway": "172.20.0.1",
  "isolation": "full",
  "options": {
    "mtu": "1500"
  },
  "labels": {
    "environment": "production"
  }
}
```

Response:
```json
{
  "id": "net-01234567",
  "name": "example-network",
  "driver": "bridge",
  "subnet": "172.20.0.0/16",
  "gateway": "172.20.0.1",
  "isolation": "full",
  "options": {
    "mtu": "1500"
  },
  "labels": {
    "environment": "production"
  },
  "created_at": "2023-01-01T00:00:00Z"
}
```

#### List Networks

```
GET /api/v1/networks
```

Response:
```json
{
  "networks": [
    {
      "id": "net-01234567",
      "name": "example-network",
      "driver": "bridge",
      "subnet": "172.20.0.0/16",
      "gateway": "172.20.0.1",
      "isolation": "full",
      "created_at": "2023-01-01T00:00:00Z"
    }
  ]
}
```

#### Get Network

```
GET /api/v1/networks/{id}
```

Response:
```json
{
  "id": "net-01234567",
  "name": "example-network",
  "driver": "bridge",
  "subnet": "172.20.0.0/16",
  "gateway": "172.20.0.1",
  "isolation": "full",
  "options": {
    "mtu": "1500"
  },
  "labels": {
    "environment": "production"
  },
  "created_at": "2023-01-01T00:00:00Z"
}
```

#### Delete Network

```
DELETE /api/v1/networks/{id}
```

Response:
```json
{
  "success": true
}
```

### Container Management

#### Connect Container

```
POST /api/v1/containers/{id}/connect
```

Request Body:
```json
{
  "network_id": "net-01234567",
  "ip_address": "172.20.0.2",
  "mac_address": "02:42:ac:14:00:02"
}
```

Response:
```json
{
  "endpoint_id": "ep-01234567",
  "container_id": "cont-01234567",
  "network_id": "net-01234567",
  "ip_address": "172.20.0.2",
  "mac_address": "02:42:ac:14:00:02",
  "created_at": "2023-01-01T00:00:00Z"
}
```

#### Disconnect Container

```
POST /api/v1/containers/{id}/disconnect
```

Request Body:
```json
{
  "network_id": "net-01234567"
}
```

Response:
```json
{
  "success": true
}
```

## gRPC API

The gRPC API provides the same functionality as the REST API but with improved performance for high-throughput scenarios.

### Proto Definition

```protobuf
syntax = "proto3";

package quantum.network;

service NetworkService {
  rpc CreateNetwork(CreateNetworkRequest) returns (Network);
  rpc GetNetwork(GetNetworkRequest) returns (Network);
  rpc ListNetworks(ListNetworksRequest) returns (ListNetworksResponse);
  rpc DeleteNetwork(DeleteNetworkRequest) returns (DeleteNetworkResponse);
  rpc ConnectContainer(ConnectContainerRequest) returns (Endpoint);
  rpc DisconnectContainer(DisconnectContainerRequest) returns (DisconnectContainerResponse);
}

// Message definitions omitted for brevity
```

## Authentication

The API Module supports multiple authentication methods:

- **JWT**: JSON Web Tokens for stateless authentication
- **TLS Client Certificates**: For mutual TLS authentication
- **API Keys**: Simple key-based authentication

Authentication can be enabled in the configuration:

```rust
let config = ApiConfig {
    auth_enabled: true,
    auth_type: AuthType::Jwt,
    jwt_secret: Some("your-secret-key".to_string()),
    ..Default::default()
};
```

## Error Handling

The API returns standard HTTP status codes for REST endpoints:

- 200: Success
- 400: Bad Request
- 401: Unauthorized
- 403: Forbidden
- 404: Not Found
- 409: Conflict
- 500: Internal Server Error

Error responses include a JSON body with details:

```json
{
  "error": {
    "code": "NETWORK_NOT_FOUND",
    "message": "Network with ID 'net-01234567' not found"
  }
}
```

## Metrics

The API Module exposes Prometheus-compatible metrics at the `/metrics` endpoint when metrics are enabled in the configuration.

Available metrics include:
- Request count by endpoint
- Request latency
- Error count by type
- Active connections

## Integration with Other Modules

The API Module integrates with:

- **Virtual Network Manager**: For network creation and management
- **CNI Manager**: For container connectivity
- **Firewall Module**: For security policy application
- **Metrics Module**: For performance monitoring

## Example Usage

### Creating a Network with curl

```bash
curl -X POST http://localhost:9443/api/v1/networks \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example-network",
    "driver": "bridge",
    "subnet": "172.20.0.0/16",
    "gateway": "172.20.0.1",
    "isolation": "full"
  }'
```

### Using the gRPC Client

```rust
let mut client = NetworkServiceClient::connect("http://localhost:9443").await?;

let request = tonic::Request::new(CreateNetworkRequest {
    name: "example-network".to_string(),
    driver: "bridge".to_string(),
    subnet: "172.20.0.0/16".to_string(),
    gateway: "172.20.0.1".to_string(),
    isolation: "full".to_string(),
    options: HashMap::new(),
    labels: HashMap::new(),
});

let response = client.create_network(request).await?;
let network = response.into_inner();
println!("Created network: {}", network.id);
```