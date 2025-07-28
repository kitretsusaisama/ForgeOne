# Quantum-Network Fabric Layer

The Quantum-Network Fabric Layer is a Zero Trust Network Manager for container networking. It provides a secure, scalable, and flexible networking solution for containerized applications.

## Overview

The Quantum-Network Fabric Layer is designed to provide the following features:

- **Zero Trust Architecture**: All network connections are authenticated, authorized, and encrypted by default.
- **Container Networking Interface (CNI)**: Integration with container runtimes like Docker, Kubernetes, and containerd.
- **Virtual Networks**: Create isolated virtual networks for containers with custom CIDR ranges and gateways.
- **Network Policies**: Define fine-grained network policies for container-to-container communication.
- **API**: REST and gRPC APIs for managing networks, containers, and policies.
- **Metrics**: Prometheus metrics for monitoring network performance and security events.

## Components

### Virtual Network Manager

The Virtual Network Manager is responsible for creating and managing virtual networks. It provides the following functionality:

- Creating and deleting virtual networks
- Allocating IP addresses to containers
- Managing network interfaces and routes
- Enforcing network isolation and security policies

### CNI Module

The CNI module implements the Container Networking Interface (CNI) specification. It allows container runtimes to request network connectivity for containers. The CNI module includes:

- CNI Server: A Unix socket server that handles CNI requests from container runtimes
- CNI Plugin: A binary that can be invoked by container runtimes to connect containers to networks
- CNI Manager: A component that manages CNI configurations and plugins

### API Module

The API module provides REST and gRPC interfaces for managing networks, containers, and policies. It includes:

- REST API: A RESTful API for managing networks and containers
- gRPC API: A gRPC API for programmatic access to network management functions
- API Server: A component that initializes and manages the REST and gRPC servers

## Getting Started

### Building

To build the Quantum-Network Fabric Layer, run the following commands:

```bash
cargo build --release
```

This will build the following binaries:

- `target/release/quantum-cni`: The CNI plugin binary
- `target/release/quantum-api`: The API server binary

### Running

To run the API server:

```bash
./target/release/quantum-api
```

To install the CNI plugin:

```bash
mkdir -p /opt/cni/bin
cp ./target/release/quantum-cni /opt/cni/bin/
```

### Configuration

The Quantum-Network Fabric Layer can be configured using environment variables or configuration files. See the documentation for each component for more details.

## API Usage

### Creating a Network

```bash
curl -X POST -H "Content-Type: application/json" -d '{"name":"my-network","cidr":"172.17.0.0/16","gateway":"172.17.0.1","driver":"bridge","isolation_mode":"none"}' http://localhost:9443/networks
```

### Listing Networks

```bash
curl -X GET http://localhost:9443/networks
```

### Connecting a Container

```bash
curl -X POST -H "Content-Type: application/json" -d '{"container_id":"my-container","netns_path":"/var/run/netns/my-container","interface_name":"eth0"}' http://localhost:9443/networks/my-network/containers
```

## CNI Usage

The CNI plugin can be invoked by container runtimes like Docker, Kubernetes, and containerd. See the [CNI specification](https://github.com/containernetworking/cni/blob/master/SPEC.md) for more details.

## Development

### Running Tests

To run the tests:

```bash
cargo test
```

### Code Structure

- `src/api`: API module for REST and gRPC interfaces
- `src/cni`: CNI module for container runtime integration
- `src/vnet`: Virtual Network Manager for network management
- `src/model.rs`: Data models for networks, endpoints, and policies
- `src/lib.rs`: Library entry point and initialization
- `src/bin`: Binary entry points for CNI plugin and API server

## License

This project is licensed under the MIT License - see the LICENSE file for details.