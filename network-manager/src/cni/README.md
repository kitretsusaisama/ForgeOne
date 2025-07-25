# Container Network Interface (CNI) Module

This module implements the Container Network Interface (CNI) specification for the Quantum-Network Fabric Layer, allowing integration with container runtimes like Docker, Kubernetes, and containerd.

## Overview

The CNI module provides the following functionality:

- CNI plugin implementation that can be invoked by container runtimes
- CNI server that listens on a Unix socket for CNI requests
- Integration with the virtual network manager to connect containers to networks
- Support for multiple CNI versions (0.3.0, 0.3.1, 0.4.0, 1.0.0)

## Components

### CNI Manager

The `CniManager` is responsible for managing CNI configurations and handling CNI requests. It provides the following functionality:

- Generating CNI configurations for networks
- Installing and uninstalling CNI configurations
- Handling CNI commands (ADD, DEL, CHECK, VERSION)

### CNI Plugin

The `CniPlugin` is the implementation of the CNI specification. It can be invoked by container runtimes to connect containers to networks. It provides the following functionality:

- Parsing CNI environment variables and configuration
- Executing CNI commands
- Returning CNI results in the format expected by container runtimes

### CNI Server

The `CniServer` is a server that listens on a Unix socket for CNI requests. It provides the following functionality:

- Accepting connections from container runtimes
- Parsing CNI requests
- Handling CNI commands
- Returning CNI results

## Usage

### Initialization

To initialize the CNI module, create a `CniConfig` and a `CniManager`:

```rust
let cni_config = CniConfig::default();
let cni_manager = CniManager::new(cni_config);
cni_manager.init().await?;
```

### Creating a Network

To create a network with CNI support:

```rust
let network = vnet_manager.create_network(
    "my-network",
    "172.17.0.0/16",
    Some("172.17.0.1".parse()?),
    NetworkDriverType::Bridge,
    IsolationLevel::None,
).await?;

let cni_config = cni_manager.generate_network_config(&network)?;
cni_manager.install_network_config(&cni_config)?;
```

### Deleting a Network

To delete a network with CNI support:

```rust
cni_manager.uninstall_network_config("my-network")?;
vnet_manager.delete_network("my-network").await?;
```

### Running as a CNI Plugin

To run as a CNI plugin, use the `cni_main` function:

```rust
#[tokio::main]
async fn main() -> Result<()> {
    cni::plugin::cni_main().await
}
```

## CNI Configuration

The CNI configuration is stored in the directory specified by `CniConfig::config_path` (default: `/etc/cni/net.d`). The configuration files are named `<network-name>.conflist` and contain the network configuration in JSON format.

Example configuration:

```json
{
  "cniVersion": "1.0.0",
  "name": "my-network",
  "type": "quantum",
  "driver": "bridge",
  "subnet": "172.17.0.0/16",
  "gateway": "172.17.0.1",
  "routes": [
    {
      "dst": "0.0.0.0/0",
      "gw": "172.17.0.1"
    }
  ],
  "dns": {
    "nameservers": ["8.8.8.8", "8.8.4.4"],
    "search": ["quantum.local"]
  }
}
```

## CNI Commands

The CNI plugin supports the following commands:

- `ADD`: Connect a container to a network
- `DEL`: Disconnect a container from a network
- `CHECK`: Check a container's networking
- `VERSION`: Get the version of the CNI plugin

## Integration with Container Runtimes

To integrate with container runtimes, the CNI plugin binary should be installed in the directory specified by `CniConfig::plugin_path` (default: `/opt/cni/bin`). The container runtime will invoke the plugin with the appropriate environment variables and configuration.

## References

- [CNI Specification](https://github.com/containernetworking/cni/blob/master/SPEC.md)
- [CNI GitHub Repository](https://github.com/containernetworking/cni)