# Bridge Module Documentation

## Overview

The Bridge Module is a fundamental component of the Quantum-Network Fabric Layer that creates and manages Linux network bridges for container connectivity. It provides the underlying network infrastructure for the Bridge driver in the Virtual Network Manager, enabling containers to communicate with each other and with external networks.

## Architecture

The Bridge Module consists of the following components:

- **Bridge Manager**: Central controller for bridge operations
- **Veth Manager**: Handles virtual Ethernet pair creation and management
- **IP Configuration**: Manages IP addressing for bridges
- **Forwarding Control**: Controls packet forwarding between interfaces

## Bridge Manager

The Bridge Manager (`BridgeManager`) is the central component that:

- Creates and configures Linux bridge devices
- Manages bridge lifecycle (creation, modification, deletion)
- Configures IP addresses and routes
- Controls bridge properties (STP, forwarding, etc.)
- Integrates with the Virtual Network Manager

### Configuration

The Bridge Manager can be configured through the `BridgeConfig` structure:

```rust
pub struct BridgeConfig {
    pub default_bridge_name: String,
    pub default_bridge_ip: String,
    pub default_bridge_mtu: u32,
    pub enable_ip_forwarding: bool,
    pub enable_stp: bool,
    pub forward_delay: u32,
    pub ageing_time: u32,
    pub metrics_enabled: bool,
}
```

Default configuration:
- Default Bridge Name: "forge0"
- Default Bridge IP: "172.17.0.1/16"
- Default MTU: 1500
- IP Forwarding: Enabled
- STP: Disabled
- Forward Delay: 15 seconds
- Ageing Time: 300 seconds
- Metrics: Enabled

## Bridge Creation

When a new bridge network is created, the Bridge Module performs the following steps:

1. **Bridge Device Creation**: Creates a new Linux bridge device
2. **MAC Address Configuration**: Sets the bridge MAC address
3. **STP Configuration**: Enables/disables Spanning Tree Protocol
4. **MTU Configuration**: Sets the Maximum Transmission Unit
5. **IP Configuration**: Assigns IP address and subnet
6. **Forwarding Configuration**: Enables IP forwarding if required
7. **Bridge Activation**: Brings the bridge interface up

```rust
pub async fn create_bridge(&self, name: &str, ip_addr: &str, mtu: u32) -> Result<Bridge> {
    // Create bridge device using netlink
    let mut bridge = Bridge::new(name);
    bridge.set_mtu(mtu);
    bridge.set_stp_state(self.config.enable_stp);
    bridge.set_forward_delay(self.config.forward_delay);
    bridge.set_ageing_time(self.config.ageing_time);
    
    // Add bridge to kernel
    self.netlink.add_bridge(&bridge).await?;
    
    // Configure IP address
    let addr = IpAddr::from_str(ip_addr)?;
    self.netlink.add_addr(name, &addr).await?;
    
    // Enable IP forwarding if configured
    if self.config.enable_ip_forwarding {
        self.enable_ip_forwarding().await?;
    }
    
    // Bring bridge up
    self.netlink.set_link_up(name).await?;
    
    Ok(bridge)
}
```

## Virtual Ethernet (veth) Pairs

The Bridge Module creates and manages veth pairs to connect containers to bridges:

1. **Veth Creation**: Creates a pair of virtual Ethernet interfaces
2. **Container End Configuration**: Moves one end to the container namespace
3. **Bridge End Configuration**: Attaches the other end to the bridge
4. **Interface Configuration**: Sets MTU, MAC address, and other properties
5. **Activation**: Brings both interfaces up

```rust
pub async fn create_veth_pair(
    &self,
    bridge_name: &str,
    container_id: &str,
    container_ifname: &str,
    host_ifname: &str,
    mtu: u32,
) -> Result<VethPair> {
    // Create veth pair using netlink
    let veth = VethPair::new(host_ifname, container_ifname);
    veth.set_mtu(mtu);
    
    // Add veth pair to kernel
    self.netlink.add_veth_pair(&veth).await?;
    
    // Attach host end to bridge
    self.netlink.set_link_master(host_ifname, bridge_name).await?;
    
    // Move container end to container namespace
    let container_ns = format!("/var/run/netns/{}", container_id);
    self.netlink.set_link_ns(container_ifname, &container_ns).await?;
    
    // Bring host end up
    self.netlink.set_link_up(host_ifname).await?;
    
    Ok(veth)
}
```

## IP Forwarding

The Bridge Module manages IP forwarding to enable container communication with external networks:

1. **System Configuration**: Enables IP forwarding at the system level
2. **Bridge-Specific Forwarding**: Controls forwarding for specific bridges
3. **Forwarding Tables**: Manages forwarding tables for efficient routing
4. **Path MTU Discovery**: Handles MTU discovery for optimal packet sizing

```rust
pub async fn enable_ip_forwarding(&self) -> Result<()> {
    // Enable IPv4 forwarding
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").await?;
    
    // Enable IPv6 forwarding if needed
    if self.config.ipv6_enabled {
        fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1").await?;
    }
    
    Ok(())
}
```

## Bridge Interface Management

The Bridge Module provides comprehensive management of bridge interfaces:

### Interface Properties

- **MTU**: Maximum Transmission Unit for the bridge
- **MAC Address**: Hardware address for the bridge
- **Promiscuous Mode**: Controls packet capture behavior
- **Multicast Settings**: Controls multicast traffic handling
- **Learning Mode**: Controls MAC address learning

### STP Configuration

- **STP State**: Enables/disables Spanning Tree Protocol
- **Bridge Priority**: Sets bridge priority for root bridge election
- **Path Cost**: Sets path cost for STP calculations
- **Forward Delay**: Sets delay before forwarding
- **Hello Time**: Sets interval between hello packets
- **Max Age**: Sets maximum age of STP information

## Integration with Virtual Network Manager

The Bridge Module integrates with the Virtual Network Manager:

1. **Driver Registration**: Registers as a network driver
2. **Network Creation**: Creates bridge infrastructure for new networks
3. **Endpoint Management**: Handles container attachment to bridges
4. **Network Deletion**: Cleans up bridge resources when networks are removed

```rust
impl NetworkDriver for BridgeDriver {
    async fn create_network(&self, network: &VirtualNetwork) -> Result<()> {
        // Generate bridge name from network ID
        let bridge_name = format!("br-{}", &network.id[0..12]);
        
        // Create bridge with network gateway as IP
        self.bridge_manager
            .create_bridge(&bridge_name, &network.gateway, 1500)
            .await?;
        
        // Store bridge information
        let mut bridges = self.bridges.write().await;
        bridges.insert(network.id.clone(), bridge_name);
        
        Ok(())
    }
    
    async fn connect_endpoint(&self, endpoint: &Endpoint, network: &VirtualNetwork) -> Result<()> {
        // Get bridge name for this network
        let bridges = self.bridges.read().await;
        let bridge_name = bridges.get(&network.id)
            .ok_or_else(|| Error::NetworkNotFound(network.id.clone()))?;
        
        // Generate interface names
        let host_ifname = format!("veth{}", &endpoint.id[0..12]);
        let container_ifname = "eth0";
        
        // Create veth pair and connect to bridge
        self.bridge_manager
            .create_veth_pair(
                bridge_name,
                &endpoint.container_id,
                container_ifname,
                &host_ifname,
                1500,
            )
            .await?;
        
        Ok(())
    }
    
    // Other driver methods...
}
```

## Netlink Communication

The Bridge Module uses netlink for communication with the Linux kernel:

- **RTNetlink**: For network interface configuration
- **Generic Netlink**: For advanced bridge configuration
- **Asynchronous Operations**: Non-blocking netlink communication
- **Batch Processing**: Efficient handling of multiple operations
- **Error Handling**: Comprehensive error handling for netlink operations

```rust
pub struct NetlinkManager {
    handle: Handle,
}

impl NetlinkManager {
    pub async fn add_bridge(&self, bridge: &Bridge) -> Result<()> {
        let mut link = LinkMessage::new();
        link.header.link_type = LinkType::Bridge;
        link.header.flags = IFF_UP.into();
        link.header.change_mask = IFF_UP.into();
        link.attributes.push(LinkAttribute::IfName(bridge.name.clone()));
        
        // Add bridge-specific attributes
        if let Some(mtu) = bridge.mtu {
            link.attributes.push(LinkAttribute::Mtu(mtu));
        }
        
        // Send netlink message
        self.handle.link().add().execute(&link).await?
        
        Ok(())
    }
    
    // Other netlink operations...
}
```

## Port Mapping

The Bridge Module supports port mapping for container external connectivity:

1. **DNAT Rules**: Creates DNAT rules to forward external traffic to containers
2. **Port Allocation**: Manages port allocation to avoid conflicts
3. **Protocol Support**: Handles TCP, UDP, and SCTP protocols
4. **Interface Binding**: Controls which interfaces accept mapped traffic
5. **Port Range Support**: Supports mapping port ranges

## Hairpin Mode

The Bridge Module supports hairpin mode for container self-communication:

1. **Hairpin Configuration**: Enables hairpin mode on bridge ports
2. **Reflection Control**: Manages packet reflection for container interfaces
3. **MAC Learning**: Configures MAC learning for hairpin operation

```rust
pub async fn enable_hairpin_mode(&self, bridge_name: &str, port_name: &str) -> Result<()> {
    // Enable hairpin mode using sysfs
    let path = format!("/sys/class/net/{}/brif/{}/hairpin_mode", bridge_name, port_name);
    fs::write(path, "1").await?;
    
    Ok(())
}
```

## Metrics

The Bridge Module exposes the following metrics:

- `bridge_total`: Total number of bridges
- `bridge_ports_total`: Total number of bridge ports
- `bridge_operations_total`: Counter of bridge operations by type
- `bridge_operation_errors_total`: Counter of operation errors by type
- `bridge_operation_duration_seconds`: Histogram of operation durations
- `bridge_rx_bytes_total`: Counter of received bytes per bridge
- `bridge_tx_bytes_total`: Counter of transmitted bytes per bridge
- `bridge_rx_packets_total`: Counter of received packets per bridge
- `bridge_tx_packets_total`: Counter of transmitted packets per bridge

## Example Usage

### Creating a Bridge

```rust
let config = BridgeConfig {
    default_bridge_name: "quantum0".to_string(),
    default_bridge_ip: "172.20.0.1/16".to_string(),
    default_bridge_mtu: 1500,
    enable_ip_forwarding: true,
    enable_stp: false,
    ..Default::default()
};

let bridge_manager = BridgeManager::new(config);

// Create a bridge
let bridge = bridge_manager
    .create_bridge("quantum0", "172.20.0.1/16", 1500)
    .await?;

println!("Created bridge: {}", bridge.name);
```

### Connecting a Container

```rust
// Create a veth pair
let veth = bridge_manager
    .create_veth_pair(
        "quantum0",
        "container123",
        "eth0",
        "vethABCDEF",
        1500,
    )
    .await?;

println!("Connected container to bridge");

// Enable hairpin mode if needed
bridge_manager
    .enable_hairpin_mode("quantum0", "vethABCDEF")
    .await?;
```

## Troubleshooting

Common issues and their solutions:

1. **Bridge Creation Fails**: Check for name conflicts or permissions
2. **Veth Creation Fails**: Verify namespace existence and permissions
3. **No Connectivity**: Check IP configuration and forwarding settings
4. **MTU Issues**: Ensure consistent MTU across interfaces
5. **Performance Problems**: Check for STP issues or MAC table overflow