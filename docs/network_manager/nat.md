# NAT Module Documentation

## Overview

The Network Address Translation (NAT) Module is an essential component of the Quantum-Network Fabric Layer that enables containers to communicate with external networks. It provides address translation, port mapping, and masquerading capabilities to facilitate connectivity between isolated container networks and the outside world.

## Architecture

The NAT Module consists of the following components:

- **NAT Manager**: Central controller for NAT operations
- **Rule Manager**: Manages NAT rules and translations
- **Port Mapper**: Handles port mapping for container services
- **Connection Tracker**: Monitors and manages NAT connections
- **Backend Providers**: Implementations for different NAT technologies (iptables, nftables)

## NAT Manager

The NAT Manager (`NatManager`) is the central component that:

- Initializes and configures the NAT subsystem
- Manages NAT rules for container networks
- Handles port mapping requests
- Coordinates with the Virtual Network Manager
- Provides an API for NAT configuration

### Configuration

The NAT Manager can be configured through the `NatConfig` structure:

```rust
pub struct NatConfig {
    pub enable_ip_forwarding: bool,
    pub enable_masquerade: bool,
    pub external_interface: Option<String>,
    pub port_range_start: u16,
    pub port_range_end: u16,
    pub backend: NatBackend,
    pub connection_tracking_timeout: u32,
    pub metrics_enabled: bool,
}
```

Default configuration:
- IP Forwarding: Enabled
- Masquerade: Enabled
- External Interface: Auto-detected
- Port Range: 32768-60999
- Backend: nftables
- Connection Tracking Timeout: 3600 seconds
- Metrics: Enabled

## NAT Types

The NAT Module supports different types of network address translation:

### Source NAT (SNAT)

Source NAT modifies the source address of outgoing packets:

- Used for outbound container traffic
- Replaces private container IPs with the host IP
- Enables containers to access external networks
- Maintains connection state for return traffic
- Typically implemented as masquerading

### Destination NAT (DNAT)

Destination NAT modifies the destination address of incoming packets:

- Used for inbound traffic to containers
- Redirects external traffic to container services
- Enables port mapping for container applications
- Maintains connection state for return traffic
- Typically implemented as port forwarding

### Masquerading

Masquerading is a special form of SNAT:

- Automatically uses the outgoing interface's IP address
- Adapts to dynamic IP changes on the host
- Simplifies configuration for outbound connectivity
- Slightly higher overhead than static SNAT
- Ideal for most container networking scenarios

## NAT Rules

NAT rules define how address translation is performed:

```rust
pub struct NatRule {
    pub id: String,
    pub nat_type: NatType,
    pub protocol: Protocol,
    pub source_address: Option<String>,
    pub source_port: Option<u16>,
    pub destination_address: Option<String>,
    pub destination_port: Option<u16>,
    pub translated_address: String,
    pub translated_port: Option<u16>,
    pub external_interface: Option<String>,
    pub internal_interface: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}
```

Key attributes:
- **id**: Unique identifier for the rule
- **nat_type**: SNAT, DNAT, or Masquerade
- **protocol**: TCP, UDP, ICMP, or All
- **source/destination**: Original packet addresses and ports
- **translated**: New addresses and ports after translation
- **interfaces**: External and internal network interfaces

## Port Mapping

The NAT Module provides port mapping for container services:

```rust
pub struct PortMapping {
    pub id: String,
    pub container_id: String,
    pub container_port: u16,
    pub host_port: u16,
    pub protocol: Protocol,
    pub host_ip: Option<String>,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}
```

Port mapping enables:
- External access to container services
- Multiple containers to share the host's IP address
- Service discovery through well-known ports
- Load balancing across multiple containers
- Secure exposure of internal services

## NAT Implementation

The NAT Module implements network address translation using:

### nftables Backend

The nftables backend is the default and recommended implementation:

```rust
pub struct NftablesBackend {
    config: NatConfig,
}

impl NatBackendProvider for NftablesBackend {
    async fn initialize(&self) -> Result<()> {
        // Create nftables tables and chains
        let output = Command::new("nft")
            .args([
                "add", "table", "inet", "quantum",
            ])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(Error::NatBackendError(String::from_utf8_lossy(&output.stderr).to_string()));
        }
        
        // Create prerouting chain (for DNAT)
        Command::new("nft")
            .args([
                "add", "chain", "inet", "quantum", "prerouting",
                "{", "type", "nat", "hook", "prerouting", "priority", "0", ";", "}",
            ])
            .output()
            .await?;
        
        // Create postrouting chain (for SNAT)
        Command::new("nft")
            .args([
                "add", "chain", "inet", "quantum", "postrouting",
                "{", "type", "nat", "hook", "postrouting", "priority", "100", ";", "}",
            ])
            .output()
            .await?;
        
        // Enable IP forwarding if configured
        if self.config.enable_ip_forwarding {
            fs::write("/proc/sys/net/ipv4/ip_forward", "1").await?;
        }
        
        Ok(())
    }
    
    async fn add_masquerade_rule(&self, network_cidr: &str, external_interface: &str) -> Result<String> {
        let rule_id = Uuid::new_v4().to_string();
        
        // Add masquerade rule
        let output = Command::new("nft")
            .args([
                "add", "rule", "inet", "quantum", "postrouting",
                "ip", "saddr", network_cidr,
                "oif", external_interface,
                "masquerade",
                "comment", &format!("quantum-nat-{}", rule_id),
            ])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(Error::NatBackendError(String::from_utf8_lossy(&output.stderr).to_string()));
        }
        
        Ok(rule_id)
    }
    
    async fn add_port_mapping_rule(
        &self,
        protocol: Protocol,
        host_ip: &str,
        host_port: u16,
        container_ip: &str,
        container_port: u16,
    ) -> Result<String> {
        let rule_id = Uuid::new_v4().to_string();
        
        // Add port mapping rule
        let proto = match protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            _ => return Err(Error::UnsupportedProtocol),
        };
        
        let output = Command::new("nft")
            .args([
                "add", "rule", "inet", "quantum", "prerouting",
                "ip", "daddr", host_ip,
                proto, "dport", &host_port.to_string(),
                "dnat", "to", &format!("{container_ip}:{container_port}"),
                "comment", &format!("quantum-portmap-{}", rule_id),
            ])
            .output()
            .await?;
        
        if !output.status.success() {
            return Err(Error::NatBackendError(String::from_utf8_lossy(&output.stderr).to_string()));
        }
        
        Ok(rule_id)
    }
    
    // Other methods...
}
```

### iptables Backend

The iptables backend is provided for compatibility:

```rust
pub struct IptablesBackend {
    config: NatConfig,
}

impl NatBackendProvider for IptablesBackend {
    async fn initialize(&self) -> Result<()> {
        // Create iptables chains
        let output = Command::new("iptables")
            .args([
                "-t", "nat", "-N", "QUANTUM-PREROUTING",
            ])
            .output()
            .await?;
        
        if !output.status.success() && !output.stderr.contains(b"Chain already exists") {
            return Err(Error::NatBackendError(String::from_utf8_lossy(&output.stderr).to_string()));
        }
        
        // Link to main chains
        Command::new("iptables")
            .args([
                "-t", "nat", "-A", "PREROUTING", "-j", "QUANTUM-PREROUTING",
            ])
            .output()
            .await?;
        
        Command::new("iptables")
            .args([
                "-t", "nat", "-N", "QUANTUM-POSTROUTING",
            ])
            .output()
            .await?;
        
        Command::new("iptables")
            .args([
                "-t", "nat", "-A", "POSTROUTING", "-j", "QUANTUM-POSTROUTING",
            ])
            .output()
            .await?;
        
        // Enable IP forwarding if configured
        if self.config.enable_ip_forwarding {
            fs::write("/proc/sys/net/ipv4/ip_forward", "1").await?;
        }
        
        Ok(())
    }
    
    // Other methods...
}
```

## Container Outbound Connectivity

The NAT Module enables container outbound connectivity through:

1. **Network Creation**: When a network is created, masquerade rules are added
2. **IP Forwarding**: System-level IP forwarding is enabled
3. **Masquerading**: Container source IPs are translated to the host IP
4. **Connection Tracking**: Return traffic is properly routed back to containers
5. **Default Routes**: Container default routes point to the network gateway

```rust
pub async fn enable_outbound_connectivity(&self, network: &VirtualNetwork) -> Result<()> {
    // Get external interface
    let external_interface = match &self.config.external_interface {
        Some(iface) => iface.clone(),
        None => self.detect_default_interface().await?,
    };
    
    // Add masquerade rule
    let rule_id = self.backend
        .add_masquerade_rule(&network.cidr, &external_interface)
        .await?;
    
    // Store rule information
    let rule = NatRule {
        id: rule_id,
        nat_type: NatType::Masquerade,
        protocol: Protocol::All,
        source_address: Some(network.cidr.clone()),
        source_port: None,
        destination_address: None,
        destination_port: None,
        translated_address: "0.0.0.0".to_string(), // Masquerade uses interface IP
        translated_port: None,
        external_interface: Some(external_interface),
        internal_interface: None,
        description: Some(format!("Masquerade for network {}", network.name)),
        created_at: Utc::now(),
    };
    
    let mut rules = self.rules.write().await;
    rules.insert(rule_id, rule);
    
    Ok(())
}
```

## Container Inbound Connectivity

The NAT Module enables container inbound connectivity through port mapping:

1. **Port Mapping Request**: A port mapping is requested for a container
2. **Port Allocation**: An available host port is allocated
3. **DNAT Rule Creation**: A DNAT rule is created to forward traffic
4. **Connection Tracking**: Return traffic is properly routed back to the host
5. **Service Exposure**: The container service is accessible from outside

```rust
pub async fn create_port_mapping(
    &self,
    container_id: &str,
    container_ip: &str,
    container_port: u16,
    host_port: Option<u16>,
    protocol: Protocol,
    host_ip: Option<String>,
) -> Result<PortMapping> {
    // Allocate host port if not specified
    let allocated_host_port = match host_port {
        Some(port) => {
            // Check if port is available
            if !self.is_port_available(port, &protocol).await? {
                return Err(Error::PortAlreadyAllocated(port));
            }
            port
        },
        None => self.allocate_port(&protocol).await?,
    };
    
    // Determine host IP
    let allocated_host_ip = match host_ip {
        Some(ip) => ip,
        None => "0.0.0.0".to_string(), // Listen on all interfaces
    };
    
    // Create DNAT rule
    let rule_id = self.backend
        .add_port_mapping_rule(
            protocol.clone(),
            &allocated_host_ip,
            allocated_host_port,
            container_ip,
            container_port,
        )
        .await?;
    
    // Create port mapping record
    let mapping_id = Uuid::new_v4().to_string();
    let mapping = PortMapping {
        id: mapping_id.clone(),
        container_id: container_id.to_string(),
        container_port,
        host_port: allocated_host_port,
        protocol: protocol.clone(),
        host_ip: Some(allocated_host_ip.clone()),
        description: Some(format!("Port mapping for container {}", container_id)),
        created_at: Utc::now(),
    };
    
    // Store mapping and rule information
    let mut mappings = self.port_mappings.write().await;
    mappings.insert(mapping_id.clone(), mapping.clone());
    
    let rule = NatRule {
        id: rule_id,
        nat_type: NatType::Destination,
        protocol: protocol.clone(),
        source_address: None,
        source_port: None,
        destination_address: Some(allocated_host_ip),
        destination_port: Some(allocated_host_port),
        translated_address: container_ip.to_string(),
        translated_port: Some(container_port),
        external_interface: None,
        internal_interface: None,
        description: Some(format!("Port mapping for container {}", container_id)),
        created_at: Utc::now(),
    };
    
    let mut rules = self.rules.write().await;
    rules.insert(rule_id, rule);
    
    Ok(mapping)
}
```

## Port Allocation

The NAT Module manages port allocation for container services:

1. **Port Range**: Configurable range of ports for allocation
2. **Port Tracking**: Keeps track of allocated ports
3. **Conflict Prevention**: Ensures no port conflicts occur
4. **Protocol Separation**: Separate tracking for TCP and UDP
5. **Explicit Allocation**: Support for explicitly requested ports

```rust
pub async fn allocate_port(&self, protocol: &Protocol) -> Result<u16> {
    let mut allocated_ports = self.allocated_ports.write().await;
    let proto_ports = allocated_ports.entry(protocol.clone()).or_insert_with(HashSet::new);
    
    // Find an available port in the configured range
    for port in self.config.port_range_start..=self.config.port_range_end {
        if !proto_ports.contains(&port) {
            proto_ports.insert(port);
            return Ok(port);
        }
    }
    
    Err(Error::NoAvailablePorts)
}
```

## Integration with Other Modules

The NAT Module integrates with:

- **Virtual Network Manager**: For network CIDR and gateway information
- **CNI Module**: For container network setup
- **Firewall Module**: For coordinated security policy
- **Bridge Module**: For local network implementation
- **Metrics Module**: For NAT performance monitoring

## Hairpin NAT

The NAT Module supports hairpin NAT for container-to-container communication via published ports:

1. **Loopback Detection**: Detects when containers access mapped ports on the host
2. **Hairpin Translation**: Performs double NAT for hairpin connections
3. **Connection Tracking**: Maintains state for hairpin connections
4. **Performance Optimization**: Minimizes overhead for hairpin traffic

## Metrics

The NAT Module exposes the following metrics:

- `nat_rules_total`: Total number of NAT rules by type
- `nat_port_mappings_total`: Total number of port mappings
- `nat_connections_total`: Counter of NAT connections by type
- `nat_operations_total`: Counter of NAT operations by type
- `nat_operation_errors_total`: Counter of operation errors by type
- `nat_operation_duration_seconds`: Histogram of operation durations

## Example Usage

### Enabling Outbound Connectivity

```rust
let config = NatConfig {
    enable_ip_forwarding: true,
    enable_masquerade: true,
    ..Default::default()
};

let nat_manager = NatManager::new(config);

// Enable outbound connectivity for a network
let network = VirtualNetwork {
    id: "net-123".to_string(),
    name: "example-network".to_string(),
    cidr: "172.20.0.0/16".to_string(),
    gateway: "172.20.0.1".to_string(),
    driver_type: DriverType::Bridge,
    isolation_mode: IsolationMode::Full,
    options: HashMap::new(),
    labels: HashMap::new(),
    created_at: Utc::now(),
    updated_at: Utc::now(),
};

nat_manager.enable_outbound_connectivity(&network).await?;

println!("Outbound connectivity enabled for network {}", network.name);
```

### Creating a Port Mapping

```rust
// Create a port mapping for a container
let mapping = nat_manager
    .create_port_mapping(
        "container123",
        "172.20.0.2",
        80,
        Some(8080),
        Protocol::Tcp,
        None,
    )
    .await?;

println!("Created port mapping: {}:{} -> {}:{}", 
         mapping.host_ip.unwrap_or("0.0.0.0".to_string()), 
         mapping.host_port, 
         "172.20.0.2", 
         mapping.container_port);
```

## Troubleshooting

Common issues and their solutions:

1. **No Outbound Connectivity**: Check IP forwarding and masquerade rules
2. **Port Mapping Fails**: Verify port availability and DNAT rules
3. **Connection Tracking Issues**: Check connection tracking table size and timeout
4. **Performance Problems**: Consider optimizing rule count and connection tracking
5. **Hairpin NAT Issues**: Verify hairpin mode configuration on bridges