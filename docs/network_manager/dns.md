# DNS Module Documentation

## Overview

The DNS Module is a key component of the Quantum-Network Fabric Layer that provides name resolution services for containers. It enables containers to discover and communicate with each other using hostnames instead of IP addresses, simplifying network management and enhancing service discovery capabilities.

## Architecture

The DNS Module consists of the following components:

- **DNS Manager**: Central controller for DNS operations
- **DNS Server**: Embedded DNS server for name resolution
- **Record Manager**: Manages DNS records and zones
- **Service Discovery**: Provides service discovery functionality
- **mDNS Integration**: Supports multicast DNS for local discovery

## DNS Manager

The DNS Manager (`DnsManager`) is the central component that:

- Initializes and configures the DNS subsystem
- Manages DNS records for containers and services
- Integrates with the Virtual Network Manager
- Provides an API for DNS record management
- Handles DNS queries and responses

### Configuration

The DNS Manager can be configured through the `DnsConfig` structure:

```rust
pub struct DnsConfig {
    pub server_enabled: bool,
    pub server_port: u16,
    pub mdns_enabled: bool,
    pub domain_suffix: String,
    pub default_ttl: u32,
    pub forward_upstream: bool,
    pub upstream_servers: Vec<String>,
    pub cache_size: usize,
    pub metrics_enabled: bool,
}
```

Default configuration:
- Server Enabled: true
- Server Port: 53
- mDNS Enabled: true
- Domain Suffix: "quantum.local"
- Default TTL: 3600 seconds
- Forward Upstream: true
- Upstream Servers: ["8.8.8.8", "1.1.1.1"]
- Cache Size: 1000 entries
- Metrics: Enabled

## DNS Records

The DNS Module supports various record types:

### A Records

A records map hostnames to IPv4 addresses:

```rust
pub struct ARecord {
    pub name: String,
    pub ip: Ipv4Addr,
    pub ttl: u32,
}
```

### AAAA Records

AAAA records map hostnames to IPv6 addresses:

```rust
pub struct AaaaRecord {
    pub name: String,
    pub ip: Ipv6Addr,
    pub ttl: u32,
}
```

### CNAME Records

CNAME records create aliases for existing hostnames:

```rust
pub struct CnameRecord {
    pub name: String,
    pub target: String,
    pub ttl: u32,
}
```

### SRV Records

SRV records define the location of services:

```rust
pub struct SrvRecord {
    pub name: String,
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
    pub ttl: u32,
}
```

### TXT Records

TXT records store arbitrary text data:

```rust
pub struct TxtRecord {
    pub name: String,
    pub data: Vec<String>,
    pub ttl: u32,
}
```

## DNS Server

The DNS Module includes an embedded DNS server that:

- Listens for DNS queries on the configured port
- Resolves queries using the record database
- Forwards queries to upstream servers when needed
- Caches responses for improved performance
- Supports both UDP and TCP transports

```rust
pub struct DnsServer {
    config: DnsConfig,
    records: Arc<RwLock<RecordStore>>,
    cache: Arc<RwLock<LruCache<Query, Message>>>,
}

impl DnsServer {
    pub async fn start(&self) -> Result<()> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), self.config.server_port);
        
        // Create UDP socket
        let socket = UdpSocket::bind(addr).await?;
        
        // Handle incoming queries
        loop {
            let mut buf = vec![0; 512];
            let (size, src) = socket.recv_from(&mut buf).await?;
            
            // Parse query
            let query = Message::from_vec(&buf[..size])?;
            
            // Process query and generate response
            let response = self.process_query(query).await?;
            
            // Send response
            socket.send_to(&response.to_vec()?, src).await?;
        }
    }
    
    async fn process_query(&self, query: Message) -> Result<Message> {
        // Check cache first
        let cache_key = query.queries().first().cloned().unwrap_or_default();
        
        // Try to get from cache
        let mut cache = self.cache.write().await;
        if let Some(cached) = cache.get(&cache_key) {
            return Ok(cached.clone());
        }
        
        // Process query
        let mut response = Message::new();
        response.set_id(query.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_authoritative(true);
        
        // Process each query
        for q in query.queries() {
            let records = self.records.read().await;
            
            // Try to find matching records
            let answers = records.lookup(&q.name().to_string(), q.query_type());
            
            if !answers.is_empty() {
                // Add answers to response
                for answer in answers {
                    response.add_answer(answer);
                }
                response.set_response_code(ResponseCode::NoError);
            } else if self.config.forward_upstream {
                // Forward to upstream servers
                let upstream_response = self.forward_to_upstream(&query).await?;
                return Ok(upstream_response);
            } else {
                response.set_response_code(ResponseCode::NXDomain);
            }
        }
        
        // Cache the response
        cache.put(cache_key, response.clone());
        
        Ok(response)
    }
    
    // Other methods...
}
```

## Container Integration

The DNS Module automatically manages DNS records for containers:

1. **Container Creation**: When a container joins a network, an A record is created
2. **Container Removal**: When a container leaves a network, its records are removed
3. **Container Update**: When a container's IP changes, its records are updated

```rust
pub async fn register_container(
    &self,
    container_id: &str,
    container_name: &str,
    ip_address: &str,
    network_id: &str,
) -> Result<()> {
    // Parse IP address
    let ip = IpAddr::from_str(ip_address)?;
    
    // Generate DNS names
    let short_name = container_name.split('.').next().unwrap_or(container_name);
    let full_name = format!("{}.{}", short_name, self.config.domain_suffix);
    let id_name = format!("{}.{}", &container_id[..12], self.config.domain_suffix);
    
    // Create records
    let mut records = self.records.write().await;
    
    match ip {
        IpAddr::V4(ipv4) => {
            // Add A records
            records.add_a(ARecord {
                name: full_name.clone(),
                ip: ipv4,
                ttl: self.config.default_ttl,
            });
            
            records.add_a(ARecord {
                name: id_name,
                ip: ipv4,
                ttl: self.config.default_ttl,
            });
        },
        IpAddr::V6(ipv6) => {
            // Add AAAA records
            records.add_aaaa(AaaaRecord {
                name: full_name.clone(),
                ip: ipv6,
                ttl: self.config.default_ttl,
            });
            
            records.add_aaaa(AaaaRecord {
                name: id_name,
                ip: ipv6,
                ttl: self.config.default_ttl,
            });
        },
    }
    
    // Add network-specific record
    let network_name = format!("{}.{}.{}", short_name, network_id, self.config.domain_suffix);
    
    match ip {
        IpAddr::V4(ipv4) => {
            records.add_a(ARecord {
                name: network_name,
                ip: ipv4,
                ttl: self.config.default_ttl,
            });
        },
        IpAddr::V6(ipv6) => {
            records.add_aaaa(AaaaRecord {
                name: network_name,
                ip: ipv6,
                ttl: self.config.default_ttl,
            });
        },
    }
    
    Ok(())
}
```

## Service Discovery

The DNS Module provides service discovery functionality:

### Service Registration

Services can be registered with the DNS Module:

```rust
pub struct Service {
    pub id: String,
    pub name: String,
    pub network_id: String,
    pub ip_address: String,
    pub port: u16,
    pub protocol: String,
    pub priority: u16,
    pub weight: u16,
    pub tags: HashMap<String, String>,
    pub ttl: u32,
}
```

### Service Discovery Methods

Services can be discovered through:

1. **DNS Queries**: Standard DNS queries for A/AAAA records
2. **SRV Queries**: For service location information
3. **TXT Queries**: For service metadata
4. **mDNS**: For local network discovery
5. **API**: Programmatic service discovery

## mDNS Integration

The DNS Module supports Multicast DNS (mDNS) for local service discovery:

1. **mDNS Responder**: Responds to multicast queries on the local network
2. **Service Announcement**: Announces services via mDNS
3. **Zero-Configuration**: Enables zero-configuration networking
4. **Local Name Resolution**: Resolves .local domain names

```rust
pub struct MdnsResponder {
    config: DnsConfig,
    records: Arc<RwLock<RecordStore>>,
}

impl MdnsResponder {
    pub async fn start(&self) -> Result<()> {
        // Create multicast socket
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
        let socket = UdpSocket::bind("0.0.0.0:5353").await?;
        
        // Join multicast group
        socket.join_multicast_v4(Ipv4Addr::new(224, 0, 0, 251), Ipv4Addr::new(0, 0, 0, 0))?;
        
        // Handle incoming queries
        loop {
            let mut buf = vec![0; 512];
            let (size, src) = socket.recv_from(&mut buf).await?;
            
            // Parse query
            let query = Message::from_vec(&buf[..size])?;
            
            // Process mDNS query
            if let Some(response) = self.process_mdns_query(query).await? {
                // Send response
                socket.send_to(&response.to_vec()?, src).await?;
            }
        }
    }
    
    // Other methods...
}
```

## DNS Resolution Process

When a container performs a DNS lookup, the following process occurs:

1. **Query Reception**: The DNS server receives the query
2. **Cache Check**: The server checks if the response is cached
3. **Local Resolution**: The server attempts to resolve using local records
4. **Upstream Forwarding**: If not found locally and forwarding is enabled, the query is sent to upstream servers
5. **Response Generation**: The server generates and returns the response
6. **Cache Update**: The response is cached for future queries

## Integration with Other Modules

The DNS Module integrates with:

- **Virtual Network Manager**: For network-aware name resolution
- **CNI Module**: For container DNS configuration
- **API Module**: For DNS record management
- **Metrics Module**: For DNS performance monitoring

## DNS Configuration for Containers

The DNS Module provides DNS configuration for containers:

```json
{
  "nameservers": ["172.20.0.1"],
  "domain": "quantum.local",
  "search": ["quantum.local", "svc.quantum.local"],
  "options": ["ndots:2", "timeout:2", "attempts:3"]
}
```

This configuration is passed to containers through the CNI Module, ensuring that containers use the Quantum-Network DNS server for name resolution.

## Metrics

The DNS Module exposes the following metrics:

- `dns_queries_total`: Counter of DNS queries by type
- `dns_responses_total`: Counter of DNS responses by response code
- `dns_query_duration_seconds`: Histogram of query processing durations
- `dns_cache_hits_total`: Counter of cache hits
- `dns_cache_misses_total`: Counter of cache misses
- `dns_records_total`: Gauge of total DNS records by type
- `dns_services_total`: Gauge of registered services

## Example Usage

### Starting the DNS Server

```rust
let config = DnsConfig {
    server_enabled: true,
    server_port: 53,
    domain_suffix: "quantum.local".to_string(),
    ..Default::default()
};

let dns_manager = DnsManager::new(config);

// Start the DNS server
dns_manager.start_server().await?;

println!("DNS server started on port 53");
```

### Registering a Container

```rust
// Register a container
dns_manager
    .register_container(
        "container123",
        "web-server",
        "172.20.0.2",
        "net-456",
    )
    .await?;

println!("Container registered with DNS");
```

### Registering a Service

```rust
// Register a service
let service = Service {
    id: "svc-123".to_string(),
    name: "web".to_string(),
    network_id: "net-456".to_string(),
    ip_address: "172.20.0.2".to_string(),
    port: 80,
    protocol: "tcp".to_string(),
    priority: 10,
    weight: 100,
    tags: HashMap::new(),
    ttl: 3600,
};

dns_manager.register_service(service).await?;

println!("Service registered with DNS");
```

## Troubleshooting

Common issues and their solutions:

1. **Name Resolution Fails**: Check DNS server status and container DNS configuration
2. **Service Discovery Issues**: Verify service registration and network connectivity
3. **mDNS Not Working**: Check multicast routing and firewall settings
4. **Performance Problems**: Consider increasing cache size or optimizing record count
5. **Upstream Resolution Fails**: Verify upstream server configuration and connectivity