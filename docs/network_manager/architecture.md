# Network Manager Architecture

The Network Manager is a core component of the Quantum platform, responsible for managing all aspects of container networking. It provides a comprehensive set of features for network creation, configuration, and management.

## System Architecture

The Network Manager is composed of several modules that work together to provide a complete networking solution:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Network Manager                             │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │    Bridge   │  │  Firewall   │  │     DNS     │  │   NAT   │ │
│  │   Manager   │  │   Manager   │  │   Manager   │  │ Manager │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Metrics   │  │  Container  │  │  Network    │             │
│  │   Manager   │  │ Integration │  │   Models    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Bridge Manager**: Responsible for creating and managing network bridges, which serve as the foundation for container networks.

2. **Firewall Manager**: Handles network security policies, implementing rules to control traffic flow between containers and external networks.

3. **DNS Manager**: Provides DNS resolution and service discovery capabilities for containers.

4. **NAT Manager**: Manages Network Address Translation, allowing containers with private IPs to communicate with external networks.

5. **Metrics Manager**: Collects and exposes performance and operational metrics for all network components.

6. **Container Integration**: Interfaces with the container runtime to configure networking for containers.

7. **Network Models**: Core data structures representing networks, endpoints, and other networking concepts.

## Component Interactions

The following diagram illustrates how the different components interact with each other:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Container │     │   Network   │     │   External  │
│   Runtime   │◄───►│   Manager   │◄───►│   Networks  │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
       ┌──────────────────┬┴─────────────────┐
       │                  │                  │
┌──────▼──────┐   ┌──────▼──────┐    ┌──────▼──────┐
│    Bridge    │   │   Firewall  │    │     DNS     │
│   Manager    │◄─►│   Manager   │◄──►│   Manager   │
└──────┬──────┘   └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       │           ┌──────▼──────┐          │
       └──────────►│     NAT     │◄─────────┘
                   │   Manager   │
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐
                   │   Metrics   │
                   │   Manager   │
                   └─────────────┘
```

## Data Flow

When a container is created and connected to a network, the following sequence of operations occurs:

1. The Container Runtime requests a network connection from the Network Manager
2. The Bridge Manager creates the necessary veth pair and connects it to the bridge
3. The Firewall Manager applies security policies to the container's network interface
4. The DNS Manager registers the container in the DNS service for discovery
5. The NAT Manager configures address translation if the container needs external access
6. The Metrics Manager collects performance data throughout the process

## Module Details

Each module in the Network Manager has its own architecture and components. Refer to the individual module documentation for more details:

- [Bridge Module](bridge.md)
- [Firewall Module](firewall.md)
- [DNS Module](dns.md)
- [NAT Module](nat.md)
- [Metrics Module](metrics.md)