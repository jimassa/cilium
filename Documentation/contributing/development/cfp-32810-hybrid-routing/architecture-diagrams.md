# CFP-32810: Hybrid Routing Mode - Architecture Diagrams

This document contains detailed architecture diagrams for the Hybrid Routing Mode implementation using Mermaid.

## Table of Contents

1. [High-Level System Architecture](#1-high-level-system-architecture)
2. [Component Relationships](#2-component-relationships)
3. [Dynamic Configuration Update Flow](#3-dynamic-configuration-update-flow)
4. [Data Plane Packet Processing](#4-data-plane-packet-processing)
5. [Agent Startup Sequence](#5-agent-startup-sequence)
6. [eBPF Map Reconciliation Flow](#6-ebpf-map-reconciliation-flow)
7. [Subnet Topology Agent State Machine](#7-subnet-topology-agent-state-machine)
8. [Kubernetes Integration](#8-kubernetes-integration)
9. [Class Diagram: Key Components](#9-class-diagram-key-components)
10. [Deployment Architecture](#10-deployment-architecture)

---

## 1. High-Level System Architecture

```mermaid
graph TB
    subgraph "User Configuration"
        CM[ConfigMap<br/>subnet-topology-ipv4/v6]
        CLI[CLI Flags<br/>--routing-mode=hybrid]
    end

    subgraph "Cilium Agent Process"
        subgraph "Control Plane Components"
            DC[DaemonConfig<br/>RoutingMode=hybrid]
            LNC[LocalNodeConfiguration<br/>EnableHybridRouting]
            STA[Subnet Topology Agent<br/>Config Parser & Reconciler]
            HFW[HeaderfileWriter<br/>Generate C Defines]
        end

        subgraph "eBPF Maps (Kernel Space)"
            STM4[cilium_subnet_topology_v4<br/>LPM Trie Map]
            STM6[cilium_subnet_topology_v6<br/>LPM Trie Map]
            IPM[cilium_ipcache_v2<br/>Endpoint Info]
        end
    end

    subgraph "Data Plane (eBPF Programs)"
        BPF_LXC[bpf_lxc.c<br/>Container Egress]
        BPF_HOST[bpf_host.c<br/>Host Network]
        BPF_OVL[bpf_overlay.c<br/>Overlay Network]
    end

    subgraph "Network"
        PKT_NATIVE[Native Routing<br/>Same Subnet]
        PKT_TUNNEL[Encapsulation<br/>Different Subnets]
    end

    %% Configuration Flow
    CLI --> DC
    CM --> STA
    DC --> LNC
    DC --> HFW
    LNC --> HFW

    %% Agent to Maps
    STA -->|Update/Delete| STM4
    STA -->|Update/Delete| STM6

    %% Header Generation
    HFW -->|Generate node_config.h<br/>HYBRID_ROUTING_MODE| BPF_LXC
    HFW -->|Generate node_config.h<br/>HYBRID_ROUTING_MODE| BPF_HOST
    HFW -->|Generate node_config.h<br/>HYBRID_ROUTING_MODE| BPF_OVL

    %% Datapath Lookups
    BPF_LXC -.->|lookup_subnet_id| STM4
    BPF_LXC -.->|lookup_subnet_id| STM6
    BPF_LXC -.->|ipcache_lookup| IPM

    BPF_HOST -.->|lookup_subnet_id| STM4
    BPF_HOST -.->|lookup_subnet_id| STM6
    BPF_HOST -.->|ipcache_lookup| IPM

    %% Routing Decisions
    BPF_LXC -->|Same Subnet| PKT_NATIVE
    BPF_LXC -->|Different Subnet| PKT_TUNNEL
    BPF_HOST -->|Same Subnet| PKT_NATIVE
    BPF_HOST -->|Different Subnet| PKT_TUNNEL

    style CM fill:#e1f5ff
    style STA fill:#fff4e1
    style STM4 fill:#e8f5e9
    style STM6 fill:#e8f5e9
    style BPF_LXC fill:#f3e5f5
    style BPF_HOST fill:#f3e5f5
    style PKT_NATIVE fill:#c8e6c9
    style PKT_TUNNEL fill:#ffccbc
```

---

## 2. Component Relationships

```mermaid
graph LR
    subgraph "pkg/option"
        Config[DaemonConfig<br/>• RoutingMode<br/>• SubnetTopologyConfigMap<br/>• HybridRoutingEnabled]
    end

    subgraph "pkg/datapath/types"
        LNC[LocalNodeConfiguration<br/>• EnableHybridRouting<br/>• SubnetTopologyIPv4Enabled<br/>• SubnetTopologyIPv6Enabled]
    end

    subgraph "pkg/subnetopology"
        Agent[Subnet Topology Agent<br/>• Config Parser<br/>• Subnet ID Assigner<br/>• Map Reconciler<br/>• File Watcher]
        Cell_Agent[Agent Cell<br/>Lifecycle Management]
    end

    subgraph "pkg/maps/subnetopology"
        MapOps[Map Operations<br/>• UpdateIPv4/IPv6<br/>• DeleteIPv4/IPv6<br/>• DumpIPv4/IPv6]
        Cell_Maps[Maps Cell<br/>OpenOrCreate Maps]
    end

    subgraph "pkg/datapath/linux/config"
        HFW[HeaderfileWriter<br/>• WriteNodeConfig<br/>• Emit HYBRID_ROUTING_MODE<br/>• Emit ENABLE_SUBNET_TOPOLOGY_*]
    end

    subgraph "bpf/lib"
        STH[subnet_topology.h<br/>• Map Definitions<br/>• lookup_subnet_id_v4/v6<br/>• should_skip_tunnel_for_subnet]
    end

    subgraph "daemon/cmd"
        Cells[cells.go<br/>Wire All Cells Together]
    end

    %% Relationships
    Config -->|Read by| Agent
    Config -->|Used to create| LNC
    LNC -->|Passed to| HFW

    Agent -->|Uses| MapOps
    Agent -->|Managed by| Cell_Agent
    MapOps -->|Managed by| Cell_Maps

    Cell_Agent -->|Registered in| Cells
    Cell_Maps -->|Registered in| Cells

    HFW -->|Generates| STH
    Config -->|Configures| HFW

    style Config fill:#e3f2fd
    style Agent fill:#fff9c4
    style MapOps fill:#c8e6c9
    style STH fill:#f3e5f5
    style Cells fill:#ffccbc
```

---

## 3. Dynamic Configuration Update Flow

```mermaid
sequenceDiagram
    participant User
    participant K8s as Kubernetes API
    participant Kubelet
    participant FS as File System
    participant FSNotify as fsnotify Watcher
    participant Agent as Subnet Topology Agent
    participant MapOps as Map Operations
    participant BPFMap as eBPF Map
    participant Datapath as eBPF Programs

    User->>K8s: kubectl edit configmap cilium-subnet-topology
    Note over User,K8s: Add new subnet groups

    K8s->>K8s: Store in etcd
    K8s->>Kubelet: Watch notification

    Kubelet->>FS: Create new timestamped directory
    Kubelet->>FS: Write new config file
    Kubelet->>FS: Update symlinks atomically

    FS->>FSNotify: File system event (Create/Rename)

    FSNotify->>Agent: Event received on channel
    Note over Agent: Watcher goroutine wakes up

    Agent->>Agent: readConfig() and Parse YAML
    Note over Agent: Parse config into subnet groups
    Agent->>Agent: Assign Subnet IDs to groups

    Agent->>Agent: reconcileIPv4()
    Note over Agent: Compare desired vs current state

    Agent->>MapOps: UpdateIPv4(cidr, subnetID=2)
    MapOps->>BPFMap: bpf_map_update_elem syscall

    BPFMap-->>MapOps: Success
    MapOps-->>Agent: Updated

    Agent->>Agent: Log: Adding CIDR with subnet_id=2

    Note over Datapath: Next packet processed
    Datapath->>BPFMap: lookup_subnet_id(192.168.0.100)
    BPFMap-->>Datapath: Returns: 2

    Note over Datapath: Same subnet_id, use native routing!

    Note over User,Datapath: Total time ~5-10ms, no agent restart needed!
```

---

## 4. Data Plane Packet Processing

```mermaid
flowchart TD
    Start([Packet Arrives]) --> CheckTunnelMode{TUNNEL_MODE<br/>defined?}

    CheckTunnelMode -->|No| NativeRoute[Use Native Routing<br/>No encapsulation]
    CheckTunnelMode -->|Yes| CheckHybrid{HYBRID_ROUTING_MODE<br/>defined?}

    CheckHybrid -->|No| TunnelMode[Traditional Tunnel Mode<br/>Check ipcache only]
    CheckHybrid -->|Yes| HybridMode[Hybrid Routing Mode]

    HybridMode --> ExtractIPs[Extract src_ip and dst_ip<br/>from packet]

    ExtractIPs --> LookupSrc[src_subnet_id =<br/>lookup_subnet_id_v4/v6]
    LookupSrc --> LookupDst[dst_subnet_id =<br/>lookup_subnet_id_v4/v6]

    LookupDst --> CompareSubnets{src_subnet_id ==<br/>dst_subnet_id<br/>AND<br/>src_subnet_id != 0?}

    CompareSubnets -->|Yes| SameSubnet[Same Subnet Group<br/>skip_tunnel = true]
    CompareSubnets -->|No| DiffSubnet[Different Subnet Groups<br/>or Unknown<br/>skip_tunnel = false]

    SameSubnet --> CheckSkip{skip_tunnel?}
    DiffSubnet --> CheckIPCache[Check ipcache for<br/>tunnel endpoint]

    TunnelMode --> CheckIPCache

    CheckIPCache --> HasTunnelEP{Has tunnel<br/>endpoint?}

    HasTunnelEP -->|Yes| CheckAutoSkip{flag_skip_tunnel<br/>set?}
    HasTunnelEP -->|No| NativeRoute

    CheckAutoSkip -->|Yes| CheckSkip
    CheckAutoSkip -->|No| CheckSkip

    CheckSkip -->|Yes| NativeRoute
    CheckSkip -->|No| Encapsulate[Encapsulate Packet<br/>VXLAN/Geneve]

    Encapsulate --> RedirectTunnel[Redirect to<br/>Tunnel Device]
    NativeRoute --> RedirectStack[Pass to<br/>Linux Stack]

    RedirectTunnel --> End([Done])
    RedirectStack --> End

    style Start fill:#e3f2fd
    style HybridMode fill:#fff9c4
    style SameSubnet fill:#c8e6c9
    style DiffSubnet fill:#ffccbc
    style Encapsulate fill:#ffccbc
    style NativeRoute fill:#c8e6c9
    style End fill:#e3f2fd
```

---

## 5. Agent Startup Sequence

```mermaid
sequenceDiagram
    participant Main as main()<br/>daemon/cmd/agent.go
    participant Hive as Hive Framework
    participant ConfigCell as Config Cell
    participant MapsCell as Subnet Topology<br/>Maps Cell
    participant AgentCell as Subnet Topology<br/>Agent Cell
    participant Agent as Subnet Topology<br/>Agent Instance
    participant FSNotify as fsnotify Watcher
    participant BPFMaps as eBPF Maps

    Main->>Hive: Initialize Hive
    Hive->>Hive: Discover all cells

    Hive->>ConfigCell: Invoke provider
    ConfigCell->>ConfigCell: Load DaemonConfig<br/>from CLI flags
    ConfigCell-->>Hive: Return config

    Note over Hive: Resolve dependencies

    Hive->>MapsCell: Check if enabled
    MapsCell->>MapsCell: if HybridRoutingEnabled()

    alt Hybrid Routing Enabled
        MapsCell->>BPFMaps: OpenOrCreate()<br/>cilium_subnet_topology_v4
        BPFMaps-->>MapsCell: Map FD
        MapsCell->>BPFMaps: OpenOrCreate()<br/>cilium_subnet_topology_v6
        BPFMaps-->>MapsCell: Map FD
    else Disabled
        MapsCell->>MapsCell: Return nil (skip)
    end

    Hive->>AgentCell: Invoke provider
    AgentCell->>AgentCell: if HybridRoutingEnabled()

    alt Hybrid Routing Enabled
        AgentCell->>Agent: NewAgent(logger, configPath)
        Agent-->>AgentCell: agent instance
        AgentCell->>AgentCell: Register OnStart/OnStop hooks
    else Disabled
        AgentCell->>AgentCell: Return nil (skip)
    end

    Note over Hive: All cells initialized

    Hive->>Hive: Call all OnStart hooks

    Hive->>MapsCell: OnStart()
    MapsCell->>MapsCell: Maps already opened
    MapsCell-->>Hive: OK

    Hive->>AgentCell: OnStart()
    AgentCell->>Agent: Start()

    Agent->>FSNotify: NewWatcher()
    FSNotify-->>Agent: watcher

    Agent->>FSNotify: Add(configDir)
    FSNotify-->>Agent: OK

    Agent->>BPFMaps: Dump() existing entries
    BPFMaps-->>Agent: Current state
    Note over Agent: Restore: Remember what's<br/>currently in maps

    Agent->>Agent: ReadFile(configPath)
    Agent->>Agent: Parse config YAML
    Agent->>Agent: Assign subnet IDs

    Agent->>Agent: reconcileIPv4/v6()
    Note over Agent: Add missing CIDRs<br/>Remove stale CIDRs

    Agent->>BPFMaps: Update() new CIDRs
    BPFMaps-->>Agent: OK

    Agent->>Agent: Start goroutine<br/>for file watching

    Agent-->>AgentCell: Started
    AgentCell-->>Hive: OK

    Note over Hive,Agent: Agent running normally<br/>Goroutine watching for changes

    loop Forever (until SIGTERM)
        FSNotify->>Agent: Config file changed
        Agent->>Agent: Update()
        Agent->>BPFMaps: Reconcile maps
    end
```

---

## 6. eBPF Map Reconciliation Flow

```mermaid
flowchart TD
    Start([reconcileIPv4 called]) --> BuildDesired[Build desired state<br/>from parsed config]

    BuildDesired --> DesiredMap["desiredCIDRs = {}<br/>For each group:<br/>  For each CIDR:<br/>    Add to desiredCIDRs<br/>    with subnet ID"]

    DesiredMap --> AddLoop{For each CIDR<br/>in desired state}

    AddLoop -->|Next CIDR| CheckInMap{CIDR already<br/>in map?}

    CheckInMap -->|No| AddCIDR[Log: Adding CIDR<br/>MapOps.UpdateIPv4]
    CheckInMap -->|Yes| AddLoop

    AddCIDR --> UpdateMap[bpf_map_update_elem<br/>Key: CIDR<br/>Value: Subnet ID]
    UpdateMap --> TrackAdded[Track in<br/>ipv4CIDRsInMap]
    TrackAdded --> AddLoop

    AddLoop -->|Done| RemoveLoop{For each CIDR<br/>currently in map}

    RemoveLoop -->|Next CIDR| CheckInDesired{CIDR in<br/>desired state?}

    CheckInDesired -->|No| RemoveCIDR[Log: Removing CIDR<br/>MapOps.DeleteIPv4]
    CheckInDesired -->|Yes| RemoveLoop

    RemoveCIDR --> DeleteMap[bpf_map_delete_elem<br/>Key: CIDR]
    DeleteMap --> UntrackRemoved[Remove from<br/>ipv4CIDRsInMap]
    UntrackRemoved --> RemoveLoop

    RemoveLoop -->|Done| End([Reconciliation complete])

    style Start fill:#e3f2fd
    style BuildDesired fill:#fff9c4
    style AddCIDR fill:#c8e6c9
    style RemoveCIDR fill:#ffccbc
    style End fill:#e3f2fd
```

---

## 7. Subnet Topology Agent State Machine

```mermaid
stateDiagram-v2
    [*] --> NotCreated: Agent process starts

    NotCreated --> Created: HybridRoutingEnabled() == true
    NotCreated --> [*]: HybridRoutingEnabled() == false<br/>(Cell returns nil)

    Created --> Starting: Hive calls OnStart hook

    Starting --> Restoring: Create fsnotify watcher
    Restoring --> Parsing: Dump existing eBPF maps
    Parsing --> Reconciling: Read & parse config file
    Reconciling --> Running: Update eBPF maps

    Running --> Running: No config changes
    Running --> ConfigChanged: fsnotify event received

    ConfigChanged --> ParsingUpdate: Read updated config
    ParsingUpdate --> ReconcilingUpdate: Parse new subnet groups
    ReconcilingUpdate --> Running: Update eBPF maps

    Running --> Stopping: Hive calls OnStop hook<br/>(SIGTERM received)

    Stopping --> Stopped: Close watcher<br/>Stop goroutine
    Stopped --> [*]

    note right of NotCreated
        Config loaded:
        - RoutingMode = "hybrid"
        - SubnetTopologyConfigMap path
    end note

    note right of Running
        Goroutine blocked on:
        - watcher.Events channel
        - stop channel
    end note

    note right of ConfigChanged
        Events handled:
        - Create
        - Write
        - Chmod
        - Remove
        - Rename
    end note

    note right of Stopped
        eBPF maps remain pinned
        (survive agent restart)
    end note
```

---

## 8. Kubernetes Integration

```mermaid
graph TB
    subgraph "Kubernetes Control Plane"
        API[API Server]
        ETCD[(etcd)]
    end

    subgraph "Node 1"
        subgraph "Kubelet 1"
            KL1[Kubelet]
            CM1[ConfigMap Volume<br/>/var/lib/kubelet/pods/.../volumes/...]
        end

        subgraph "Cilium Pod 1"
            Agent1[Cilium Agent]
            STA1[Subnet Topology<br/>Agent Component]
            Mount1[Mounted ConfigMap<br/>/etc/cilium/subnet-topology-config.yaml]
            Maps1[eBPF Maps<br/>/sys/fs/bpf/tc/globals/]
        end
    end

    subgraph "Node 2"
        subgraph "Kubelet 2"
            KL2[Kubelet]
            CM2[ConfigMap Volume<br/>/var/lib/kubelet/pods/.../volumes/...]
        end

        subgraph "Cilium Pod 2"
            Agent2[Cilium Agent]
            STA2[Subnet Topology<br/>Agent Component]
            Mount2[Mounted ConfigMap<br/>/etc/cilium/subnet-topology-config.yaml]
            Maps2[eBPF Maps<br/>/sys/fs/bpf/tc/globals/]
        end
    end

    User[User/Operator] -->|kubectl edit/apply| API
    API <--> ETCD

    API -->|Watch ConfigMap| KL1
    API -->|Watch ConfigMap| KL2

    KL1 -->|Mount as file| CM1
    KL2 -->|Mount as file| CM2

    CM1 -.->|Symlink| Mount1
    CM2 -.->|Symlink| Mount2

    Mount1 -->|fsnotify watches| STA1
    Mount2 -->|fsnotify watches| STA2

    STA1 -->|Update/Delete| Maps1
    STA2 -->|Update/Delete| Maps2

    Agent1 -->|Contains| STA1
    Agent2 -->|Contains| STA2

    style API fill:#e3f2fd
    style STA1 fill:#fff9c4
    style STA2 fill:#fff9c4
    style Maps1 fill:#c8e6c9
    style Maps2 fill:#c8e6c9
    style Mount1 fill:#ffccbc
    style Mount2 fill:#ffccbc
```

---

## 9. Class Diagram: Key Components

```mermaid
classDiagram
    class DaemonConfig {
        +string RoutingMode
        +string SubnetTopologyConfigMap
        +bool EnableIPv4
        +bool EnableIPv6
        +TunnelingEnabled() bool
        +HybridRoutingEnabled() bool
    }

    class LocalNodeConfiguration {
        +bool EnableEncapsulation
        +bool EnableHybridRouting
        +bool SubnetTopologyIPv4Enabled
        +bool SubnetTopologyIPv6Enabled
        +*cidr.CIDR NativeRoutingCIDRIPv4
        +*cidr.CIDR NativeRoutingCIDRIPv6
    }

    class SubnetTopologyAgent {
        -*slog.Logger logger
        -string configPath
        -*fsnotify.Watcher watcher
        -[]SubnetGroup ipv4Groups
        -[]SubnetGroup ipv6Groups
        -map ipv4CIDRsInMap
        -map ipv6CIDRsInMap
        +Start() error
        +Stop()
        +Update() error
        -readConfig() error
        -reconcileIPv4() error
        -reconcileIPv6() error
        -restore() error
    }

    class SubnetGroup {
        +uint32 ID
        +[]netip.Prefix CIDRs
    }

    class Config {
        +string SubnetTopologyIPv4
        +string SubnetTopologyIPv6
    }

    class MapOperations {
        +UpdateIPv4(cidr, subnetID) error
        +UpdateIPv6(cidr, subnetID) error
        +DeleteIPv4(cidr) error
        +DeleteIPv6(cidr) error
        +DumpIPv4() map
        +DumpIPv6() map
    }

    class Key4 {
        +uint32 PrefixLen
        +types.IPv4 Address
        +String() string
    }

    class Key6 {
        +uint32 PrefixLen
        +types.IPv6 Address
        +String() string
    }

    class Value {
        +uint32 SubnetID
        +String() string
    }

    class BPFMap {
        +string name
        +ebpf.MapType type
        +Update(key, value) error
        +Delete(key) error
        +DumpWithCallback(callback) error
        +OpenOrCreate() error
    }

    class HeaderfileWriter {
        +WriteNodeConfig(cfg) error
        -generateDefines(cfg) map
    }

    DaemonConfig --> LocalNodeConfiguration : creates
    DaemonConfig --> SubnetTopologyAgent : configures

    SubnetTopologyAgent --> Config : reads
    SubnetTopologyAgent --> SubnetGroup : manages
    SubnetTopologyAgent --> MapOperations : uses

    MapOperations --> BPFMap : wraps
    MapOperations --> Key4 : creates
    MapOperations --> Key6 : creates
    MapOperations --> Value : creates

    BPFMap --> Key4 : key type
    BPFMap --> Key6 : key type
    BPFMap --> Value : value type

    LocalNodeConfiguration --> HeaderfileWriter : passed to

    SubnetGroup --> Config : parsed from
```

---

## 10. Deployment Architecture

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        subgraph "Namespace: kube-system"
            CM[ConfigMap: cilium-subnet-topology]

            DS[DaemonSet: cilium with hybrid routing]
        end

        subgraph "Node 1: 10.0.0.10"
            subgraph "Cilium Pod 1"
                Agent1[Cilium Agent Process]

                subgraph "Agent Components"
                    EP1[Endpoint Manager]
                    POL1[Policy Engine]
                    STA1[Subnet Topology Agent]
                    IPMASQ1[IP Masq Agent]
                end

                subgraph "eBPF Maps (Pinned)"
                    ST1_V4[cilium_subnet_topology_v4]
                    ST1_V6[cilium_subnet_topology_v6]
                    IPC1[cilium_ipcache_v2]
                end

                subgraph "Network Interfaces"
                    ETH1[eth0: 10.0.0.10]
                    CILIUM1[cilium_host]
                    TUNNEL1[cilium_vxlan]
                end
            end

            POD1_1[Pod: app-1]
            POD1_2[Pod: app-2]
        end

        subgraph "Node 2: 10.10.0.20"
            subgraph "Cilium Pod 2"
                Agent2[Cilium Agent Process]

                subgraph "Agent Components"
                    EP2[Endpoint Manager]
                    POL2[Policy Engine]
                    STA2[Subnet Topology Agent]
                    IPMASQ2[IP Masq Agent]
                end

                subgraph "eBPF Maps (Pinned)"
                    ST2_V4[cilium_subnet_topology_v4]
                    ST2_V6[cilium_subnet_topology_v6]
                    IPC2[cilium_ipcache_v2]
                end

                subgraph "Network Interfaces"
                    ETH2[eth0: 10.10.0.20]
                    CILIUM2[cilium_host]
                    TUNNEL2[cilium_vxlan]
                end
            end

            POD2_1[Pod: app-3]
            POD2_2[Pod: app-4]
        end

        subgraph "Node 3: 192.168.0.30"
            subgraph "Cilium Pod 3"
                Agent3[Cilium Agent Process]

                subgraph "Agent Components"
                    EP3[Endpoint Manager]
                    POL3[Policy Engine]
                    STA3[Subnet Topology Agent]
                    IPMASQ3[IP Masq Agent]
                end

                subgraph "eBPF Maps (Pinned)"
                    ST3_V4[cilium_subnet_topology_v4]
                    ST3_V6[cilium_subnet_topology_v6]
                    IPC3[cilium_ipcache_v2]
                end

                subgraph "Network Interfaces"
                    ETH3[eth0: 192.168.0.30]
                    CILIUM3[cilium_host]
                    TUNNEL3[cilium_vxlan]
                end
            end

            POD3_1[Pod: db-1]
            POD3_2[Pod: db-2]
        end
    end

    %% ConfigMap distribution
    CM -.->|Mounted| Agent1
    CM -.->|Mounted| Agent2
    CM -.->|Mounted| Agent3

    %% DaemonSet creates pods
    DS -->|Creates| Agent1
    DS -->|Creates| Agent2
    DS -->|Creates| Agent3

    %% Agent manages maps
    STA1 -->|Updates| ST1_V4
    STA2 -->|Updates| ST2_V4
    STA3 -->|Updates| ST3_V4

    %% Pod connectivity examples
    POD1_1 -.->|Native Routing<br/>Same subnet group| POD2_1
    POD1_1 -.->|VXLAN Tunnel<br/>Different subnet group| POD3_1
    POD2_1 -.->|VXLAN Tunnel<br/>Different subnet group| POD3_2

    style CM fill:#e3f2fd
    style STA1 fill:#fff9c4
    style STA2 fill:#fff9c4
    style STA3 fill:#fff9c4
    style ST1_V4 fill:#c8e6c9
    style ST2_V4 fill:#c8e6c9
    style ST3_V4 fill:#c8e6c9
    style POD1_1 fill:#e1bee7
    style POD2_1 fill:#e1bee7
    style POD3_1 fill:#e1bee7
```

---

## Traffic Flow Examples

### Example 1: Same Subnet Group (Native Routing)

```mermaid
sequenceDiagram
    participant P1 as Pod app-1<br/>10.0.0.100<br/>(Node 1)
    participant BPF1 as eBPF Program<br/>bpf_lxc.c<br/>(Node 1)
    participant Map1 as subnet_topology_v4<br/>(Node 1)
    participant Net as Network<br/>(Direct L3)
    participant BPF2 as eBPF Program<br/>bpf_host.c<br/>(Node 2)
    participant P2 as Pod app-3<br/>10.10.0.100<br/>(Node 2)

    P1->>BPF1: Send packet to 10.10.0.100

    BPF1->>Map1: lookup_subnet_id(10.0.0.100)
    Map1-->>BPF1: Returns: 1

    BPF1->>Map1: lookup_subnet_id(10.10.0.100)
    Map1-->>BPF1: Returns: 1

    Note over BPF1: src_subnet_id == dst_subnet_id (1==1), skip_tunnel = true

    BPF1->>Net: Forward packet natively (no encapsulation)
    Note over BPF1,Net: Direct L3 routing with lower overhead and higher throughput

    Net->>BPF2: Packet arrives at Node 2
    BPF2->>P2: Deliver to pod

    Note over P1,P2: Same subnet group - native routing used
```

### Example 2: Different Subnet Groups (Encapsulation)

```mermaid
sequenceDiagram
    participant P1 as Pod app-1<br/>10.0.0.100<br/>(Node 1)
    participant BPF1 as eBPF Program<br/>bpf_lxc.c<br/>(Node 1)
    participant Map1 as subnet_topology_v4<br/>(Node 1)
    participant IPC as ipcache_v2<br/>(Node 1)
    participant Tunnel as VXLAN Tunnel
    participant BPF3 as eBPF Program<br/>bpf_overlay.c<br/>(Node 3)
    participant P3 as Pod db-1<br/>192.168.0.100<br/>(Node 3)

    P1->>BPF1: Send packet to 192.168.0.100

    BPF1->>Map1: lookup_subnet_id(10.0.0.100)
    Map1-->>BPF1: Returns: 1

    BPF1->>Map1: lookup_subnet_id(192.168.0.100)
    Map1-->>BPF1: Returns: 2

    Note over BPF1: src_subnet_id != dst_subnet_id (1!=2), skip_tunnel = false

    BPF1->>IPC: ipcache_lookup(192.168.0.100)
    IPC-->>BPF1: tunnel_endpoint: 192.168.0.30

    Note over BPF1: Need encapsulation

    BPF1->>BPF1: Add VXLAN header (Outer 10.0.0.10→192.168.0.30, Inner 10.0.0.100→192.168.0.100)

    BPF1->>Tunnel: Send encapsulated packet
    Note over Tunnel: Cross-subnet via tunnel with encapsulation overhead

    Tunnel->>BPF3: Receive at Node 3
    BPF3->>BPF3: Decapsulate and remove VXLAN header

    BPF3->>P3: Deliver inner packet

    Note over P1,P3: Different subnet groups - VXLAN encapsulation used
```

---

## Summary

These diagrams illustrate:

1. **System Architecture**: How all components fit together
2. **Component Relationships**: Dependencies and interactions
3. **Dynamic Updates**: ConfigMap changes → eBPF map updates (no restart!)
4. **Packet Processing**: Routing decision logic in datapath
5. **Startup Sequence**: Hive cell initialization and lifecycle
6. **Reconciliation**: How maps stay in sync with config
7. **State Machine**: Agent lifecycle states
8. **Kubernetes Integration**: How ConfigMaps reach each node
9. **Class Diagram**: Object-oriented view of key types
10. **Deployment**: Multi-node cluster topology

**Key Takeaways**:
- ✅ Subnet Topology Agent runs **inside** Cilium Agent (not separate process)
- ✅ Dynamic updates via **fsnotify + eBPF map syscalls** (no restart)
- ✅ Routing decisions in **datapath** (fast path, per-packet)
- ✅ Configuration in **control plane** (slow path, on-change)
- ✅ Clean separation of concerns with **Hive cells**

---

**Generated**: January 2025
**Related**: CFP-32810 Hybrid Routing Mode Implementation
