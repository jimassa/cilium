# Cilium Routing Architecture

## Overview

This document describes the current routing architecture in Cilium, focusing on how routing modes work and the datapath implementation. This analysis is based on the Cilium codebase as of January 2025 and serves as a foundation for implementing CFP-32810 (Hybrid Routing Mode).

## Table of Contents

1. [Routing Modes](#routing-modes)
2. [Control Plane Architecture](#control-plane-architecture)
3. [Datapath Architecture](#datapath-architecture)
4. [Configuration System](#configuration-system)
5. [eBPF Maps and Data Structures](#ebpf-maps-and-data-structures)
6. [Encapsulation Implementation](#encapsulation-implementation)
7. [IP Cache System](#ip-cache-system)
8. [Dynamic Configuration Updates](#dynamic-configuration-updates)

---

## Routing Modes

Cilium currently supports two routing modes:

### 1. Tunnel Mode (Default)
- **Configuration**: `--routing-mode=tunnel`
- **Behavior**: All pod-to-pod traffic is encapsulated using VXLAN or Geneve
- **Use case**: Cross-subnet communication without direct L3 connectivity
- **Overhead**: Encapsulation adds header overhead and processing cost
- **Location**: [pkg/option/config.go:1018](pkg/option/config.go#L1018)

### 2. Native Routing Mode
- **Configuration**: `--routing-mode=native`
- **Behavior**: Pod IPs are routed directly by the underlying network
- **Requirements**:
  - Direct L3 connectivity between nodes
  - Native routing CIDR must be configured when masquerading is enabled
- **Advantages**: Lower overhead, higher throughput
- **Location**: [pkg/option/config.go:1016](pkg/option/config.go#L1016)

### Routing Mode Constants

```go
// pkg/option/config.go:1014-1021
const (
    RoutingModeNative = "native"
    RoutingModeTunnel = "tunnel"
)
```

---

## Control Plane Architecture

### Configuration Flow

```
CLI Flags → Viper Config → DaemonConfig → LocalNodeConfiguration → eBPF Header Defines
```

### Key Components

#### 1. DaemonConfig
**Location**: [pkg/option/config.go:1184](pkg/option/config.go#L1184)

Central configuration structure containing all daemon settings:

```go
type DaemonConfig struct {
    RoutingMode  string  // "native" or "tunnel"
    // ... hundreds of other config fields
}
```

**Key Methods**:
- `TunnelingEnabled()` - Returns true if tunneling should be used ([pkg/option/config.go:2011-2017](pkg/option/config.go#L2011-L2017))
- `DirectRoutingDeviceRequired()` - Determines if direct routing device is needed ([pkg/option/config.go:2198](pkg/option/config.go#L2198))

#### 2. LocalNodeConfiguration
**Location**: [pkg/datapath/types/node.go:33-208](pkg/datapath/types/node.go#L33-L208)

Immutable datapath configuration passed to eBPF programs:

```go
type LocalNodeConfiguration struct {
    NativeRoutingCIDRIPv4        *cidr.CIDR
    NativeRoutingCIDRIPv6        *cidr.CIDR
    EnableEncapsulation          bool  // Set from config.TunnelingEnabled()
    EnableAutoDirectRouting      bool
    DirectRoutingSkipUnreachable bool
    DirectRoutingDevice          *tables.Device
    // ... other fields
}
```

**Construction**: [pkg/datapath/orchestrator/localnodeconfig.go:43-145](pkg/datapath/orchestrator/localnodeconfig.go#L43-L145)

#### 3. Tunnel Configuration
**Location**: [pkg/datapath/tunnel/tunnel.go](pkg/datapath/tunnel/tunnel.go)

Manages tunnel-specific settings:

```go
type Config struct {
    underlay       UnderlayProtocol  // IPv4 or IPv6
    protocol       EncapProtocol     // VXLAN or Geneve
    port           uint16            // Default: 8472 (VXLAN), 6081 (Geneve)
    srcPortLow     uint16
    srcPortHigh    uint16
    deviceName     string
    shouldAdaptMTU bool
}
```

**Encapsulation Protocols**:
- **VXLAN**: Default tunnel protocol, port 8472
- **Geneve**: Alternative protocol, port 6081

**CLI Flags**:
- `--tunnel-protocol`: Choose "vxlan" or "geneve"
- `--tunnel-port`: Override default port
- `--underlay-protocol`: Choose "ipv4" or "ipv6"

---

## Datapath Architecture

### Compilation Flow

```
DaemonConfig → HeaderfileWriter → node_config.h → eBPF Programs
```

### 1. Header Generation
**Location**: [pkg/datapath/linux/config/config.go:56-95](pkg/datapath/linux/config/config.go#L56-L95)

The `HeaderfileWriter` generates `node_config.h` with C defines:

```go
func (h *HeaderfileWriter) WriteNodeConfig(cfg datapath.LocalNodeConfiguration) error {
    cDefinesMap := make(map[string]string)

    // Key routing mode define
    if option.Config.TunnelingEnabled() {
        cDefinesMap["TUNNEL_MODE"] = "1"
    }

    // Tunnel protocol
    cDefinesMap["TUNNEL_PROTOCOL"] = tunProtocol
    cDefinesMap["TUNNEL_PORT"] = strconv.FormatUint(uint64(tunPort), 10)

    // Masquerading
    if option.Config.EnableBPFMasquerade {
        if option.Config.EnableIPv4Masquerade {
            cDefinesMap["ENABLE_MASQUERADE_IPV4"] = "1"
            if option.Config.EnableIPMasqAgent {
                cDefinesMap["ENABLE_IP_MASQ_AGENT_IPV4"] = "1"
            }
        }
    }

    // ... write to bpf/node_config.h
}
```

### 2. eBPF Program Compilation

Programs are conditionally compiled based on `TUNNEL_MODE`:

**Key Programs**:
- `bpf_host.c` - Host network stack integration
- `bpf_lxc.c` - Container/endpoint datapath
- `bpf_overlay.c` - Overlay network handling
- Various nodeport and NAT programs

### 3. Runtime Configuration Structures

**Location**: [pkg/datapath/config/](pkg/datapath/config/)

Generated Go structures mirroring eBPF config:

```go
// node_config.go
type Node struct {
    DirectRoutingDeviceIfindex   uint32
    HybridRoutingEnabled         bool  // Future field for CFP-32810
    EnableRemoteNodeMasquerade   bool
    NATIPv4Masquerade           [4]byte
    NATIPv6Masquerade           [16]byte
    // ...
}
```

Similar structures exist for:
- `BPFOverlay` (overlay_config.go)
- `BPFHost` (host_config.go)
- `BPFLXC` (lxc_config.go)
- `BPFWireguard` (wireguard_config.go)
- `BPFXDP` (xdp_config.go)
- `BPFSocket` (socket_config.go)

---

## Configuration System

### Validation and Requirements

#### Native Routing CIDR Requirements
**Location**: [pkg/option/config.go:3023-3070](pkg/option/config.go#L3023-L3070)

Native routing CIDRs are **required** when:
1. `--routing-mode=native` is set
2. Masquerading is enabled (`--enable-ipv4-masquerade` or `--enable-ipv6-masquerade`)
3. IP masquerade agent is NOT enabled
4. Tunneling is NOT enabled

```go
func (c *DaemonConfig) checkIPv4NativeRoutingCIDR() error {
    if c.IPv4NativeRoutingCIDR != nil && !option.Config.TunnelingEnabled() &&
       c.EnableIPv4Masquerade && !c.EnableIPMasqAgent {
        return fmt.Errorf("ipv4-native-routing-cidr must be specified when using native routing mode with masquerading")
    }
    return nil
}
```

#### Routing Mode Validation
**Location**: [pkg/option/config.go:2284-2289](pkg/option/config.go#L2284-L2289)

```go
switch c.RoutingMode {
case RoutingModeNative, RoutingModeTunnel:
    // Valid
default:
    return fmt.Errorf("invalid routing mode %q, valid modes = {%q, %q}",
        c.RoutingMode, RoutingModeTunnel, RoutingModeNative)
}
```

---

## eBPF Maps and Data Structures

### 1. IP Cache Map
**Location**: [bpf/lib/eps.h:129-136](bpf/lib/eps.h#L129-L136)

Stores remote endpoint information:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipcache_key);
    __type(value, struct remote_endpoint_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, IPCACHE_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_ipcache_v2 __section_maps_btf;
```

**Remote Endpoint Info**: [bpf/lib/eps.h:92-110](bpf/lib/eps.h#L92-L110)

```c
struct remote_endpoint_info {
    __u32    sec_identity;
    union {
        struct {
            __u32 ip4;
            __u32 pad1;
            __u32 pad2;
            __u32 pad3;
        };
        union v6addr ip6;
    } tunnel_endpoint;
    __u16    pad;
    __u8     key;
    __u8     flag_skip_tunnel:1,        // Skip tunneling for this endpoint
             flag_has_tunnel_ep:1,      // Tunnel endpoint is set
             flag_ipv6_tunnel_ep:1,     // Tunnel endpoint is IPv6
             flag_remote_cluster:1,     // Endpoint in remote cluster
             pad2:4;
};
```

**Key Flags**:
- `flag_skip_tunnel`: When set, bypass encapsulation (used in auto-direct routing)
- `flag_has_tunnel_ep`: Indicates tunnel endpoint IP is valid
- `flag_ipv6_tunnel_ep`: Tunnel endpoint uses IPv6

### 2. IP Masquerading Maps
**Location**: [bpf/lib/nat.h](bpf/lib/nat.h)

LPM trie maps for CIDR-based masquerading decisions:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, struct lpm_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_ipmasq_v4 __section_maps_btf;

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, struct lpm_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_ipmasq_v6 __section_maps_btf;
```

**Key Structures**: [bpf/lib/common.h:666-679](bpf/lib/common.h#L666-L679)

```c
struct lpm_v4_key {
    struct bpf_lpm_trie_key lpm;  // Contains prefixlen
    __u8 addr[4];                 // IPv4 address
};

struct lpm_v6_key {
    struct bpf_lpm_trie_key lpm;  // Contains prefixlen
    __u8 addr[16];                // IPv6 address
};

struct lpm_val {
    __u8 flags;  // Dummy value for now
};
```

### 3. Other LPM Trie Maps

**Egress Gateway Policy**: [bpf/lib/egress_gateway.h:13-29](bpf/lib/egress_gateway.h#L13-L29)
```c
cilium_egress_gw_policy_v4  // Egress gateway routing decisions
cilium_egress_gw_policy_v6
```

**Subnet Map**: [bpf/lib/subnet.h:35-41](bpf/lib/subnet.h#L35-L41)
```c
cilium_subnet_map  // Subnet-based identity lookups
```

**Policy Map**: [bpf/lib/policy.h:159-166](bpf/lib/policy.h#L159-L166)
```c
cilium_policy_v2  // Policy enforcement
```

---

## Encapsulation Implementation

### 1. Tunnel Structures
**Location**: [bpf/lib/tunnel.h:53-79](bpf/lib/tunnel.h#L53-L79)

```c
struct vxlanhdr {
    __be32 vx_flags;  // VXLAN flags
    __be32 vx_vni;    // Virtual Network Identifier
};

struct genevehdr {
    __u8 opt_len:6, ver:2;
    __u8 rsvd:6, critical:1, control:1;
    __be16 protocol_type;
    __u8 vni[3];      // Virtual Network Identifier
    __u8 reserved;
};
```

### 2. Encapsulation Functions
**Location**: [bpf/lib/encap.h](bpf/lib/encap.h)

All encapsulation code is conditional on `#ifdef TUNNEL_MODE`:

```c
#ifdef TUNNEL_MODE

static __always_inline int
__encap_with_nodeid4(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
                     __u32 seclabel, __u32 dstid, __u32 vni,
                     enum trace_reason reason, __u32 monitor,
                     __s8 *ext_err)
{
    // Sets up tunnel headers (VXLAN or Geneve)
    // Redirects packet to tunnel device
}

static __always_inline int
encap_and_redirect_lxc(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
                       __u32 seclabel, __u32 dstid, __u32 vni,
                       const struct trace_ctx *trace, __u32 monitor,
                       __s8 *ext_err)
{
    // Helper to encapsulate and redirect from LXC
}

#endif /* TUNNEL_MODE */
```

### 3. Routing Decision Logic

The decision to tunnel or route natively happens in multiple places:

**In bpf_lxc.c** (container egress):
```c
#ifdef TUNNEL_MODE
    if (!skip_tunnel) {
        return encap_and_redirect_lxc(ctx, tunnel_endpoint, ...);
    }
#endif
    // Otherwise, use native routing
```

**In bpf_host.c** (host network):
```c
#ifdef TUNNEL_MODE
    struct remote_endpoint_info *info = ipcache_lookup(dst_ip);
    if (info && info->flag_has_tunnel_ep && !info->flag_skip_tunnel) {
        return __encap_with_nodeid(ctx, info->tunnel_endpoint, ...);
    }
#endif
```

---

## IP Cache System

### Purpose

The IP cache (ipcache) is a critical component that maps:
- **IP addresses** (pod IPs, node IPs) →
- **Security identities** (for policy enforcement) +
- **Tunnel endpoints** (for encapsulation) +
- **Routing metadata** (flags for routing decisions)

### Lookup Functions

**IPv4 Lookup**: [bpf/lib/eps.h:168-185](bpf/lib/eps.h#L168-L185)

```c
static __always_inline const struct remote_endpoint_info *
ipcache_lookup4(const void *map, __be32 addr, __u32 prefix, __u32 cluster_id)
{
    struct ipcache_key key = {
        .lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
        .family = ENDPOINT_KEY_IPV4,
        .ip4 = addr,
        .cluster_id = (__u16)cluster_id,
    };

    key.ip4 &= GET_PREFIX(prefix);  // Normalize for LPM
    return map_lookup_elem(map, &key);
}
```

**IPv6 Lookup**: Similar pattern with 128-bit addresses

### Control Plane Management

**Location**: [pkg/ipcache/](pkg/ipcache/)

The ipcache is managed by the control plane:
1. **Node discovery**: When nodes are discovered, their IPs are added to ipcache with tunnel endpoints
2. **Endpoint creation**: When pods are created, their IPs are added to ipcache
3. **Policy updates**: Security identities are associated with IP prefixes
4. **Cluster mesh**: Remote cluster endpoints are marked with `flag_remote_cluster`

---

## Dynamic Configuration Updates

### IP Masquerade Agent Example

The IP masquerade agent demonstrates the pattern for dynamic CIDR configuration, which is directly applicable to the hybrid routing CFP.

#### 1. Configuration File Watching
**Location**: [pkg/ipmasq/ipmasq.go:118-175](pkg/ipmasq/ipmasq.go#L118-L175)

```go
func (a *IPMasqAgent) Start() error {
    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return fmt.Errorf("failed to create fsnotify watcher: %w", err)
    }

    configDir := filepath.Dir(a.configPath)
    if err := a.watcher.Add(configDir); err != nil {
        return fmt.Errorf("failed to add %q dir to fsnotify watcher: %w", configDir, err)
    }

    go func() {
        for {
            select {
            case event := <-a.watcher.Events:
                switch {
                case event.Has(fsnotify.Create),
                     event.Has(fsnotify.Write),
                     event.Has(fsnotify.Chmod),
                     event.Has(fsnotify.Remove),
                     event.Has(fsnotify.Rename):
                    if err := a.Update(); err != nil {
                        a.logger.Warn("Failed to update", logfields.Error, err)
                    }
                }
            case <-a.stop:
                return
            }
        }
    }()

    return nil
}
```

#### 2. Map Reconciliation
**Location**: [pkg/ipmasq/ipmasq.go:184-227](pkg/ipmasq/ipmasq.go#L184-L227)

```go
func (a *IPMasqAgent) update() error {
    // Read config from file
    isEmpty, err := a.readConfig()
    if err != nil {
        return err
    }

    // Set defaults if empty
    if isEmpty {
        maps.Copy(a.nonMasqCIDRsFromConfig, defaultNonMasqCIDRs)
    }

    // Add new CIDRs (config → map)
    for cidrStr, cidr := range a.nonMasqCIDRsFromConfig {
        if _, ok := a.nonMasqCIDRsInMap[cidrStr]; !ok {
            a.logger.Info("Adding CIDR", logfields.CIDR, cidrStr)
            a.ipMasqMap.Update(cidr)
            a.nonMasqCIDRsInMap[cidrStr] = cidr
        }
    }

    // Remove stale CIDRs (map → config)
    for cidrStr, cidr := range a.nonMasqCIDRsInMap {
        if _, ok := a.nonMasqCIDRsFromConfig[cidrStr]; !ok {
            a.logger.Info("Removing CIDR", logfields.CIDR, cidrStr)
            a.ipMasqMap.Delete(cidr)
            delete(a.nonMasqCIDRsInMap, cidrStr)
        }
    }

    return nil
}
```

#### 3. eBPF Map Operations
**Location**: [pkg/maps/ipmasq/ipmasq.go:90-114](pkg/maps/ipmasq/ipmasq.go#L90-L114)

```go
func (m *IPMasqBPFMap) Update(cidr netip.Prefix) error {
    if cidr.Addr().Is4() {
        if option.Config.EnableIPv4Masquerade {
            return IPMasq4Map(m.MetricsRegistry).Update(keyIPv4(cidr), &Value{})
        }
    } else {
        if option.Config.EnableIPv6Masquerade {
            return IPMasq6Map(m.MetricsRegistry).Update(keyIPv6(cidr), &Value{})
        }
    }
    return nil
}

func keyIPv4(cidr netip.Prefix) *Key4 {
    ones := cidr.Bits()
    key := &Key4{PrefixLen: uint32(ones)}
    copy(key.Address[:], cidr.Masked().Addr().AsSlice())
    return key
}
```

#### 4. Datapath Lookup
**Location**: [bpf/lib/nat.h:720-730](bpf/lib/nat.h#L720-L730)

```c
#ifdef ENABLE_IP_MASQ_AGENT_IPV4
{
    struct lpm_v4_key pfx;

    pfx.lpm.prefixlen = 32;  // Full IP address
    memcpy(pfx.lpm.data, &tuple->daddr, sizeof(pfx.addr));

    if (map_lookup_elem(&cilium_ipmasq_v4, &pfx)) {
        // Destination is in exclusion CIDR, skip masquerading
        return NAT_PUNT_TO_STACK;
    }
}
#endif
```

### Cell-Based Lifecycle

**Location**: [pkg/ipmasq/cell/cell.go:33-56](pkg/ipmasq/cell/cell.go#L33-L56)

```go
func newIPMasqAgentCell(params ipMasqAgentParams) (*ipmasq.IPMasqAgent, error) {
    if !params.Config.EnableIPMasqAgent {
        return nil, nil
    }

    agent := ipmasq.NewIPMasqAgent(params.Logger, params.Config.IPMasqAgentConfigPath, params.IPMasqMap)

    params.Lifecycle.Append(cell.Hook{
        OnStart: func(cell.HookContext) error {
            params.Logger.Info("Starting ip-masq-agent")
            return agent.Start()
        },
        OnStop: func(cell.HookContext) error {
            params.Logger.Info("Stopping ip-masq-agent")
            agent.Stop()
            return nil
        },
    })

    return agent, nil
}
```

---

## Key Takeaways for Hybrid Routing Implementation

### 1. Existing Infrastructure to Leverage

- **LPM Trie Maps**: Well-established pattern for CIDR lookups (IP masq, egress GW, subnets)
- **Dynamic Config**: File watcher + reconciliation pattern proven in IP masq agent
- **Routing Flags**: `flag_skip_tunnel` already exists in `remote_endpoint_info`
- **Cell System**: Modern Hive-based lifecycle management

### 2. Integration Points

- **Config Option**: Add `RoutingModeHybrid` constant alongside existing modes
- **LocalNodeConfiguration**: Add hybrid routing settings
- **Header Generation**: Add `HYBRID_ROUTING_MODE` define
- **eBPF Maps**: Create `cilium_subnet_topology_v4` and `cilium_subnet_topology_v6` LPM tries
- **Datapath Logic**: Modify encapsulation decision to check subnet IDs

### 3. Design Principles Observed

- **Immutability**: LocalNodeConfiguration is immutable once created
- **Separation of Concerns**: Control plane handles config, datapath handles forwarding
- **Performance**: LPM lookups are O(log n) with prefix length
- **Observability**: Extensive logging and metrics throughout
- **Backward Compatibility**: Feature flags and graceful degradation

### 4. Testing Considerations

- **Unit tests**: Map operations, CIDR parsing, subnet ID assignment
- **Integration tests**: Dynamic config updates, map reconciliation
- **Datapath tests**: eBPF program logic with various subnet topologies
- **E2E tests**: Multi-subnet clusters, cluster mesh scenarios

---

## References

### Key Files by Component

| Component | Files |
|-----------|-------|
| **Config** | [pkg/option/config.go](pkg/option/config.go) |
| **Tunnel** | [pkg/datapath/tunnel/tunnel.go](pkg/datapath/tunnel/tunnel.go), [pkg/datapath/tunnel/cell.go](pkg/datapath/tunnel/cell.go) |
| **LocalNodeConfig** | [pkg/datapath/types/node.go](pkg/datapath/types/node.go), [pkg/datapath/orchestrator/localnodeconfig.go](pkg/datapath/orchestrator/localnodeconfig.go) |
| **Header Generation** | [pkg/datapath/linux/config/config.go](pkg/datapath/linux/config/config.go) |
| **Runtime Config** | [pkg/datapath/config/node_config.go](pkg/datapath/config/node_config.go) (and siblings) |
| **IP Cache** | [pkg/ipcache/](pkg/ipcache/), [bpf/lib/eps.h](bpf/lib/eps.h) |
| **IP Masq Agent** | [pkg/ipmasq/ipmasq.go](pkg/ipmasq/ipmasq.go), [pkg/ipmasq/cell/cell.go](pkg/ipmasq/cell/cell.go) |
| **IP Masq Maps** | [pkg/maps/ipmasq/ipmasq.go](pkg/maps/ipmasq/ipmasq.go), [bpf/lib/nat.h](bpf/lib/nat.h) |
| **Encapsulation** | [bpf/lib/encap.h](bpf/lib/encap.h), [bpf/lib/tunnel.h](bpf/lib/tunnel.h) |
| **Datapath Programs** | [bpf/bpf_host.c](bpf/bpf_host.c), [bpf/bpf_lxc.c](bpf/bpf_lxc.c), [bpf/bpf_overlay.c](bpf/bpf_overlay.c) |

### Constants

| Constant | Value | Location |
|----------|-------|----------|
| `RoutingModeNative` | "native" | [pkg/option/config.go:1016](pkg/option/config.go#L1016) |
| `RoutingModeTunnel` | "tunnel" | [pkg/option/config.go:1018](pkg/option/config.go#L1018) |
| `TunnelProtocol` | "vxlan" | [pkg/defaults/defaults.go:458](pkg/defaults/defaults.go#L458) |
| `TunnelPortVXLAN` | 8472 | [pkg/defaults/defaults.go:488](pkg/defaults/defaults.go#L488) |
| `TunnelPortGeneve` | 6081 | [pkg/defaults/defaults.go:490](pkg/defaults/defaults.go#L490) |
| `IPCACHE_MAP_SIZE` | 512000 | [bpf/lib/common.h](bpf/lib/common.h) |
| `MaxEntriesIPv4` (ipmasq) | 16384 | [pkg/maps/ipmasq/ipmasq.go](pkg/maps/ipmasq/ipmasq.go) |

---

**Document Version**: 1.0
**Last Updated**: January 2025
**Related**: CFP-32810 Hybrid Routing Mode
