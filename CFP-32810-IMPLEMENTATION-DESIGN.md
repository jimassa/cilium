# CFP-32810: Hybrid Routing Mode - Implementation Design

## Document Metadata

- **CFP**: CFP-32810 - Add Hybrid Routing Mode in Cilium
- **Target Release**: Cilium 1.19
- **Implementation Owner**: TBD
- **Design Document Version**: 1.0
- **Last Updated**: January 2025

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Goals and Non-Goals](#goals-and-non-goals)
3. [Architecture Overview](#architecture-overview)
4. [Detailed Design](#detailed-design)
5. [Implementation Plan](#implementation-plan)
6. [Testing Strategy](#testing-strategy)
7. [Performance Considerations](#performance-considerations)
8. [Migration and Rollback](#migration-and-rollback)
9. [Open Questions](#open-questions)
10. [References](#references)

---

## Executive Summary

This document describes the implementation plan for CFP-32810, which introduces a third routing mode called "hybrid" to Cilium. The hybrid mode enables runtime decisions on whether to route packets natively or encapsulate them based on network topology awareness.

### Current State

Cilium supports two routing modes:
- **Tunnel mode**: All traffic is encapsulated (VXLAN/Geneve)
- **Native mode**: All traffic is routed directly without encapsulation

### Problem

In multi-subnet environments (e.g., peered VNETs, large clusters), users need encapsulation for cross-subnet traffic but are forced to encapsulate same-subnet traffic as well, causing unnecessary overhead.

### Proposed Solution

Add a "hybrid" routing mode that:
1. Routes natively when source and destination belong to the same subnet group
2. Encapsulates when they belong to different subnet groups
3. Uses LPM trie eBPF maps for efficient CIDR-based lookups
4. Supports dynamic configuration via ConfigMap

---

## Goals and Non-Goals

### Goals

1. **Add hybrid routing mode** without changing existing tunnel/native behavior
2. **Support IPv4 and IPv6** CIDR configurations
3. **Enable dynamic updates** to subnet topology without agent restart
4. **Maintain performance** with minimal datapath overhead
5. **Support multiple subnet groups** with complex topologies
6. **Preserve security** and policy enforcement guarantees

### Non-Goals

1. **Automatic topology discovery** - Users must explicitly configure subnet topology
2. **CRD-based configuration** - Phase 1 uses ConfigMap (CRD is future work per CFP)
3. **Support for overlapping CIDRs** - Subnet groups must be non-overlapping
4. **Changing encapsulation protocols** - Still uses existing VXLAN/Geneve
5. **Performance optimization of existing modes** - Focus only on hybrid mode

---

## Architecture Overview

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Control Plane                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ConfigMap (subnet-topology)                                         │
│  ┌───────────────────────────────────────────────────┐              │
│  │ subnet-topology:                                   │              │
│  │   "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24"         │              │
│  └────────────────────┬──────────────────────────────┘              │
│                       │                                              │
│                       ▼                                              │
│  SubnetTopologyAgent                                                 │
│  ┌───────────────────────────────────────────────────┐              │
│  │ • Watches ConfigMap for changes                   │              │
│  │ • Parses CIDR groups                              │              │
│  │ • Assigns subnet IDs (1, 2, 3, ...)              │              │
│  │ • Reconciles eBPF maps                            │              │
│  └────────────────────┬──────────────────────────────┘              │
│                       │                                              │
│                       ▼                                              │
│  eBPF Map Updates                                                    │
│  ┌───────────────────────────────────────────────────┐              │
│  │ cilium_subnet_topology_v4                         │              │
│  │ ┌──────────────────────┬──────────┐              │              │
│  │ │ CIDR                 │ SubnetID │              │              │
│  │ ├──────────────────────┼──────────┤              │              │
│  │ │ 10.0.0.0/24         │    1     │              │              │
│  │ │ 10.10.0.0/24        │    1     │              │              │
│  │ │ 10.20.0.0/24        │    2     │              │              │
│  │ └──────────────────────┴──────────┘              │              │
│  └───────────────────────────────────────────────────┘              │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                          Data Plane                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Packet Processing (bpf_lxc.c, bpf_host.c)                          │
│  ┌───────────────────────────────────────────────────┐              │
│  │ 1. Extract src_ip and dst_ip                      │              │
│  │                                                    │              │
│  │ 2. src_subnet_id = lookup_subnet_id(src_ip)       │              │
│  │    dst_subnet_id = lookup_subnet_id(dst_ip)       │              │
│  │                                                    │              │
│  │ 3. if (src_subnet_id == dst_subnet_id &&          │              │
│  │        src_subnet_id != 0) {                      │              │
│  │       // Same subnet - native routing             │              │
│  │       skip_tunnel = true                          │              │
│  │    } else {                                        │              │
│  │       // Different subnets - encapsulate          │              │
│  │       skip_tunnel = false                         │              │
│  │    }                                               │              │
│  │                                                    │              │
│  │ 4. if (skip_tunnel)                                │              │
│  │       return redirect_to_stack();                 │              │
│  │    else                                            │              │
│  │       return encap_and_redirect();                │              │
│  └───────────────────────────────────────────────────┘              │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        User Configuration                         │
│  --routing-mode=hybrid                                           │
│  --subnet-topology-configmap=/path/to/configmap.yaml             │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                         DaemonConfig                             │
│  RoutingMode = "hybrid"                                          │
│  SubnetTopologyConfigPath = "/path/to/configmap.yaml"            │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                   LocalNodeConfiguration                         │
│  EnableEncapsulation = true                                      │
│  EnableHybridRouting = true                                      │
│  SubnetTopologyEnabled = true                                    │
└────────────────────────────┬─────────────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                     HeaderfileWriter                             │
│  #define TUNNEL_MODE 1                                           │
│  #define HYBRID_ROUTING_MODE 1                                   │
│  #define ENABLE_SUBNET_TOPOLOGY_IPV4 1                           │
│  #define ENABLE_SUBNET_TOPOLOGY_IPV6 1                           │
└──────────────────────────────────────────────────────────────────┘
```

---

## Detailed Design

### 1. Configuration Layer

#### 1.1 CLI Options

Add new routing mode constant and configuration options:

**File**: `pkg/option/config.go`

```go
// Add to existing routing mode constants (around line 1014)
const (
    RoutingModeNative = "native"
    RoutingModeTunnel = "tunnel"
    RoutingModeHybrid = "hybrid"  // NEW
)

// Add to DaemonConfig struct (around line 1184)
type DaemonConfig struct {
    // ... existing fields ...
    RoutingMode             string
    SubnetTopologyConfigMap string  // NEW: Path to subnet topology ConfigMap
    // ... existing fields ...
}

// Add CLI flag registration (around line 2637)
flags.String(SubnetTopologyConfigMap, defaults.SubnetTopologyConfigMap,
    "Path to ConfigMap containing subnet topology configuration for hybrid routing mode")

// Update TunnelingEnabled() (around line 2011)
func (c *DaemonConfig) TunnelingEnabled() bool {
    // Hybrid mode requires tunnel infrastructure
    return c.RoutingMode != RoutingModeNative
}

// Add new helper
func (c *DaemonConfig) HybridRoutingEnabled() bool {
    return c.RoutingMode == RoutingModeHybrid
}

// Update validation (around line 2284)
switch c.RoutingMode {
case RoutingModeNative, RoutingModeTunnel, RoutingModeHybrid:
    // Valid
default:
    return fmt.Errorf("invalid routing mode %q, valid modes = {%q, %q, %q}",
        c.RoutingMode, RoutingModeTunnel, RoutingModeNative, RoutingModeHybrid)
}

// Add validation for hybrid mode
func (c *DaemonConfig) checkHybridRoutingConfig() error {
    if c.HybridRoutingEnabled() {
        if c.SubnetTopologyConfigMap == "" {
            return fmt.Errorf("subnet-topology-configmap must be specified when using hybrid routing mode")
        }
        if !c.TunnelingEnabled() {
            return fmt.Errorf("hybrid routing mode requires tunnel infrastructure")
        }
    }
    return nil
}
```

**File**: `pkg/defaults/defaults.go`

```go
const (
    // ... existing defaults ...
    SubnetTopologyConfigMap = "/etc/cilium/subnet-topology-config.yaml"
)
```

#### 1.2 ConfigMap Format

**Example ConfigMap YAML**:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
  namespace: kube-system
data:
  subnet-topology-ipv4: "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24;192.168.0.0/16"
  subnet-topology-ipv6: "2001:db8:1::/64,2001:db8:2::/64;2001:db8:3::/64"
```

**Format Specification**:
- Semicolon (`;`) separates subnet groups
- Comma (`,`) separates CIDRs within the same group
- Each group gets a unique subnet ID (1, 2, 3, ...)
- Empty/missing configuration means all traffic uses encapsulation (same as tunnel mode)

#### 1.3 LocalNodeConfiguration

**File**: `pkg/datapath/types/node.go`

```go
type LocalNodeConfiguration struct {
    // ... existing fields ...

    // EnableHybridRouting enables hybrid routing mode where routing
    // decisions are made based on subnet topology
    EnableHybridRouting bool

    // SubnetTopologyIPv4Enabled indicates if IPv4 subnet topology is configured
    SubnetTopologyIPv4Enabled bool

    // SubnetTopologyIPv6Enabled indicates if IPv6 subnet topology is configured
    SubnetTopologyIPv6Enabled bool

    // ... existing fields ...
}
```

**File**: `pkg/datapath/orchestrator/localnodeconfig.go`

```go
func newLocalNodeConfig(...) (datapath.LocalNodeConfiguration, ...) {
    // ... existing code ...

    lnc := LocalNodeConfiguration{
        // ... existing fields ...
        EnableEncapsulation:       config.TunnelingEnabled(),
        EnableHybridRouting:       config.HybridRoutingEnabled(),
        SubnetTopologyIPv4Enabled: config.HybridRoutingEnabled() && config.EnableIPv4,
        SubnetTopologyIPv6Enabled: config.HybridRoutingEnabled() && config.EnableIPv6,
        // ... existing fields ...
    }

    return lnc, readyChan, nil
}
```

---

### 2. eBPF Maps Layer

#### 2.1 Map Definitions

**File**: `bpf/lib/subnet_topology.h` (NEW FILE)

```c
#ifndef __LIB_SUBNET_TOPOLOGY_H_
#define __LIB_SUBNET_TOPOLOGY_H_

#include "common.h"

/* Subnet topology maps for hybrid routing mode.
 * These LPM trie maps store CIDR -> Subnet ID mappings.
 * Packets are routed natively when source and destination
 * have the same subnet ID, otherwise they are encapsulated.
 */

#ifdef ENABLE_SUBNET_TOPOLOGY_IPV4
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);  // Subnet ID (1, 2, 3, ...)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, SUBNET_TOPOLOGY_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_subnet_topology_v4 __section_maps_btf;
#endif /* ENABLE_SUBNET_TOPOLOGY_IPV4 */

#ifdef ENABLE_SUBNET_TOPOLOGY_IPV6
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);  // Subnet ID (1, 2, 3, ...)
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(max_entries, SUBNET_TOPOLOGY_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_subnet_topology_v6 __section_maps_btf;
#endif /* ENABLE_SUBNET_TOPOLOGY_IPV6 */

#ifndef SUBNET_TOPOLOGY_MAP_SIZE
#define SUBNET_TOPOLOGY_MAP_SIZE 1024
#endif

/* lookup_subnet_id returns the subnet ID for the given IP address.
 * Returns 0 if the IP is not found in any configured subnet.
 */
static __always_inline __u32
lookup_subnet_id_v4(__be32 addr)
{
#ifdef ENABLE_SUBNET_TOPOLOGY_IPV4
    struct lpm_v4_key key;
    __u32 *subnet_id;

    key.lpm.prefixlen = 32;  // Full address lookup
    memcpy(key.addr, &addr, sizeof(key.addr));

    subnet_id = map_lookup_elem(&cilium_subnet_topology_v4, &key);
    if (subnet_id)
        return *subnet_id;
#endif
    return 0;  // Not found or feature disabled
}

static __always_inline __u32
lookup_subnet_id_v6(const union v6addr *addr)
{
#ifdef ENABLE_SUBNET_TOPOLOGY_IPV6
    struct lpm_v6_key key __align_stack_8;
    __u32 *subnet_id;

    key.lpm.prefixlen = 128;  // Full address lookup
    memcpy(key.addr, addr, sizeof(key.addr));

    subnet_id = map_lookup_elem(&cilium_subnet_topology_v6, &key);
    if (subnet_id)
        return *subnet_id;
#endif
    return 0;  // Not found or feature disabled
}

/* should_skip_tunnel_for_subnet returns true if src and dst
 * belong to the same subnet and therefore should not be tunneled.
 */
static __always_inline bool
should_skip_tunnel_for_subnet_v4(__be32 src_ip, __be32 dst_ip)
{
#ifdef HYBRID_ROUTING_MODE
    __u32 src_subnet_id = lookup_subnet_id_v4(src_ip);
    __u32 dst_subnet_id = lookup_subnet_id_v4(dst_ip);

    // If both IPs are in configured subnets and have the same ID,
    // they can communicate natively
    if (src_subnet_id != 0 && src_subnet_id == dst_subnet_id)
        return true;
#endif
    return false;
}

static __always_inline bool
should_skip_tunnel_for_subnet_v6(const union v6addr *src_ip,
                                   const union v6addr *dst_ip)
{
#ifdef HYBRID_ROUTING_MODE
    __u32 src_subnet_id = lookup_subnet_id_v6(src_ip);
    __u32 dst_subnet_id = lookup_subnet_id_v6(dst_ip);

    if (src_subnet_id != 0 && src_subnet_id == dst_subnet_id)
        return true;
#endif
    return false;
}

#endif /* __LIB_SUBNET_TOPOLOGY_H_ */
```

#### 2.2 Go Map Interface

**File**: `pkg/maps/subnetopology/subnetopology.go` (NEW FILE)

```go
package subnetopology

import (
    "fmt"
    "net/netip"

    "github.com/cilium/ebpf"
    "golang.org/x/sys/unix"

    "github.com/cilium/cilium/pkg/bpf"
    "github.com/cilium/cilium/pkg/option"
    "github.com/cilium/cilium/pkg/types"
)

const (
    MapNameIPv4      = "cilium_subnet_topology_v4"
    MapNameIPv6      = "cilium_subnet_topology_v6"
    MaxEntriesIPv4   = 1024
    MaxEntriesIPv6   = 1024
)

// Key4 is the IPv4 LPM trie key for subnet topology
type Key4 struct {
    PrefixLen uint32
    Address   types.IPv4
}

// Key6 is the IPv6 LPM trie key for subnet topology
type Key6 struct {
    PrefixLen uint32
    Address   types.IPv6
}

// Value is the subnet ID (1, 2, 3, ...)
type Value struct {
    SubnetID uint32
}

func (k *Key4) String() string {
    return fmt.Sprintf("%s/%d", k.Address.String(), k.PrefixLen)
}

func (k *Key6) String() string {
    return fmt.Sprintf("%s/%d", k.Address.String(), k.PrefixLen)
}

func (v *Value) String() string {
    return fmt.Sprintf("SubnetID=%d", v.SubnetID)
}

var (
    subnetTopology4Map *bpf.Map
    subnetTopology6Map *bpf.Map
)

// SubnetTopology4Map returns the IPv4 subnet topology map
func SubnetTopology4Map() *bpf.Map {
    if subnetTopology4Map == nil {
        subnetTopology4Map = bpf.NewMap(
            MapNameIPv4,
            ebpf.LPMTrie,
            &Key4{},
            &Value{},
            MaxEntriesIPv4,
            unix.BPF_F_NO_PREALLOC,
        ).WithCache()
    }
    return subnetTopology4Map
}

// SubnetTopology6Map returns the IPv6 subnet topology map
func SubnetTopology6Map() *bpf.Map {
    if subnetTopology6Map == nil {
        subnetTopology6Map = bpf.NewMap(
            MapNameIPv6,
            ebpf.LPMTrie,
            &Key6{},
            &Value{},
            MaxEntriesIPv6,
            unix.BPF_F_NO_PREALLOC,
        ).WithCache()
    }
    return subnetTopology6Map
}

// UpdateIPv4 adds or updates a CIDR in the IPv4 subnet topology map
func UpdateIPv4(cidr netip.Prefix, subnetID uint32) error {
    if !option.Config.HybridRoutingEnabled() || !option.Config.EnableIPv4 {
        return nil
    }

    key := keyIPv4(cidr)
    value := &Value{SubnetID: subnetID}
    return SubnetTopology4Map().Update(key, value)
}

// UpdateIPv6 adds or updates a CIDR in the IPv6 subnet topology map
func UpdateIPv6(cidr netip.Prefix, subnetID uint32) error {
    if !option.Config.HybridRoutingEnabled() || !option.Config.EnableIPv6 {
        return nil
    }

    key := keyIPv6(cidr)
    value := &Value{SubnetID: subnetID}
    return SubnetTopology6Map().Update(key, value)
}

// DeleteIPv4 removes a CIDR from the IPv4 subnet topology map
func DeleteIPv4(cidr netip.Prefix) error {
    if !option.Config.HybridRoutingEnabled() || !option.Config.EnableIPv4 {
        return nil
    }

    key := keyIPv4(cidr)
    return SubnetTopology4Map().Delete(key)
}

// DeleteIPv6 removes a CIDR from the IPv6 subnet topology map
func DeleteIPv6(cidr netip.Prefix) error {
    if !option.Config.HybridRoutingEnabled() || !option.Config.EnableIPv6 {
        return nil
    }

    key := keyIPv6(cidr)
    return SubnetTopology6Map().Delete(key)
}

func keyIPv4(cidr netip.Prefix) *Key4 {
    ones := cidr.Bits()
    key := &Key4{PrefixLen: uint32(ones)}
    copy(key.Address[:], cidr.Masked().Addr().AsSlice())
    return key
}

func keyIPv6(cidr netip.Prefix) *Key6 {
    ones := cidr.Bits()
    key := &Key6{PrefixLen: uint32(ones)}
    copy(key.Address[:], cidr.Masked().Addr().AsSlice())
    return key
}

// DumpIPv4 returns all CIDRs in the IPv4 subnet topology map
func DumpIPv4() (map[string]netip.Prefix, error) {
    cidrs := make(map[string]netip.Prefix)

    callback := func(key bpf.MapKey, value bpf.MapValue) {
        k := key.(*Key4)
        cidr := netip.PrefixFrom(k.Address.Addr(), int(k.PrefixLen))
        cidrs[cidr.String()] = cidr
    }

    if err := SubnetTopology4Map().DumpWithCallback(callback); err != nil {
        return nil, err
    }

    return cidrs, nil
}

// DumpIPv6 returns all CIDRs in the IPv6 subnet topology map
func DumpIPv6() (map[string]netip.Prefix, error) {
    cidrs := make(map[string]netip.Prefix)

    callback := func(key bpf.MapKey, value bpf.MapValue) {
        k := key.(*Key6)
        cidr := netip.PrefixFrom(k.Address.Addr(), int(k.PrefixLen))
        cidrs[cidr.String()] = cidr
    }

    if err := SubnetTopology6Map().DumpWithCallback(callback); err != nil {
        return nil, err
    }

    return cidrs, nil
}
```

---

### 3. Subnet Topology Agent

**File**: `pkg/subnetopology/agent.go` (NEW FILE)

```go
package subnetopology

import (
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/netip"
    "os"
    "path/filepath"
    "strings"
    "sync"

    "github.com/fsnotify/fsnotify"
    "gopkg.in/yaml.v3"

    "github.com/cilium/cilium/pkg/lock"
    "github.com/cilium/cilium/pkg/logging/logfields"
    "github.com/cilium/cilium/pkg/maps/subnetopology"
)

// Config represents the subnet topology configuration
type Config struct {
    SubnetTopologyIPv4 string `json:"subnet-topology-ipv4,omitempty" yaml:"subnet-topology-ipv4,omitempty"`
    SubnetTopologyIPv6 string `json:"subnet-topology-ipv6,omitempty" yaml:"subnet-topology-ipv6,omitempty"`
}

// SubnetGroup represents a group of CIDRs that are directly connected
type SubnetGroup struct {
    ID     uint32          // Subnet ID (1, 2, 3, ...)
    CIDRs  []netip.Prefix  // CIDRs in this group
}

// Agent manages subnet topology configuration
type Agent struct {
    logger     *slog.Logger
    configPath string
    watcher    *fsnotify.Watcher
    lock       lock.Mutex

    // Current state
    ipv4Groups []SubnetGroup
    ipv6Groups []SubnetGroup

    // Tracking what's in the maps
    ipv4CIDRsInMap map[string]netip.Prefix
    ipv6CIDRsInMap map[string]netip.Prefix

    // Lifecycle
    stop            chan struct{}
    handlerFinished chan struct{}
}

// NewAgent creates a new subnet topology agent
func NewAgent(logger *slog.Logger, configPath string) *Agent {
    return &Agent{
        logger:         logger,
        configPath:     configPath,
        ipv4CIDRsInMap: make(map[string]netip.Prefix),
        ipv6CIDRsInMap: make(map[string]netip.Prefix),
    }
}

// Start starts the subnet topology agent
func (a *Agent) Start() error {
    a.lock.Lock()
    defer a.lock.Unlock()

    watcher, err := fsnotify.NewWatcher()
    if err != nil {
        return fmt.Errorf("failed to create fsnotify watcher: %w", err)
    }
    a.watcher = watcher

    configDir := filepath.Dir(a.configPath)
    if err := a.watcher.Add(configDir); err != nil {
        a.watcher.Close()
        return fmt.Errorf("failed to add %q dir to fsnotify watcher: %w", configDir, err)
    }

    // Initial load
    if err := a.restore(); err != nil {
        a.logger.Warn("Failed to restore subnet topology from maps", logfields.Error, err)
    }
    if err := a.update(); err != nil {
        a.logger.Warn("Failed to update subnet topology", logfields.Error, err)
    }

    a.stop = make(chan struct{})
    a.handlerFinished = make(chan struct{})

    go a.watchLoop()

    return nil
}

// Stop stops the subnet topology agent
func (a *Agent) Stop() {
    a.lock.Lock()
    defer a.lock.Unlock()

    if a.stop != nil {
        close(a.stop)
        <-a.handlerFinished
    }

    if a.watcher != nil {
        a.watcher.Close()
    }
}

func (a *Agent) watchLoop() {
    for {
        select {
        case event := <-a.watcher.Events:
            a.logger.Debug("Received fsnotify event", logfields.Event, event)

            switch {
            case event.Has(fsnotify.Create),
                event.Has(fsnotify.Write),
                event.Has(fsnotify.Chmod),
                event.Has(fsnotify.Remove),
                event.Has(fsnotify.Rename):
                if err := a.Update(); err != nil {
                    a.logger.Warn("Failed to update subnet topology", logfields.Error, err)
                }
            default:
                a.logger.Warn("Watcher received unknown event", logfields.Event, event)
            }
        case err := <-a.watcher.Errors:
            a.logger.Warn("Watcher received an error", logfields.Error, err)
        case <-a.stop:
            a.logger.Info("Stopping subnet-topology-agent")
            close(a.handlerFinished)
            return
        }
    }
}

// Update updates the subnet topology from the config file
func (a *Agent) Update() error {
    a.lock.Lock()
    defer a.lock.Unlock()
    return a.update()
}

func (a *Agent) update() error {
    // Read config
    if err := a.readConfig(); err != nil {
        return err
    }

    // Reconcile IPv4
    if err := a.reconcileIPv4(); err != nil {
        return fmt.Errorf("failed to reconcile IPv4 subnet topology: %w", err)
    }

    // Reconcile IPv6
    if err := a.reconcileIPv6(); err != nil {
        return fmt.Errorf("failed to reconcile IPv6 subnet topology: %w", err)
    }

    return nil
}

func (a *Agent) readConfig() error {
    raw, err := os.ReadFile(a.configPath)
    if err != nil {
        if os.IsNotExist(err) {
            a.logger.Info("Config file not found, clearing subnet topology", logfields.Path, a.configPath)
            a.ipv4Groups = nil
            a.ipv6Groups = nil
            return nil
        }
        return fmt.Errorf("failed to read %s: %w", a.configPath, err)
    }

    // Parse YAML/JSON
    var cfg Config
    jsonStr, err := yaml.ToJSON(raw)
    if err != nil {
        return fmt.Errorf("failed to convert to json: %w", err)
    }

    if err := json.Unmarshal(jsonStr, &cfg); err != nil {
        return fmt.Errorf("failed to unmarshal json: %w", err)
    }

    // Parse IPv4 subnet groups
    a.ipv4Groups, err = parseSubnetGroups(cfg.SubnetTopologyIPv4, false)
    if err != nil {
        return fmt.Errorf("failed to parse IPv4 subnet topology: %w", err)
    }

    // Parse IPv6 subnet groups
    a.ipv6Groups, err = parseSubnetGroups(cfg.SubnetTopologyIPv6, true)
    if err != nil {
        return fmt.Errorf("failed to parse IPv6 subnet topology: %w", err)
    }

    return nil
}

// parseSubnetGroups parses the subnet topology string
// Format: "cidr1,cidr2;cidr3;cidr4,cidr5"
// Semicolons separate groups, commas separate CIDRs within a group
func parseSubnetGroups(topology string, isIPv6 bool) ([]SubnetGroup, error) {
    if topology == "" {
        return nil, nil
    }

    groups := []SubnetGroup{}
    subnetID := uint32(1)

    // Split by semicolon to get groups
    for _, groupStr := range strings.Split(topology, ";") {
        groupStr = strings.TrimSpace(groupStr)
        if groupStr == "" {
            continue
        }

        group := SubnetGroup{
            ID:    subnetID,
            CIDRs: []netip.Prefix{},
        }

        // Split by comma to get CIDRs
        for _, cidrStr := range strings.Split(groupStr, ",") {
            cidrStr = strings.TrimSpace(cidrStr)
            if cidrStr == "" {
                continue
            }

            cidr, err := netip.ParsePrefix(cidrStr)
            if err != nil {
                return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
            }

            // Validate IP version
            if isIPv6 && cidr.Addr().Is4() {
                return nil, fmt.Errorf("IPv4 CIDR %q in IPv6 topology", cidrStr)
            }
            if !isIPv6 && cidr.Addr().Is6() {
                return nil, fmt.Errorf("IPv6 CIDR %q in IPv4 topology", cidrStr)
            }

            group.CIDRs = append(group.CIDRs, cidr)
        }

        if len(group.CIDRs) > 0 {
            groups = append(groups, group)
            subnetID++
        }
    }

    return groups, nil
}

func (a *Agent) reconcileIPv4() error {
    // Build desired state
    desiredCIDRs := make(map[string]struct {
        cidr     netip.Prefix
        subnetID uint32
    })

    for _, group := range a.ipv4Groups {
        for _, cidr := range group.CIDRs {
            desiredCIDRs[cidr.String()] = struct {
                cidr     netip.Prefix
                subnetID uint32
            }{cidr: cidr, subnetID: group.ID}
        }
    }

    // Add new CIDRs
    for cidrStr, desired := range desiredCIDRs {
        if _, ok := a.ipv4CIDRsInMap[cidrStr]; !ok {
            a.logger.Info("Adding IPv4 CIDR to subnet topology",
                logfields.CIDR, cidrStr,
                "subnet_id", desired.subnetID)
            if err := subnetopology.UpdateIPv4(desired.cidr, desired.subnetID); err != nil {
                return fmt.Errorf("failed to update IPv4 map for %s: %w", cidrStr, err)
            }
            a.ipv4CIDRsInMap[cidrStr] = desired.cidr
        }
    }

    // Remove stale CIDRs
    for cidrStr, cidr := range a.ipv4CIDRsInMap {
        if _, ok := desiredCIDRs[cidrStr]; !ok {
            a.logger.Info("Removing IPv4 CIDR from subnet topology", logfields.CIDR, cidrStr)
            if err := subnetopology.DeleteIPv4(cidr); err != nil {
                return fmt.Errorf("failed to delete IPv4 map entry for %s: %w", cidrStr, err)
            }
            delete(a.ipv4CIDRsInMap, cidrStr)
        }
    }

    return nil
}

func (a *Agent) reconcileIPv6() error {
    // Build desired state
    desiredCIDRs := make(map[string]struct {
        cidr     netip.Prefix
        subnetID uint32
    })

    for _, group := range a.ipv6Groups {
        for _, cidr := range group.CIDRs {
            desiredCIDRs[cidr.String()] = struct {
                cidr     netip.Prefix
                subnetID uint32
            }{cidr: cidr, subnetID: group.ID}
        }
    }

    // Add new CIDRs
    for cidrStr, desired := range desiredCIDRs {
        if _, ok := a.ipv6CIDRsInMap[cidrStr]; !ok {
            a.logger.Info("Adding IPv6 CIDR to subnet topology",
                logfields.CIDR, cidrStr,
                "subnet_id", desired.subnetID)
            if err := subnetopology.UpdateIPv6(desired.cidr, desired.subnetID); err != nil {
                return fmt.Errorf("failed to update IPv6 map for %s: %w", cidrStr, err)
            }
            a.ipv6CIDRsInMap[cidrStr] = desired.cidr
        }
    }

    // Remove stale CIDRs
    for cidrStr, cidr := range a.ipv6CIDRsInMap {
        if _, ok := desiredCIDRs[cidrStr]; !ok {
            a.logger.Info("Removing IPv6 CIDR from subnet topology", logfields.CIDR, cidrStr)
            if err := subnetopology.DeleteIPv6(cidr); err != nil {
                return fmt.Errorf("failed to delete IPv6 map entry for %s: %w", cidrStr, err)
            }
            delete(a.ipv6CIDRsInMap, cidrStr)
        }
    }

    return nil
}

func (a *Agent) restore() error {
    // Restore IPv4 state from map
    ipv4CIDRs, err := subnetopology.DumpIPv4()
    if err != nil {
        return fmt.Errorf("failed to dump IPv4 subnet topology map: %w", err)
    }
    a.ipv4CIDRsInMap = ipv4CIDRs

    // Restore IPv6 state from map
    ipv6CIDRs, err := subnetopology.DumpIPv6()
    if err != nil {
        return fmt.Errorf("failed to dump IPv6 subnet topology map: %w", err)
    }
    a.ipv6CIDRsInMap = ipv6CIDRs

    a.logger.Info("Restored subnet topology state",
        "ipv4_cidrs", len(a.ipv4CIDRsInMap),
        "ipv6_cidrs", len(a.ipv6CIDRsInMap))

    return nil
}
```

---

### 4. Datapath Integration

#### 4.1 Header File Changes

**File**: `pkg/datapath/linux/config/config.go`

```go
func (h *HeaderfileWriter) WriteNodeConfig(cfg datapath.LocalNodeConfiguration) error {
    cDefinesMap := make(map[string]string)

    // ... existing code ...

    // Tunnel mode
    if option.Config.TunnelingEnabled() {
        cDefinesMap["TUNNEL_MODE"] = "1"
    }

    // NEW: Hybrid routing mode
    if option.Config.HybridRoutingEnabled() {
        cDefinesMap["HYBRID_ROUTING_MODE"] = "1"

        if cfg.SubnetTopologyIPv4Enabled {
            cDefinesMap["ENABLE_SUBNET_TOPOLOGY_IPV4"] = "1"
        }

        if cfg.SubnetTopologyIPv6Enabled {
            cDefinesMap["ENABLE_SUBNET_TOPOLOGY_IPV6"] = "1"
        }
    }

    // ... rest of existing code ...
}
```

#### 4.2 eBPF Program Changes

**File**: `bpf/bpf_lxc.c`

```c
#include "lib/subnet_topology.h"

// In the container egress path (around line 1271)
#ifdef TUNNEL_MODE
    struct remote_endpoint_info *info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
    if (info && info->flag_has_tunnel_ep) {
        bool skip_tunnel = false;

        // Check existing skip_tunnel flag (auto-direct routing)
        if (info->flag_skip_tunnel) {
            skip_tunnel = true;
        }

#ifdef HYBRID_ROUTING_MODE
        // NEW: Check subnet topology for hybrid routing
        if (!skip_tunnel && should_skip_tunnel_for_subnet_v4(ip4->saddr, ip4->daddr)) {
            skip_tunnel = true;
        }
#endif /* HYBRID_ROUTING_MODE */

        if (!skip_tunnel) {
            return encap_and_redirect_lxc(ctx, info->tunnel_endpoint, ...);
        }
    }
#endif /* TUNNEL_MODE */

    // Native routing path
    return CTX_ACT_OK;
```

**File**: `bpf/bpf_host.c`

```c
#include "lib/subnet_topology.h"

// In the host routing path (around line 833)
#ifdef TUNNEL_MODE
    struct remote_endpoint_info *info = ipcache_lookup4(&IPCACHE_MAP, ip4->daddr, V4_CACHE_KEY_LEN, 0);
    if (info && info->flag_has_tunnel_ep) {
        bool skip_tunnel = info->flag_skip_tunnel;

#ifdef HYBRID_ROUTING_MODE
        // NEW: Check subnet topology for hybrid routing
        if (!skip_tunnel && should_skip_tunnel_for_subnet_v4(ip4->saddr, ip4->daddr)) {
            skip_tunnel = true;
        }
#endif /* HYBRID_ROUTING_MODE */

        if (!skip_tunnel) {
            return __encap_with_nodeid4(ctx, info->tunnel_endpoint, ...);
        }
    }
#endif /* TUNNEL_MODE */

    // Continue with native routing
```

**Similar changes for IPv6 in both files**

---

### 5. Cell Integration

**File**: `pkg/subnetopology/cell/cell.go` (NEW FILE)

```go
package cell

import (
    "github.com/cilium/cilium/pkg/hive/cell"
    "github.com/cilium/cilium/pkg/option"
    "github.com/cilium/cilium/pkg/subnetopology"
)

var Cell = cell.Module(
    "subnet-topology",
    "Subnet Topology Agent for Hybrid Routing Mode",

    cell.Provide(newSubnetTopologyAgent),
)

type subnetTopologyAgentParams struct {
    cell.In

    Lifecycle cell.Lifecycle
    Logger    *slog.Logger
    Config    *option.DaemonConfig
}

func newSubnetTopologyAgent(params subnetTopologyAgentParams) (*subnetopology.Agent, error) {
    if !params.Config.HybridRoutingEnabled() {
        return nil, nil
    }

    agent := subnetopology.NewAgent(params.Logger, params.Config.SubnetTopologyConfigMap)

    params.Lifecycle.Append(cell.Hook{
        OnStart: func(ctx cell.HookContext) error {
            params.Logger.Info("Starting subnet-topology-agent")
            return agent.Start()
        },
        OnStop: func(ctx cell.HookContext) error {
            params.Logger.Info("Stopping subnet-topology-agent")
            agent.Stop()
            return nil
        },
    })

    return agent, nil
}
```

**File**: `pkg/maps/subnetopology/cell.go` (NEW FILE)

```go
package subnetopology

import (
    "fmt"

    "github.com/cilium/cilium/pkg/hive/cell"
    "github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
    "subnet-topology-maps",
    "Subnet Topology eBPF Maps",

    cell.Invoke(initSubnetTopologyMaps),
)

type subnetTopologyMapsParams struct {
    cell.In

    Lifecycle cell.Lifecycle
    Config    *option.DaemonConfig
}

func initSubnetTopologyMaps(params subnetTopologyMapsParams) error {
    if !params.Config.HybridRoutingEnabled() {
        return nil
    }

    params.Lifecycle.Append(cell.Hook{
        OnStart: func(ctx cell.HookContext) error {
            if params.Config.EnableIPv4 {
                if err := SubnetTopology4Map().OpenOrCreate(); err != nil {
                    return fmt.Errorf("failed to open/create IPv4 subnet topology map: %w", err)
                }
            }

            if params.Config.EnableIPv6 {
                if err := SubnetTopology6Map().OpenOrCreate(); err != nil {
                    return fmt.Errorf("failed to open/create IPv6 subnet topology map: %w", err)
                }
            }

            return nil
        },
        OnStop: func(ctx cell.HookContext) error {
            // Maps are pinned, no cleanup needed
            return nil
        },
    })

    return nil
}
```

**Update**: `daemon/cmd/cells.go` to include new cells

```go
var (
    Agent = cell.Module(
        // ... existing cells ...
        subnetopologycell.Cell,
        subnetopologymaps.Cell,
        // ... existing cells ...
    )
)
```

---

## Implementation Plan

### Phase 1: Foundation (Week 1-2)

**Tasks**:
1. Add routing mode constant and configuration options
   - [ ] Update `pkg/option/config.go` with `RoutingModeHybrid`
   - [ ] Add `SubnetTopologyConfigMap` config field
   - [ ] Add validation for hybrid routing mode
   - [ ] Update `LocalNodeConfiguration` with hybrid routing fields

2. Create eBPF map infrastructure
   - [ ] Create `bpf/lib/subnet_topology.h` with map definitions
   - [ ] Create `pkg/maps/subnetopology/` package
   - [ ] Implement map operations (Update, Delete, Dump)

3. Testing
   - [ ] Unit tests for configuration parsing
   - [ ] Unit tests for map key/value encoding

### Phase 2: Subnet Topology Agent (Week 3-4)

**Tasks**:
1. Implement subnet topology agent
   - [ ] Create `pkg/subnetopology/agent.go`
   - [ ] Implement config file parsing
   - [ ] Implement subnet ID assignment
   - [ ] Implement map reconciliation logic
   - [ ] Add fsnotify-based file watching

2. Cell integration
   - [ ] Create `pkg/subnetopology/cell/cell.go`
   - [ ] Create `pkg/maps/subnetopology/cell.go`
   - [ ] Wire cells into daemon

3. Testing
   - [ ] Unit tests for CIDR parsing
   - [ ] Unit tests for subnet ID assignment
   - [ ] Unit tests for map reconciliation
   - [ ] Integration tests for file watching

### Phase 3: Datapath Integration (Week 5-6)

**Tasks**:
1. Update header generation
   - [ ] Modify `pkg/datapath/linux/config/config.go` to emit defines
   - [ ] Add `HYBRID_ROUTING_MODE`, `ENABLE_SUBNET_TOPOLOGY_IPV4/6`

2. Modify eBPF programs
   - [ ] Update `bpf/bpf_lxc.c` with subnet topology checks
   - [ ] Update `bpf/bpf_host.c` with subnet topology checks
   - [ ] Update `bpf/bpf_overlay.c` if needed
   - [ ] Handle IPv6 cases

3. Testing
   - [ ] Unit tests for eBPF lookup functions (using BPF test framework)
   - [ ] Datapath tests with mock subnet topology maps

### Phase 4: End-to-End Testing (Week 7-8)

**Tasks**:
1. Integration testing
   - [ ] Test single subnet group (all native routing)
   - [ ] Test multiple subnet groups (mixed routing)
   - [ ] Test dynamic config updates (add/remove CIDRs)
   - [ ] Test IPv4 and IPv6
   - [ ] Test cluster mesh scenarios

2. Performance testing
   - [ ] Benchmark LPM lookup overhead
   - [ ] Measure throughput improvement for same-subnet traffic
   - [ ] Test with large numbers of subnet groups

3. Chaos/failure testing
   - [ ] Agent restart during traffic
   - [ ] Config file corruption
   - [ ] Map update failures
   - [ ] Partial rollout scenarios

### Phase 5: Documentation and Polish (Week 9-10)

**Tasks**:
1. Documentation
   - [ ] User-facing documentation (setup guide, examples)
   - [ ] Operator guide (troubleshooting, monitoring)
   - [ ] Architecture documentation
   - [ ] API reference

2. Observability
   - [ ] Add metrics for subnet topology updates
   - [ ] Add metrics for routing decisions (native vs tunneled)
   - [ ] Add logging for config changes
   - [ ] Add Hubble integration if applicable

3. Polish
   - [ ] Code review and refactoring
   - [ ] Error message improvements
   - [ ] CLI help text
   - [ ] Example configurations

### Phase 6: Production Readiness (Week 11-12)

**Tasks**:
1. Stability
   - [ ] Fuzz testing for config parsing
   - [ ] Memory leak testing
   - [ ] Upgrade/downgrade testing
   - [ ] Large-scale testing (1000+ nodes)

2. Release preparation
   - [ ] Release notes
   - [ ] Migration guide
   - [ ] Blog post (optional)
   - [ ] Demo/tutorial

---

## Testing Strategy

### Unit Tests

1. **Configuration Parsing** (`pkg/subnetopology/agent_test.go`)
   - Valid configurations (single group, multiple groups, IPv4, IPv6, mixed)
   - Invalid configurations (malformed CIDRs, wrong IP version, overlapping)
   - Empty/missing configurations

2. **Subnet ID Assignment** (`pkg/subnetopology/agent_test.go`)
   - Sequential ID assignment (1, 2, 3, ...)
   - ID stability across config reloads
   - ID reuse after group deletion

3. **Map Operations** (`pkg/maps/subnetopology/subnetopology_test.go`)
   - Update/Delete operations
   - Key encoding (prefix length, address bytes)
   - Dump operations

4. **Map Reconciliation** (`pkg/subnetopology/agent_test.go`)
   - Add new CIDRs
   - Remove stale CIDRs
   - Update existing CIDRs with new subnet IDs
   - No-op when config unchanged

### Integration Tests

1. **Agent Lifecycle** (`test/integration/subnetopology/`)
   - Agent start with existing config
   - Agent start with missing config
   - Config file updates trigger reconciliation
   - Agent stop cleans up resources

2. **Dynamic Updates** (`test/integration/subnetopology/`)
   - Add subnet group
   - Remove subnet group
   - Modify subnet group (add/remove CIDRs)
   - Multiple rapid updates

3. **Multi-Subnet Scenarios** (`test/k8s/`)
   - Two subnets, directly connected
   - Three+ subnets, some connected, some isolated
   - IPv4-only, IPv6-only, dual-stack

### Datapath Tests

1. **eBPF Program Tests** (`bpf/tests/`)
   - `lookup_subnet_id_v4()` returns correct subnet ID
   - `lookup_subnet_id_v4()` returns 0 for unknown IP
   - `should_skip_tunnel_for_subnet_v4()` returns true for same subnet
   - `should_skip_tunnel_for_subnet_v4()` returns false for different subnets
   - IPv6 variants

2. **Routing Decision Tests** (`test/datapath/`)
   - Same subnet → native routing
   - Different subnets → encapsulation
   - Unknown subnet → encapsulation (default)
   - Interaction with `flag_skip_tunnel` (auto-direct routing)

### End-to-End Tests

1. **Cluster Mesh** (`test/k8s/clustermesh/`)
   - Two clusters, each with multiple subnets
   - Pods in same subnet across clusters (should route natively)
   - Pods in different subnets (should encapsulate)

2. **Large Clusters** (`test/k8s/scale/`)
   - 100+ nodes across multiple subnets
   - Traffic patterns (same-subnet, cross-subnet)
   - Dynamic pod creation/deletion

3. **Upgrade/Downgrade** (`test/k8s/upgrade/`)
   - Upgrade from tunnel mode to hybrid mode
   - Downgrade from hybrid mode to tunnel mode
   - Rolling upgrade with hybrid mode enabled

### Performance Tests

1. **Throughput** (`test/performance/`)
   - Baseline: tunnel mode throughput
   - Hybrid mode, same subnet: expect >tunnel mode
   - Hybrid mode, different subnets: expect ≈tunnel mode

2. **Latency** (`test/performance/`)
   - LPM lookup overhead (should be <1µs)
   - P50, P95, P99 latencies for routing decisions

3. **Scale** (`test/performance/`)
   - 100 subnet groups, 1000 CIDRs
   - Map lookup performance at scale

---

## Performance Considerations

### Expected Performance Characteristics

1. **Same-Subnet Traffic**
   - **Improvement**: 5-15% throughput increase (no encapsulation overhead)
   - **Latency**: Slightly lower due to no encap/decap
   - **CPU**: Reduced due to less processing

2. **Cross-Subnet Traffic**
   - **Overhead**: Minimal (<1% due to additional LPM lookup)
   - **Latency**: <1µs additional for subnet ID lookup
   - **Throughput**: Same as tunnel mode

3. **Map Lookup Performance**
   - **LPM Trie Complexity**: O(log n) where n = prefix length (max 32 for IPv4, 128 for IPv6)
   - **Expected Latency**: <100ns for typical configurations (<1000 CIDRs)

### Optimization Strategies

1. **Map Size**
   - Default: 1024 entries (configurable)
   - Should accommodate 100+ subnet groups with headroom

2. **Lookup Optimization**
   - LPM tries are inherently fast (used in Linux kernel routing)
   - No need for additional caching (kernel already optimizes)

3. **Control Plane Optimization**
   - Reconciliation is replace-all (simple, predictable)
   - File watching limits unnecessary updates

### Monitoring

**Metrics to Add**:
- `cilium_subnet_topology_updates_total{ip_version}` - Total config updates
- `cilium_subnet_topology_cidrs{ip_version}` - Current number of CIDRs
- `cilium_subnet_topology_groups{ip_version}` - Current number of subnet groups
- `cilium_datapath_routing_decisions_total{mode}` - native vs tunneled

**Logging**:
- Config file changes (INFO level)
- CIDR additions/removals (INFO level)
- Map reconciliation errors (ERROR level)
- Subnet ID assignments (DEBUG level)

---

## Migration and Rollback

### Migration from Tunnel Mode

**Step 1**: Enable hybrid mode
```yaml
# DaemonSet config
--routing-mode=hybrid
--subnet-topology-configmap=/etc/cilium/subnet-topology-config.yaml
```

**Step 2**: Create ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
  namespace: kube-system
data:
  subnet-topology-ipv4: "10.0.0.0/24,10.10.0.0/24"
```

**Step 3**: Mount ConfigMap in DaemonSet
```yaml
volumes:
  - name: subnet-topology-config
    configMap:
      name: cilium-subnet-topology
volumeMounts:
  - name: subnet-topology-config
    mountPath: /etc/cilium/subnet-topology-config.yaml
    subPath: subnet-topology-config.yaml
```

**Step 4**: Rolling restart
- Cilium agents will pick up new config
- Traffic continues to flow (may use encapsulation until config loaded)

### Rollback to Tunnel Mode

**Step 1**: Update DaemonSet
```yaml
--routing-mode=tunnel
# Remove --subnet-topology-configmap
```

**Step 2**: Rolling restart
- Agents fall back to tunnel mode
- eBPF maps are not used (compiled out)

### Safety Considerations

1. **Backward Compatibility**
   - Hybrid mode without config = tunnel mode (safe default)
   - Feature is opt-in (no impact on existing deployments)

2. **Traffic Disruption**
   - Config changes may cause brief (<1s) routing instability
   - Existing connections remain stable (conntrack)

3. **Validation**
   - Invalid config is rejected (agent continues with previous state)
   - Malformed CIDRs log errors but don't crash agent

---

## Open Questions

### Implementation Questions

1. **Atomic Map Updates**
   - **Question**: Should we support atomic updates to minimize traffic disruption?
   - **Options**:
     - Replace-all (simpler, brief disruption)
     - Incremental updates (complex, no disruption)
   - **Decision**: Start with replace-all, optimize later if needed

2. **Subnet ID Stability**
   - **Question**: Should subnet IDs be stable across config changes?
   - **Options**:
     - Re-assign IDs each time (simpler, may cause brief disruption)
     - Stable IDs based on CIDR hash (complex, better for dynamic updates)
   - **Decision**: Re-assign (CFP suggests this approach)

3. **Overlapping CIDRs**
   - **Question**: How to handle overlapping CIDRs in different groups?
   - **Options**:
     - Reject config (simpler, forces user to fix)
     - LPM chooses longest match (complex, may be confusing)
   - **Decision**: Reject overlapping CIDRs in validation

4. **ConfigMap vs CRD**
   - **Question**: When to migrate to CRD-based config?
   - **Decision**: Phase 1 uses ConfigMap (per CFP), CRD in future release

### Operational Questions

1. **Default Behavior**
   - **Question**: What happens when subnet topology is not configured?
   - **Decision**: Fall back to tunnel mode (all traffic encapsulated)

2. **Error Handling**
   - **Question**: How to handle config parse errors?
   - **Decision**: Log error, continue with previous valid config

3. **Connection Persistence**
   - **Question**: How to ensure existing connections survive config changes?
   - **Options**:
     - Rely on conntrack (existing connections unaffected)
     - Add grace period for connection draining
   - **Decision**: Rely on conntrack (existing Cilium behavior)

4. **Observability**
   - **Question**: How can users verify hybrid routing is working?
   - **Options**:
     - CLI tool to show routing decisions
     - Metrics for native vs tunneled packets
     - Hubble integration
   - **Decision**: All of the above (implement incrementally)

---

## References

### Related CFPs and Issues

- [CFP-32810: Add Hybrid Routing Mode](https://github.com/cilium/design-cfps/blob/main/cilium/CFP-32810-hybrid-routing-mode.md)
- Cluster Mesh documentation
- IP masquerading agent (similar pattern)

### Code References

- [pkg/option/config.go](pkg/option/config.go) - Configuration
- [pkg/ipmasq/ipmasq.go](pkg/ipmasq/ipmasq.go) - IP masq agent (reference implementation)
- [pkg/maps/ipmasq/ipmasq.go](pkg/maps/ipmasq/ipmasq.go) - LPM trie map example
- [bpf/lib/nat.h](bpf/lib/nat.h) - eBPF LPM lookup example
- [bpf/lib/encap.h](bpf/lib/encap.h) - Encapsulation functions
- [pkg/datapath/types/node.go](pkg/datapath/types/node.go) - LocalNodeConfiguration

### External References

- [BPF_MAP_TYPE_LPM_TRIE documentation](https://docs.kernel.org/bpf/map_lpm_trie.html)
- [Cilium Architecture Guide](https://docs.cilium.io/en/stable/concepts/overview/)
- [Cilium Cluster Mesh](https://docs.cilium.io/en/stable/network/clustermesh/)

---

## Appendix A: Example Configurations

### Single Subnet

All nodes in same subnet - all traffic uses native routing:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
data:
  subnet-topology-ipv4: "10.0.0.0/16"
```

### Two Connected Subnets

Two subnets with direct L2/L3 connectivity:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
data:
  subnet-topology-ipv4: "10.0.0.0/24,10.10.0.0/24"
```

### Multiple Isolated Subnets

Three subnet groups, no direct connectivity between groups:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
data:
  subnet-topology-ipv4: "10.0.0.0/24,10.0.1.0/24;10.10.0.0/24;192.168.1.0/24"
```

**Routing behavior**:
- Pods in 10.0.0.0/24 ↔ 10.0.1.0/24: Native routing
- Pods in 10.0.0.0/24 ↔ 10.10.0.0/24: Encapsulation
- Pods in 10.0.0.0/24 ↔ 192.168.1.0/24: Encapsulation

### Dual-Stack

IPv4 and IPv6 subnet topology:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
data:
  subnet-topology-ipv4: "10.0.0.0/24,10.10.0.0/24"
  subnet-topology-ipv6: "2001:db8:1::/64,2001:db8:2::/64"
```

### Cluster Mesh

Two clusters with peered VNETs:

**Cluster 1**:
```yaml
subnet-topology-ipv4: "10.0.0.0/16,10.1.0.0/16"  # Cluster 1 and 2 peered
```

**Cluster 2**:
```yaml
subnet-topology-ipv4: "10.1.0.0/16,10.0.0.0/16"  # Same peering, reverse order
```

---

**End of Document**
