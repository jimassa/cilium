# CFP-32810: Hybrid Routing Mode - Project Overview

This directory contains the analysis, architecture documentation, and implementation design for CFP-32810: Add Hybrid Routing Mode in Cilium.

## Quick Links

- **CFP Document**: [CFP-32810 on GitHub](https://github.com/cilium/design-cfps/blob/main/cilium/CFP-32810-hybrid-routing-mode.md)
- **Architecture Analysis**: [architecture.md](architecture.md)
- **Implementation Design**: [implementation-design.md](implementation-design.md)
- **Architecture Diagrams**: [architecture-diagrams.md](architecture-diagrams.md)

## Branch

```bash
git branch
# * hybrid-routing-mode-cfp-32810
```

## What is Hybrid Routing Mode?

Hybrid routing mode is a new routing mode for Cilium that makes intelligent routing decisions at runtime:

- **Same subnet**: Route natively (no encapsulation) → Better performance
- **Different subnets**: Use encapsulation (VXLAN/Geneve) → Cross-subnet connectivity

This combines the best of both worlds:
- **Tunnel mode**: Works everywhere but has overhead
- **Native mode**: High performance but requires L3 connectivity
- **Hybrid mode**: Performance where possible, encapsulation where needed

## Documents Overview

### 1. [architecture.md](architecture.md)

**Comprehensive analysis of current Cilium routing architecture**, including:

- How existing routing modes (tunnel/native) work
- Control plane architecture (DaemonConfig → LocalNodeConfiguration → eBPF)
- Datapath architecture (eBPF programs, maps, encapsulation)
- Configuration system and validation
- IP cache system for endpoint information
- Dynamic configuration updates (IP masq agent as reference)
- LPM trie map usage patterns throughout the codebase

**Key Findings**:
- Cilium already has extensive LPM trie infrastructure (IP masq, egress GW, subnets, policy)
- IP masq agent provides the perfect pattern for dynamic CIDR configuration
- `flag_skip_tunnel` in `remote_endpoint_info` is used for auto-direct routing
- Hive cell system provides clean lifecycle management

### 2. [implementation-design.md](implementation-design.md)

**Complete implementation design** for hybrid routing mode, including:

#### Architecture
- High-level flow diagrams
- Component diagrams
- Control plane → data plane flow

#### Detailed Design
1. **Configuration Layer**
   - New `RoutingModeHybrid` constant
   - `SubnetTopologyConfigMap` option
   - ConfigMap format specification
   - LocalNodeConfiguration updates

2. **eBPF Maps Layer**
   - `cilium_subnet_topology_v4` and `v6` LPM trie maps
   - Subnet ID lookup functions
   - Go map interface for control plane

3. **Subnet Topology Agent**
   - ConfigMap parsing
   - Subnet ID assignment (1, 2, 3, ...)
   - Map reconciliation (add/remove CIDRs)
   - fsnotify-based file watching

4. **Datapath Integration**
   - Header file generation (`HYBRID_ROUTING_MODE` define)
   - eBPF program changes in `bpf_lxc.c` and `bpf_host.c`
   - Routing decision logic

5. **Cell Integration**
   - Hive cells for agent and maps
   - Lifecycle hooks (OnStart/OnStop)

#### Implementation Plan

**12-week phased approach**:
- Phase 1 (Weeks 1-2): Foundation (config, maps)
- Phase 2 (Weeks 3-4): Subnet topology agent
- Phase 3 (Weeks 5-6): Datapath integration
- Phase 4 (Weeks 7-8): End-to-end testing
- Phase 5 (Weeks 9-10): Documentation and polish
- Phase 6 (Weeks 11-12): Production readiness

#### Testing Strategy
- Unit tests (config parsing, map ops, reconciliation)
- Integration tests (agent lifecycle, dynamic updates)
- Datapath tests (eBPF program logic)
- E2E tests (cluster mesh, large clusters, upgrades)
- Performance tests (throughput, latency, scale)

#### Performance Considerations
- Same-subnet traffic: 5-15% throughput improvement
- Cross-subnet traffic: <1% overhead (LPM lookup)
- Map lookup: O(log n), <100ns for typical configs

#### Migration and Rollback
- Safe migration from tunnel mode
- Easy rollback if needed
- Backward compatible (hybrid without config = tunnel mode)

## Code Structure (Proposed)

```
cilium/
├── pkg/
│   ├── option/
│   │   └── config.go                      # Add RoutingModeHybrid, config options
│   ├── datapath/
│   │   ├── types/node.go                  # Update LocalNodeConfiguration
│   │   ├── orchestrator/localnodeconfig.go # Wire hybrid routing config
│   │   └── linux/config/config.go         # Emit HYBRID_ROUTING_MODE define
│   ├── maps/
│   │   └── subnetopology/                 # NEW: eBPF map interface
│   │       ├── subnetopology.go           # Map operations (Update/Delete/Dump)
│   │       └── cell.go                    # Map lifecycle
│   └── subnetopology/                     # NEW: Subnet topology agent
│       ├── agent.go                       # Config parsing, reconciliation
│       └── cell/
│           └── cell.go                    # Agent lifecycle
├── bpf/
│   └── lib/
│       └── subnet_topology.h              # NEW: LPM maps, lookup functions
└── daemon/cmd/
    └── cells.go                           # Wire new cells
```

## Example Configuration

```yaml
# DaemonSet config
--routing-mode=hybrid
--subnet-topology-configmap=/etc/cilium/subnet-topology-config.yaml

# ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: cilium-subnet-topology
  namespace: kube-system
data:
  # Two connected subnets (same subnet ID = 1)
  # Third subnet isolated (subnet ID = 2)
  subnet-topology-ipv4: "10.0.0.0/24,10.10.0.0/24;10.20.0.0/24"
```

**Routing behavior**:
- 10.0.0.x ↔ 10.10.0.x: Native routing (same subnet group)
- 10.0.0.x ↔ 10.20.0.x: Encapsulation (different subnet groups)
- 10.10.0.x ↔ 10.20.0.x: Encapsulation (different subnet groups)

## Key Design Decisions

1. **ConfigMap-based configuration** (Phase 1)
   - Simple, follows IP masq agent pattern
   - CRD-based config deferred to future release

2. **Replace-all reconciliation**
   - Simpler implementation
   - Subnet IDs recalculated on each update
   - Brief (<1s) disruption acceptable for Phase 1

3. **Reject overlapping CIDRs**
   - Clearer semantics
   - Forces explicit configuration

4. **Default to encapsulation**
   - Safe default when subnet not configured
   - Backward compatible with tunnel mode

5. **Leverage existing infrastructure**
   - LPM trie maps (proven pattern)
   - fsnotify file watching (IP masq agent)
   - Hive cell lifecycle management
   - `flag_skip_tunnel` mechanism

## Next Steps

### To Start Implementation

1. **Review documents**
   - Read [architecture.md](architecture.md) to understand current system
   - Read [CFP-32810-IMPLEMENTATION-DESIGN.md](CFP-32810-IMPLEMENTATION-DESIGN.md) for implementation plan

2. **Set up development environment**
   - Build Cilium from source
   - Run unit tests to verify setup
   - Familiarize yourself with eBPF development workflow

3. **Start with Phase 1**
   - Add routing mode constant and config options
   - Create eBPF map definitions
   - Write unit tests for config parsing

4. **Iterate through phases**
   - Follow the 12-week plan
   - Test thoroughly at each phase
   - Document as you go

### To Provide Feedback

- Comment on the design documents
- Open issues on specific technical questions
- Suggest improvements to the implementation plan

## Resources

### Cilium Documentation
- [Cilium Routing](https://docs.cilium.io/en/stable/network/concepts/routing/)
- [Cilium Cluster Mesh](https://docs.cilium.io/en/stable/network/clustermesh/)
- [eBPF Development Guide](https://docs.cilium.io/en/stable/contributing/development/dev_guide/)

### Reference Implementations
- IP Masquerading Agent: [pkg/ipmasq/ipmasq.go](pkg/ipmasq/ipmasq.go)
- LPM Trie Maps: [pkg/maps/ipmasq/ipmasq.go](pkg/maps/ipmasq/ipmasq.go)
- Encapsulation: [bpf/lib/encap.h](bpf/lib/encap.h)

### Linux Kernel
- [BPF LPM Trie Documentation](https://docs.kernel.org/bpf/map_lpm_trie.html)

## Questions?

For questions about:
- **CFP**: Comment on the [GitHub CFP](https://github.com/cilium/design-cfps/blob/main/cilium/CFP-32810-hybrid-routing-mode.md)
- **Architecture**: Review [architecture.md](architecture.md)
- **Implementation**: Review [CFP-32810-IMPLEMENTATION-DESIGN.md](CFP-32810-IMPLEMENTATION-DESIGN.md)
- **Cilium Development**: Check [Cilium Slack](https://cilium.io/slack) #development channel

---

**Created**: January 2025
**Branch**: `hybrid-routing-mode-cfp-32810`
**Status**: Design Phase
