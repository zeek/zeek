# Tunnel Analyzer Hierarchy Refactoring

## Motivation

Zeek's GRE analyzer cannot forward into MPLS because tunnel bookkeeping
(encapsulation stack, `tunnel.log`) lives in a separate `IPTunnelAnalyzer`
that sits in the forwarding chain. Any protocol inserted between GRE and
IPTunnel bypasses that bookkeeping. See [#5829](https://github.com/zeek/zeek/issues/5829).

More broadly, the existing tunnel analyzers share significant boilerplate
(depth checks, encapsulation stack construction, inner-packet building) but
have no common base class. The shared logic is copy-pasted or funneled
through a single free function (`build_inner_packet`).

This design introduces a class hierarchy that:
1. Fixes the MPLS-in-GRE bug by moving tunnel tracking into GRE itself
2. Eliminates duplicated boilerplate across all tunnel analyzers
3. Establishes a clear taxonomy of tunnel types
4. Uses helper methods (not Template Method) so each analyzer's
   `AnalyzePacket` remains a linear, self-contained read

## Current State

### Two patterns exist today

**IP-layer tunnels** (GRE, IP-in-IP):
- Arrive from the IP analyzer (`packet->ip_hdr` is set, no session)
- GRE strips its header and forwards into `IPTunnelAnalyzer`
- `IPTunnelAnalyzer` tracks tunnels via an IP-pair map, manages
  inactivity timers, builds the `EncapsulationStack`, and generates
  `tunnel.log`
- GRE → IPTunnel → IP is the chain; inserting MPLS breaks it

**Session-based tunnels** (VXLAN, Geneve, AYIYA, Teredo, GTPv1):
- Arrive via an existing UDP/TCP connection (`packet->session` is set)
- Each manages its own encapsulation using `build_inner_packet()`
- They never touch `IPTunnelAnalyzer`'s IP-pair map
- The connection itself serves as the tunnel identity

### Files involved

| Analyzer | Source | Header |
|----------|--------|--------|
| IPTunnel | `src/packet_analysis/protocol/iptunnel/IPTunnel.cc` | `IPTunnel.h` |
| GRE | `src/packet_analysis/protocol/gre/GRE.cc` | `GRE.h` |
| VXLAN | `src/packet_analysis/protocol/vxlan/VXLAN.cc` | `VXLAN.h` |
| Geneve | `src/packet_analysis/protocol/geneve/Geneve.cc` | `Geneve.h` |
| AYIYA | `src/packet_analysis/protocol/ayiya/AYIYA.cc` | `AYIYA.h` |
| Teredo | `src/packet_analysis/protocol/teredo/Teredo.cc` | `Teredo.h` |
| GTPv1 | `src/packet_analysis/protocol/gtpv1/GTPv1.cc` | `GTPv1.h` |
| MPLS | `src/packet_analysis/protocol/mpls/MPLS.cc` | `MPLS.h` |

### Script-layer registrations

- `scripts/base/packet-protocols/ip/main.zeek`: registers
  `IPPROTO_GRE → ANALYZER_GRE` and `IPPROTO_IPIP/IPV6 → ANALYZER_IPTUNNEL`
- `scripts/base/packet-protocols/gre/main.zeek`: sets
  `default_analyzer = ANALYZER_IPTUNNEL` (GRE's fallback forwarding target)
- `scripts/base/packet-protocols/mpls/main.zeek`: sets
  `default_analyzer = ANALYZER_IP` (MPLS forwards into IP)
- No registration exists for GRE → MPLS (ethertype 0x8847)

## Proposed Design

### Class hierarchy

```
packet_analysis::Analyzer
  └── TunnelAnalyzer (abstract)
        │
        ├── SessionTunnelAnalyzer
        │     ├── VXLAN_Analyzer
        │     ├── GeneveAnalyzer
        │     ├── AYIYAAnalyzer
        │     ├── TeredoAnalyzer
        │     └── GTPv1_Analyzer
        │
        └── IPLayerTunnelAnalyzer
              ├── GREAnalyzer
              └── IPInIPAnalyzer (replaces IPTunnelAnalyzer)
```

### TunnelAnalyzer (base)

Location: `src/packet_analysis/TunnelAnalyzer.h`, `TunnelAnalyzer.cc`

Provides:
- `CheckTunnelDepth(Packet*)` — returns false and emits weird if
  `packet->encap->Depth() >= Tunnel::max_depth`. Every tunnel analyzer
  currently duplicates this check.

Does NOT provide:
- `AnalyzePacket` — subclasses own their own top-to-bottom flow.
- Any forwarding logic — that varies too much between the two branches.

```cpp
namespace zeek::packet_analysis {

class TunnelAnalyzer : public Analyzer {
public:
    using Analyzer::Analyzer;

protected:
    bool CheckTunnelDepth(Packet* packet);
};

} // namespace zeek::packet_analysis
```

### SessionTunnelAnalyzer

Location: `src/packet_analysis/SessionTunnelAnalyzer.h`,
`SessionTunnelAnalyzer.cc`

Provides helpers for tunnel analyzers that operate over an existing
connection:

```cpp
namespace zeek::packet_analysis {

class SessionTunnelAnalyzer : public TunnelAnalyzer {
public:
    using TunnelAnalyzer::TunnelAnalyzer;

protected:
    // Validates packet->session is present and analyzer is not violated.
    // Returns false (and emits weird) on failure.
    bool ValidateSession(Packet* packet);

    // Builds the inner packet with encapsulation stack derived from
    // the connection. Returns the inner packet and the encap_index
    // (position in the stack for post-forward event access).
    struct InnerPacketResult {
        std::unique_ptr<Packet> packet;
        int encap_index = 0;
    };

    InnerPacketResult BuildInnerPacket(Packet* outer, size_t len,
                                       const uint8_t* data, int link_type,
                                       BifEnum::Tunnel::Type tunnel_type);
};

} // namespace zeek::packet_analysis
```

Usage example (VXLAN):

```cpp
bool VXLAN_Analyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! ValidateSession(packet) )
        return false;
    if ( ! CheckTunnelDepth(packet) )
        return false;

    // Parse VXLAN header...
    // ...extract vni, advance data/len...

    AnalyzerConfirmation(packet->session);

    auto result = BuildInnerPacket(packet, len, data,
                                    DLT_RAW, BifEnum::Tunnel::VXLAN);
    bool ok = ForwardPacket(len, data, result.packet.get());

    if ( ok && vxlan_packet ) {
        EncapsulatingConn* ec = result.packet->encap->At(result.encap_index);
        if ( ec && ec->ip_hdr )
            packet->session->EnqueueEvent(vxlan_packet, nullptr,
                                           packet->session->GetVal(),
                                           ec->ip_hdr->ToPktHdrVal(),
                                           val_mgr->Count(vni));
    }

    return ok;
}
```

### IPLayerTunnelAnalyzer

Location: `src/packet_analysis/IPLayerTunnelAnalyzer.h`,
`IPLayerTunnelAnalyzer.cc`

Provides helpers for tunnel analyzers that operate at the IP layer
(no session, tunnel identity derived from outer IP addresses):

```cpp
namespace zeek::packet_analysis {

namespace detail {
class IPLayerTunnelTimer;
}

class IPLayerTunnelAnalyzer : public TunnelAnalyzer {
public:
    using TunnelAnalyzer::TunnelAnalyzer;

protected:
    struct InnerPacketResult {
        std::unique_ptr<Packet> packet;
    };

    // Registers tunnel activity for the outer IP pair and builds a
    // synthetic inner packet. Manages the IP-pair map, assigns stable
    // UIDs, creates inactivity timers, and attaches the EncapsulatingConn
    // to the inner packet's encap stack.
    // Returns a null packet if outer->ip_hdr is null.
    InnerPacketResult BuildInnerPacket(Packet* outer, size_t len,
                                       const uint8_t* data,
                                       BifEnum::Tunnel::Type tunnel_type);

private:
    friend class detail::IPLayerTunnelTimer;

    using IPPair = std::pair<IPAddr, IPAddr>;
    using TunnelActivity = std::pair<EncapsulatingConn, double>;
    using IPTunnelMap = std::map<IPPair, TunnelActivity>;
    IPTunnelMap ip_tunnels;
};

} // namespace zeek::packet_analysis
```

`BuildInnerPacket` encapsulates what `IPTunnelAnalyzer::AnalyzePacket`
currently does: look up the IP pair, create or update the tunnel entry,
create the timer, build a synthetic inner `Packet` with the
`EncapsulatingConn` attached. After `BuildInnerPacket` returns, the
caller forwards via the inner packet and the tunnel is tracked for
`tunnel.log`.

Usage (GRE, simplified):

```cpp
bool GREAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! packet->ip_hdr ) {
        reporter->InternalError("GREAnalyzer: ip_hdr not provided");
        return false;
    }
    if ( ! CheckTunnelDepth(packet) )
        return false;

    // Parse GRE header: flags, version, proto_typ, handle ERSPAN/bridging...
    // ...advance data/len, determine proto...

    // Build inner packet (registers tunnel, creates encap stack)
    auto inner = BuildInnerPacket(packet, len, data, BifEnum::Tunnel::GRE);
    if ( ! inner.packet )
        return false;

    // Forward to whatever protocol comes next (IP, MPLS, Ethernet, etc.)
    return ForwardPacket(len, data, inner.packet.get(), proto);
}
```

Now when GRE encounters ethertype 0x8847 (MPLS), it:
1. Strips the GRE header
2. Calls `BuildInnerPacket` (tunnel tracked, inner packet with encap)
3. Forwards inner packet to MPLS via normal dispatch
4. MPLS strips its label stack, forwards to IP
5. IP processes the inner packet — which has `packet->encap` set

Result: `tunnel.log` is generated, `conn.log` gets `tunnel_parents`.

### IPInIPAnalyzer (replaces IPTunnelAnalyzer)

The current `IPTunnelAnalyzer` has two roles:
1. Tunnel tracking for IP-in-IP (IPPROTO_IPIP, IPPROTO_IPV6)
2. A chain-step target that GRE forwards into

Role #2 is eliminated by this design. Role #1 becomes a trivial
`IPLayerTunnelAnalyzer` subclass:

```cpp
class IPInIPAnalyzer : public IPLayerTunnelAnalyzer {
public:
    IPInIPAnalyzer();
    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;
    static AnalyzerPtr Instantiate() { return std::make_shared<IPInIPAnalyzer>(); }
};

bool IPInIPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( ! packet->ip_hdr ) {
        reporter->InternalError("IPInIPAnalyzer: null ip_hdr");
        return false;
    }
    if ( ! CheckTunnelDepth(packet) )
        return false;

    // Pre-validate inner IP.
    std::shared_ptr<IP_Hdr> inner = nullptr;
    auto result = packet_analysis::IP::ParsePacket(len, data, packet->proto, inner);
    if ( result != packet_analysis::IP::ParseResult::OK )
        return false;

    // Build inner packet (registers tunnel, creates encap stack)
    auto inner_pkt = BuildInnerPacket(packet, len, data, BifEnum::Tunnel::IP);
    if ( ! inner_pkt.packet )
        return false;

    return ForwardPacket(len, data, inner_pkt.packet.get());
}
```

### Forwarding approach

All tunnel analyzers follow the same pattern:

1. `BuildInnerPacket` — creates a fresh `Packet` object with the
   encapsulation stack attached, registers the tunnel for `tunnel.log`
2. `ForwardPacket` on the inner packet — dispatches to the next
   analyzer via the normal protocol dispatch table

The inner `Packet` isolates inner processing from the outer context:
inner analyzers freely overwrite packet fields (ip_hdr, l3_proto, etc.)
without corrupting the outer packet. This matters because:
- Session-based tunnels: the outer packet belongs to an active
  connection whose metadata must be preserved.
- IP-layer tunnels inside a session (GRE-over-UDP): the outer
  session's byte counting depends on the outer ip_hdr.

**What's eliminated:** The old `ProcessEncapsulatedPacket` /
`packet_mgr->ProcessInnerPacket` path, which created a synthetic
packet and re-injected it through the packet manager for DLT-based
root-level re-dispatch. In the new design, forwarding stays in the
analyzer chain — `ForwardPacket` dispatches to the next registered
analyzer directly. Downstream analyzers (Ethernet, IEEE802_11) do not
depend on being called at root level; they parse from the `data`
pointer they receive.

**GRE dispatch table:**

```zeek
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x0800, PacketAnalyzer::ANALYZER_IP);
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x86DD, PacketAnalyzer::ANALYZER_IP);
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x8847, PacketAnalyzer::ANALYZER_MPLS);
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x6558, PacketAnalyzer::ANALYZER_ETHERNET);
PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE, 0x88be, PacketAnalyzer::ANALYZER_ERSPAN);
# ARUBA ethertypes → IEEE802_11
```

**ERSPAN:** A dedicated ERSPAN analyzer is introduced to handle ERSPAN
Type II and III. GRE differentiates the cases using its sequence bit:
- `0x88be` without sequence bit → ERSPAN Type I (no ERSPAN header) →
  GRE remaps to ethertype 0x6558, dispatching directly to Ethernet.
- `0x88be` with sequence bit → ERSPAN Type II → dispatches to ERSPAN.
- `0x22eb` → ERSPAN Type III → dispatches to ERSPAN.

The ERSPAN analyzer detects the type from the version nibble in its
own header (version 1 = Type II, 8 bytes; version 2 = Type III, 12+
bytes with an optional 8-byte sub-header), strips the header, and
forwards to Ethernet via the default analyzer.

ERSPAN is a plain `packet_analysis::Analyzer` (not a tunnel analyzer) —
the tunnel is GRE, ERSPAN is just an encapsulation layer between GRE
and the mirrored Ethernet frame. This removes ~50 lines of type-
specific header parsing from GRE's `AnalyzePacket`.

```
GRE → ERSPAN → Ethernet → IP → ...
```

### Script-layer changes

1. **Add GRE → MPLS registration** in
   `scripts/base/packet-protocols/gre/main.zeek`:
   ```zeek
   PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_GRE,
       0x8847, PacketAnalyzer::ANALYZER_MPLS);
   ```

2. **Remove GRE's default_analyzer** — GRE no longer has a fallback.
   All supported inner protocols are explicitly registered in GRE's
   dispatch table. Unknown ethertypes are reported via the base class's
   `report_unknown_protocols` mechanism, giving operators clear
   visibility into unhandled GRE traffic rather than silent
   misinterpretation.

3. **Remove ANALYZER_IPTUNNEL**, replace with `ANALYZER_IPINIP` (no
   alias — see backward compatibility section).

4. **Update IP → IPInIP registration** in
   `scripts/base/packet-protocols/ip/main.zeek`:
   ```zeek
   PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP,
       IPPROTO_IPIP, PacketAnalyzer::ANALYZER_IPINIP);
   PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP,
       IPPROTO_IPV6, PacketAnalyzer::ANALYZER_IPINIP);
   ```

5. **Move ARUBA registrations** from `iptunnel/main.zeek` to
   `gre/main.zeek` (they're GRE-specific).

### Backward compatibility

- The `build_inner_packet` free function is removed. Its logic is
  inlined into `SessionTunnelAnalyzer::BuildInnerPacket`. External
  plugins that called it directly need to migrate to the new base class.
- `ANALYZER_IPTUNNEL` is **removed without alias**. The old analyzer was
  a chain-step that performed tunnel tracking + forwarding — semantically
  different from the new `ANALYZER_IPINIP` which is self-contained.
  Keeping an alias would silently break scripts that register custom
  protocols to forward into it (the old GRE → IPTunnel pattern). A clean
  break gives users a clear error and guides them to the new approach.
- The `ip_tunnel_analyzer` global pointer is removed (it was marked
  "temporary" and only used internally).

### GTPv1 behavioral changes

GTPv1 currently does not check tunnel depth or `AnalyzerViolated`. This
appears to be an omission rather than intentional. After this refactoring,
GTPv1 gains these checks via the inherited helpers. This is a minor
behavioral change: deeply nested GTP tunnels will now be rejected, and
violated GTP analyzers will short-circuit. Both are correctness
improvements.

## Testing strategy

### Existing tests that must pass unchanged

All tests under `testing/btest/core/tunnels/` exercise the current
behavior. Key ones:
- `gre.test`, `gre-in-gre.test`, `gre-pptp.test`, `gre-aruba.test`
- `ip-in-ip.test`, `ip-tunnel-uid.test`
- `vxlan.zeek`, `geneve.zeek`, `teredo.zeek`
- `max-depth.zeek`, `max-depth-exceeded.zeek`
- ERSPAN tests: `erspanI.zeek`, `erspanII.zeek`, `erspanIII.zeek`

These validate that `conn.log`, `tunnel.log`, and weirds are generated
identically after the refactoring.

### New tests

1. **MPLS-in-GRE** (`gre-mpls.test`): the motivating bug. Packet with
   `IP | GRE | MPLS | IP | UDP`. Verify:
   - `conn.log` has the inner connection with `tunnel_parents` set
   - `tunnel.log` has the GRE tunnel entry
   - No `unknown_ip_version_in_tunnel` weird

2. **GRE → MPLS → IPv6** : same as above but inner is IPv6.

3. **GTPv1 max-depth**: verify that the newly-added depth check rejects
   deeply nested GTP. (This is a behavior change that needs an explicit
   baseline update or new test.)

## Migration plan

The refactoring can proceed incrementally:

1. **Introduce base classes** (`TunnelAnalyzer`, `SessionTunnelAnalyzer`,
   `IPLayerTunnelAnalyzer`) with the helper methods. No existing code
   changes yet.

2. **Migrate GRE** to inherit from `IPLayerTunnelAnalyzer`. Use
   `BuildInnerPacket` for tunnel tracking and inner packet creation.
   Add script-layer dispatch registrations (MPLS, Ethernet, ARUBA).
   Create dedicated ERSPAN analyzer. Remove GRE's dependency on
   `IPTunnelAnalyzer`. Run all GRE + ERSPAN tests.

3. **Create IPInIPAnalyzer** inheriting from `IPLayerTunnelAnalyzer`.
   Migrate IP-in-IP registration. Run `ip-in-ip.test`,
   `ip-tunnel-uid.test`.

4. **Migrate session-based tunnels** one at a time (AYIYA first as
   simplest, then VXLAN/Geneve, then Teredo/GTPv1). Each migration
   changes the inheritance and replaces boilerplate with helper calls.
   Run that analyzer's tests after each.

5. **Remove old IPTunnelAnalyzer** once all consumers are migrated.
   Remove without alias. Remove the global pointer.

6. **Add MPLS-in-GRE test** with the pcap from issue #5829.

Each step produces a working, testable state. Steps 2 and 3 fix the
bug; steps 4-5 are cleanup.
