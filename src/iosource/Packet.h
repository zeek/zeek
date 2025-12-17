// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <cstdint>
#include <optional>
#include <string>

#if defined(__OpenBSD__)

#include <net/bpf.h>
using pkt_timeval = bpf_timeval;
#else
using pkt_timeval = struct timeval;
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include "zeek/IP.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/session/Session.h"

// Originally from <pcap/dlt.h>, duplicated here to avoid a dependency
// on libpcap in plugin builds.
#ifdef __OpenBSD__
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DLT_RAW 14 /* raw IP */
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define DLT_RAW 12 /* raw IP */
#endif

namespace zeek {

inline constexpr uint32_t vlan_unset_val = 0xFF000000;

class ODesc;
class Val;
class RecordVal;

template<class T>
class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using RecordValPtr = IntrusivePtr<RecordVal>;

/**
 * The Layer 3 type of a packet, as determined by the parsing code in Packet.
 * This enum is sized as an int32_t to make the Packet structure align
 * correctly.
 */
enum Layer3Proto : int8_t {
    L3_UNKNOWN = -1, /// Layer 3 type could not be determined.
    L3_IPV4 = 1,     /// Layer 3 is IPv4.
    L3_IPV6 = 2,     /// Layer 3 is IPv6.
    L3_ARP = 3,      /// Layer 3 is ARP.
};

/**
 * A link-layer packet.
 */
class Packet {
public:
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    /**
     * Construct and initialize from packet data.
     *
     * @param link_type The link type in the form of a \c DLT_* constant.
     *
     * @param ts The timestamp associated with the packet.
     *
     * @param caplen The number of bytes valid in *data*.
     *
     * @param len The wire length of the packet, which must be more or
     * equal *caplen* (but can't be less).
     *
     * @param data A pointer to the raw packet data, starting with the
     * layer 2 header. The pointer must remain valid for the lifetime of
     * the Packet instance, unless *copy* is true.
     *
     * @param copy If true, the constructor will make an internal copy of
     * *data*, so that the caller can release its version.
     *
     * @param tag A textual tag to associate with the packet for
     * differentiating the input streams.
     */
    Packet(int link_type, pkt_timeval* ts, uint32_t caplen, uint32_t len, const u_char* data, bool copy = false,
           std::string tag = "") {
        Init(link_type, ts, caplen, len, data, copy, std::move(tag));
    }

    /**
     * Default constructor. For internal use only.
     */
    Packet() {
        pkt_timeval ts = {0, 0};
        Init(0, &ts, 0, 0, nullptr);
    }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif

    /**
     * Destructor.
     */
    ~Packet();

    /**
     * (Re-)initialize from packet data.
     *
     * @param link_type The link type in the form of a \c DLT_* constant.
     *
     * @param ts The timestamp associated with the packet.
     *
     * @param caplen The number of bytes valid in *data*.
     *
     * @param len The wire length of the packet, which must be more or
     * equal *caplen* (but can't be less).
     *
     * @param data A pointer to the raw packet data, starting with the
     * layer 2 header. The pointer must remain valid for the lifetime of
     * the Packet instance, unless *copy* is true.
     *
     * @param copy If true, the constructor will make an internal copy of
     * *data*, so that the caller can release its version.
     *
     * @param tag A textual tag to associate with the packet for
     * differentiating the input streams.
     */
    void Init(int link_type, pkt_timeval* ts, uint32_t caplen, uint32_t len, const u_char* data, bool copy = false,
              std::string tag = "");

    /**
     * Returns a \c raw_pkt_hdr RecordVal, which includes layer 2 and
     * also everything in IP_Hdr (i.e., IP4/6 + TCP/UDP/ICMP).
     */
    RecordValPtr ToRawPktHdrVal() const;

    /**
     * Returns a RecordVal that represents the Packet. This is used
     * by the get_current_packet bif.
     */
    static RecordValPtr ToVal(const Packet* p);

    /**
     * Maximal length of a layer 2 address.
     */
    static const int L2_ADDR_LEN = 6;

    /**
     * Empty layer 2 address to be used as default value. For example, the
     * LinuxSLL/LinuxSLL2 packet analyzers don't have a destination address
     * in the header and thus sets it to this default address.
     */
    static constexpr const u_char L2_EMPTY_ADDR[L2_ADDR_LEN] = {0};

    struct VlanTag {
        uint16_t id = 0; // This struct is used optionally so no need to encode as 0xFF000000
        uint8_t pcp = 0;
        bool dei = false;

        auto operator<=>(const VlanTag&) const = default;
    };

    // Accessor methods for VLAN fields
    // Suppress deprecation warnings since these methods need to access deprecated fields
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#elif defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    /**
     * (Outermost) VLAN tag if present, otherwise empty
     */
    std::optional<VlanTag> GetVlanTag() const {
        if ( vlan == vlan_unset_val )
            return {};

        if ( ! std::in_range<uint16_t>(vlan) )
            reporter->InternalError("VLAN ID value %u exceeds 16 bits", vlan);

        if ( ! std::in_range<uint8_t>(vlan_pcp) )
            reporter->InternalError("VLAN PCP value %u exceeds 8 bits", vlan_pcp);

        return std::optional<VlanTag>{
            {.id = static_cast<uint16_t>(vlan), .pcp = static_cast<uint8_t>(vlan_pcp), .dei = vlan_dei}};
    }

    /**
     * (Outermost) Sets the VLAN tag and marks it as present
     */
    void SetVlanTag(VlanTag tag) {
        vlan = tag.id;
        vlan_pcp = tag.pcp;
        vlan_dei = tag.dei;
    }

    /**
     * (Innermost) VLAN tag if present, otherwise empty
     */
    std::optional<VlanTag> GetInnerVlanTag() const {
        if ( inner_vlan == vlan_unset_val )
            return std::nullopt;

        if ( ! std::in_range<uint16_t>(inner_vlan) )
            reporter->InternalError("inner VLAN ID value %u exceeds 16 bits", inner_vlan);

        if ( ! std::in_range<uint8_t>(inner_vlan_pcp) )
            reporter->InternalError("inner VLAN PCP value %u exceeds 8 bits", inner_vlan_pcp);

        return std::optional<VlanTag>{{.id = static_cast<uint16_t>(inner_vlan),
                                       .pcp = static_cast<uint8_t>(inner_vlan_pcp),
                                       .dei = inner_vlan_dei}};
    }

    /**
     * (Innermost) Sets the VLAN tag and marks it as present
     */
    void SetInnerVlanTag(VlanTag tag) {
        inner_vlan = tag.id;
        inner_vlan_pcp = tag.pcp;
        inner_vlan_dei = tag.dei;
    }

    /**
     * Clears both of the VLAN tags
     */
    void ClearVlanTags() {
        vlan = vlan_unset_val;
        vlan_pcp = 0;
        vlan_dei = false;

        inner_vlan = vlan_unset_val;
        inner_vlan_pcp = 0;
        inner_vlan_dei = false;
    }

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#elif defined(_MSC_VER)
#pragma warning(pop)
#endif

    // These are passed in through the constructor.
    std::string tag;              /// Used in serialization
    double time;                  /// Timestamp reconstituted as float
    pkt_timeval ts;               /// Capture timestamp
    const u_char* data = nullptr; /// Packet data.
    uint32_t len;                 /// Actual length on wire
    uint32_t cap_len;             /// Captured packet length
    uint32_t link_type;           /// pcap link_type (DLT_EN10MB, DLT_RAW, etc)

    /**
     * If layer 2 is Ethernet, innermost ethertype field.
     */
    uint32_t eth_type;

    // These should be made combined into 2 private, optional VlanTag instances
    [[deprecated("Remove in v9.1. Use GetVlanTag() and SetVlanTag(tag) instead.")]]
    uint32_t vlan = 0;
    [[deprecated("Remove in v9.1. Use GetVlanTag() and SetVlanTag(tag) instead.")]]
    uint32_t vlan_pcp = 0;
    [[deprecated("Remove in v9.1. Use GetVlanTag() and SetVlanTag(tag) instead.")]]
    bool vlan_dei = false;
    [[deprecated("Remove in v9.1. Use GetInnerVlanTag() and SetInnerVlanTag(tag) instead.")]]
    uint32_t inner_vlan = 0;
    [[deprecated("Remove in v9.1. Use GetInnerVlanTag() and SetInnerVlanTag(tag) instead.")]]
    uint32_t inner_vlan_pcp = 0;
    [[deprecated("Remove in v9.1. Use GetInnerVlanTag() and SetInnerVlanTag(tag) instead.")]]
    bool inner_vlan_dei = false;

    /**
     * Layer 3 protocol identified (if any).
     */
    Layer3Proto l3_proto;

    /**
     * If this packet is related to a connection, this flag denotes whether
     * this packet is from the originator of the connection.
     */
    bool is_orig = false;

    // Note: The following checksummed variables only apply to packets
    // received via a packet source, and not to packets contained inside
    // tunnels, etc.

    /**
     * Indicates whether the data link layer/layer 2 checksum was validated
     * the hardware/kernel before being received by zeek.
     */
    bool l2_checksummed = false;

    /**
     * Indicates whether the network layer/layer 3 checksum was validated by
     * the hardware/kernel before being received by zeek.
     */
    bool l3_checksummed = false;

    /**
     * Indicates whether the transport layer/layer 4 checksum was validated
     * by the hardware/kernel before being received by zeek.
     */
    bool l4_checksummed = false;

    /**
     * Layer 2 source address.
     */
    const u_char* l2_src = nullptr;

    /**
     * Layer 2 destination address.
     */
    const u_char* l2_dst = nullptr;

    /**
     * This flag indicates whether a packet has been processed. This can
     * mean different things depending on the traffic, but generally it
     * means that a packet has been logged in some way. We default to
     * false, and this can be set to true for any number of reasons.
     */
    bool processed = false;

    /**
     * Indicates whether this packet should be recorded.
     */
    mutable bool dump_packet = false;

    /**
     * Indicates the amount of data to be dumped. If only a header is needed,
     * set this to the size of the header. Setting it to zero will dump the
     * entire packet.
     */
    mutable int dump_size = 0;

    // These are fields passed between various packet analyzers. They're best
    // stored with the packet so they stay available as the packet is passed
    // around.

    /**
     * The stack of encapsulations this packet belongs to, if any. This is
     * used by the tunnel analyzers to keep track of the encapsulations as
     * processing occurs.
     */
    std::shared_ptr<EncapsulationStack> encap = nullptr;

    /**
     * The IP header for this packet. This is filled in by the IP analyzer
     * during processing if the packet contains an IP header.
     */
    std::shared_ptr<IP_Hdr> ip_hdr = nullptr;

    /**
     * The protocol of the packet. This is used by the tunnel analyzers to
     * pass outer protocol from one level to the next.
     */
    int proto = -1;

    /**
     * If the packet contains a tunnel, this field will be filled in with
     * the type of tunnel. It is used to pass the tunnel type between the
     * packet analyzers during analysis.
     */
    BifEnum::Tunnel::Type tunnel_type = BifEnum::Tunnel::NONE;

    /**
     * If the packet contains a GRE tunnel, this field will contain the
     * GRE version. It is used to pass this information from the GRE
     * analyzer to the IPTunnel analyzer.
     */
    int gre_version = -1;

    /**
     * If the packet contains a GRE tunnel, this field will contain the
     * GRE link type. It is used to pass this information from the GRE
     * analyzer to the IPTunnel analyzer.
     */
    int gre_link_type = DLT_RAW;

    /**
     * The session related to this packet, if one exists.
     */
    session::Session* session = nullptr;

private:
    // Renders an MAC address into its ASCII representation.
    ValPtr FmtEUI48(const u_char* mac) const;

    // True if we need to delete associated packet memory upon
    // destruction.
    bool copy = false;
};

} // namespace zeek
