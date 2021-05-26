#pragma once

#include "zeek/zeek-config.h"

#include <stdint.h>
#include <sys/types.h> // for u_char
#include <string>

#if defined(__OpenBSD__)
#include <net/bpf.h>
typedef struct bpf_timeval pkt_timeval;
#else
typedef struct timeval pkt_timeval;
#endif

#include <pcap.h> // For DLT_ constants

#include "zeek/NetVar.h" // For BifEnum::Tunnel
#include "zeek/TunnelEncapsulation.h"
#include "zeek/IP.h"

namespace zeek {

class ODesc;
class Val;
class RecordVal;

template <class T> class IntrusivePtr;
using ValPtr = IntrusivePtr<Val>;
using RecordValPtr = IntrusivePtr<RecordVal>;

/**
 * The Layer 3 type of a packet, as determined by the parsing code in Packet.
 * This enum is sized as an int32_t to make the Packet structure align
 * correctly.
 */
enum Layer3Proto : int32_t {
	L3_UNKNOWN = -1,	/// Layer 3 type could not be determined.
	L3_IPV4 = 1,		/// Layer 3 is IPv4.
	L3_IPV6 = 2,		/// Layer 3 is IPv6.
	L3_ARP = 3,			/// Layer 3 is ARP.
};

/**
 * A link-layer packet.
 */
class Packet {
public:
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
	Packet(int link_type, pkt_timeval *ts, uint32_t caplen,
	       uint32_t len, const u_char *data, bool copy = false,
	       std::string tag = "")
	       {
	       Init(link_type, ts, caplen, len, data, copy, tag);
	       }

	/**
	 * Default constructor. For internal use only.
	 */
	Packet()
		{
		pkt_timeval ts = {0, 0};
		Init(0, &ts, 0, 0, nullptr);
		}

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
	void Init(int link_type, pkt_timeval *ts, uint32_t caplen,
	          uint32_t len, const u_char *data, bool copy = false,
	          std::string tag = "");

	/**
	 * Returns a \c raw_pkt_hdr RecordVal, which includes layer 2 and
	 * also everything in IP_Hdr (i.e., IP4/6 + TCP/UDP/ICMP).
	 */
	RecordValPtr ToRawPktHdrVal() const;

	/**
	 * Maximal length of a layer 2 address.
	 */
	static const int L2_ADDR_LEN = 6;

	/**
	 * Empty layer 2 address to be used as default value. For example, the
	 * LinuxSLL packet analyzer doesn't have a destination address in the
	 * header and thus sets it to this default address.
	 */
	static constexpr const u_char L2_EMPTY_ADDR[L2_ADDR_LEN] = { 0 };

	// These are passed in through the constructor.
	std::string tag;				/// Used in serialization
	double time;					/// Timestamp reconstituted as float
	pkt_timeval ts;					/// Capture timestamp
	const u_char* data = nullptr;	/// Packet data.
	uint32_t len;					/// Actual length on wire
	uint32_t cap_len;				/// Captured packet length
	uint32_t link_type;				/// pcap link_type (DLT_EN10MB, DLT_RAW, etc)

	/**
	 * Layer 3 protocol identified (if any).
	 */
	Layer3Proto l3_proto;

	/**
	 * If layer 2 is Ethernet, innermost ethertype field.
	 */
	uint32_t eth_type;

	/**
	 * Layer 2 source address.
	 */
	const u_char* l2_src = nullptr;

	/**
	 * Layer 2 destination address.
	 */
	const u_char* l2_dst = nullptr;

	/**
	 * (Outermost) VLAN tag if any, else 0.
	 */
	uint32_t vlan;

	/**
	 * (Innermost) VLAN tag if any, else 0.
	 */
	uint32_t inner_vlan;

	/**
	 * Indicates whether the layer 2 checksum was validated by the
	 * hardware/kernel before being received by zeek.
	 */
	bool l2_checksummed;

	/**
	 * Indicates whether the layer 3 checksum was validated by the
	 * hardware/kernel before being received by zeek.
	 */
	bool l3_checksummed;

	/**
	 * Indicates whether this packet should be recorded.
	 */
	mutable bool dump_packet;

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
	std::unique_ptr<IP_Hdr> ip_hdr = nullptr;

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
	BifEnum::Tunnel::Type tunnel_type = BifEnum::Tunnel::IP;

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

private:
	// Renders an MAC address into its ASCII representation.
	ValPtr FmtEUI48(const u_char* mac) const;

	// True if we need to delete associated packet memory upon
	// destruction.
	bool copy;
};

} // namespace zeek
