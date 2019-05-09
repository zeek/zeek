#pragma once

#include "zeek-config.h"

#include <string>

#include <stdint.h>
#include <sys/types.h> // for u_char

#if defined(__OpenBSD__)
#include <net/bpf.h>
typedef struct bpf_timeval pkt_timeval;
#else
typedef struct timeval pkt_timeval;
#endif

ZEEK_FORWARD_DECLARE_NAMESPACED(ODesc, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(RecordVal, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(IP_Hdr, zeek);

namespace zeek {

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
	       std::string tag = std::string(""))
	           : data(nullptr), l2_src(nullptr), l2_dst(nullptr)
	       {
	       Init(link_type, ts, caplen, len, data, copy, tag);
	       }

	/**
	 * Default constructor. For internal use only.
	 */
	Packet() : data(nullptr), l2_src(nullptr), l2_dst(nullptr)
		{
		pkt_timeval ts = {0, 0};
		Init(0, &ts, 0, 0, nullptr);
		}

	/**
	 * Destructor.
	 */
	~Packet()
		{
		if ( copy )
			delete [] data;
		}

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
		std::string tag = std::string(""));

	/**
	 * Returns true if parsing the layer 2 fields failed, including when
	 * no data was passed into the constructor in the first place.
	 */
	bool Layer2Valid() const
		{
		return l2_valid;
		}

	/**
	 * Interprets the Layer 3 of the packet as IP and returns a
	 * corresponding object.
	 */
	const IP_Hdr IP() const;

	/**
	 * Returns a \c raw_pkt_hdr RecordVal, which includes layer 2 and
	 * also everything in IP_Hdr (i.e., IP4/6 + TCP/UDP/ICMP).
	 */
	RecordValPtr ToRawPktHdrVal() const;

	[[deprecated("Remove in v4.1.  Use ToRawPktHdrval() instead.")]]
	RecordVal* BuildPktHdrVal() const;

	/**
	 * Returns the end of the captured data for bound checking.
	 *
	 * @return End of the packet data.
	 */
	const u_char* const GetEndOfData() const;

	/**
	 * Describes the packet, with standard signature.
	 */
	void Describe(ODesc* d) const;

	/**
	 * Maximal length of a layer 2 address.
	 */
	static const int L2_ADDR_LEN = 6;

	/**
	 * Empty layer 2 address to be used as default value. For example, the
	 * LinuxSLL llanalyzer doesn't have a destination address in the header
	 * and thus sets it to this default address.
	 */
	static constexpr const u_char L2_EMPTY_ADDR[L2_ADDR_LEN] = { 0 };

	// These are passed in through the constructor.
	std::string tag;		/// Used in serialization
	double time;			/// Timestamp reconstituted as float
	pkt_timeval ts;			/// Capture timestamp
	const u_char* data;		/// Packet data.
	uint32_t len;			/// Actual length on wire
	uint32_t cap_len;		/// Captured packet length
	uint32_t link_type;		/// pcap link_type (DLT_EN10MB, DLT_RAW, etc)
	const uint8_t* cur_pos;	/// Pointer to the current start of unanalyzed payload data in the raw packet, used by llanalyzers

	// These are computed from Layer 2 data. These fields are only valid if
	// Layer2Valid() returns true.

	/**
	 * Layer 2 header size. Valid iff Layer2Valid() returns true.
	 */
	uint32_t hdr_size;

	/**
	 * Layer 3 protocol identified (if any). Valid iff Layer2Valid()
	 * returns true.
	 */
	Layer3Proto l3_proto;

	/**
	 * If layer 2 is Ethernet, innermost ethertype field. Valid iff
	 * Layer2Valid() returns true.
	 */
	uint32_t eth_type;

	/**
	 * Layer 2 source address. Valid iff Layer2Valid() returns true.
	 */
	const u_char* l2_src;

	/**
	 * Layer 2 destination address. Valid iff Layer2Valid() returns
	 * true.
	 */
	const u_char* l2_dst;

	/**
	 * (Outermost) VLAN tag if any, else 0. Valid iff Layer2Valid()
	 * returns true.
	 */
	uint32_t vlan;

	/**
	 * (Innermost) VLAN tag if any, else 0. Valid iff Layer2Valid()
	 * returns true.
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

	// Wrapper to generate a packet-level weird. Has to be public for llanalyzers to use it.
	void Weird(const char* name);

private:
	// Renders an MAC address into its ASCII representation.
	ValPtr FmtEUI48(const u_char* mac) const;

	// True if we need to delete associated packet memory upon
	// destruction.
	bool copy;

	// True if L2 processing succeeded.
	bool l2_valid;
};

} // namespace zeek

using Layer3Proto [[deprecated("Remove in v4.1. Use zeek::Layer3Proto.")]] = zeek::Layer3Proto;
using Packet [[deprecated("Remove in v4.1. Use zeek::Packet.")]] = zeek::Packet;

constexpr auto L3_UNKNOWN [[deprecated("Remove in v4.1. Use zeek::L3_UNKNOWN")]] = zeek::L3_UNKNOWN;
constexpr auto L3_IPV4 [[deprecated("Remove in v4.1. Use zeek::L3_IPV4")]] = zeek::L3_IPV4;
constexpr auto L3_IPV6 [[deprecated("Remove in v4.1. Use zeek::L3_IPV6")]] = zeek::L3_IPV6;
constexpr auto L3_ARP [[deprecated("Remove in v4.1. Use zeek::L3_ARP")]] = zeek::L3_ARP;
