#ifndef packet_h
#define packet_h

#include "Desc.h"
#include "IP.h"
#include "NetVar.h"

#if defined(__OpenBSD__)
#include <net/bpf.h>
typedef struct bpf_timeval pkt_timeval;
#else
typedef struct timeval pkt_timeval;
#endif

/**
 * The Layer 3 type of a packet, as determined by the parsing code in Packet.
 */
enum Layer3Proto {
	L3_UNKNOWN = -1,	/// Layer 3 type could not be determined.
	L3_IPV4 = 1,	/// Layer 3 is IPv4.
	L3_IPV6 = 2,	/// Layer 3 is IPv6.
	L3_ARP = 3,	/// Layer 3 is ARP.
};

/**
 * A link-layer packet.
 *
 * Note that for serialization we don't use much of the support provided by
 * the serialization framework. Serialize/Unserialize do all the work by
 * themselves. In particular, Packets aren't derived from SerialObj. They are
 * completely seperate and self-contained entities, and we don't need any of
 * the sophisticated features like object caching.
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
	Packet(int link_type, pkt_timeval *ts, uint32 caplen,
	       uint32 len, const u_char *data, int copy = false,
	       std::string tag = std::string(""))
	           : data(0), l2_src(0), l2_dst(0)
	       {
	       Init(link_type, ts, caplen, len, data, copy, tag);
	       }

	/**
	 * Default constructor. For internal use only.
	 */
	Packet() : data(0), l2_src(0), l2_dst(0)
		{
		pkt_timeval ts = {0, 0};
		Init(0, &ts, 0, 0, 0);
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
	void Init(int link_type, pkt_timeval *ts, uint32 caplen,
		uint32 len, const u_char *data, int copy = false,
		std::string tag = std::string(""));

	/**
	 * Returns true if parsing the layer 2 fields failed, including when
	 * no data was passed into the constructor in the first place.
	 */
	bool Layer2Valid()
		{
		return l2_valid;
		}

	/**
	 * Interprets the Layer 3 of the packet as IP and returns a
	 * correspondign object.
	 */
	const IP_Hdr IP() const
		{ return IP_Hdr((struct ip *) (data + hdr_size), false); }

	/**
	 * Returns a \c raw_pkt_hdr RecordVal, which includes layer 2 and
	 * also everything in IP_Hdr (i.e., IP4/6 + TCP/UDP/ICMP).
	 */
	RecordVal* BuildPktHdrVal() const;

	/**
	 * Static method returning the link-layer header size for a given
	 * link type.
	 *
	 * @param link_type The link tyoe.
	 *
	 * @return The header size in bytes, or -1 if not known.
	 */
	static int GetLinkHeaderSize(int link_type);

	/**
	 * Describes the packet, with standard signature.
	 */
	void Describe(ODesc* d) const;

	/**
	 * Serializes the packet, with standard signature.
	 */
	bool Serialize(SerialInfo* info) const;

	/**
	 * Unserializes the packet, with standard signature.
	 */
	static Packet* Unserialize(UnserialInfo* info);

	/**
	 * Maximal length of a layer 2 address.
	 */
	static const int l2_addr_len = 6;

	// These are passed in through the constructor.
	std::string tag;		/// Used in serialization
	double time;			/// Timestamp reconstituted as float
	pkt_timeval ts;			/// Capture timestamp
	const u_char* data;		/// Packet data.
	uint32 len;			/// Actual length on wire
	uint32 cap_len;			/// Captured packet length
	uint32 link_type;		/// pcap link_type (DLT_EN10MB, DLT_RAW, etc)

	// These are computed from Layer 2 data. These fields are only valid if
	// Layer2Valid() returns true.

	/**
	 * Layer 2 header size. Valid iff Layer2Valid() returns true.
	 */
	uint32 hdr_size;

	/**
	 * Layer 3 protocol identified (if any). Valid iff Layer2Valid()
	 * returns true.
	 */
	Layer3Proto l3_proto;

	/**
	 * If layer 2 is Ethernet, innermost ethertype field. Valid iff
	 * Layer2Valid() returns true.
	 */
	uint32 eth_type;

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
	uint32 vlan;

	/**
	 * (Innermost) VLAN tag if any, else 0. Valid iff Layer2Valid()
	 * returns true.
	 */
	uint32 inner_vlan;

private:
	// Calculate layer 2 attributes. Sets
	void ProcessLayer2();

	// Wrapper to generate a packet-level weird.
	void Weird(const char* name);

	// Renders an MAC address into its ASCII representation.
	Val *FmtEUI48(const u_char *mac) const;

	// True if we need to delete associated packet memory upon
	// destruction.
	bool copy;

	// True if L2 processing succeeded.
	bool l2_valid;
};

#endif // packet_h
