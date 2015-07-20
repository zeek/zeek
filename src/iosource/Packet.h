#ifndef packet_h
#define packet_h

#include "Desc.h"
#include "IP.h"
#include "NetVar.h"

enum Layer3Proto {
	L3_UNKNOWN = -1,
	L3_IPV4 = 1,
	L3_IPV6 = 2,
	L3_ARP = 3,
};

// A link-layer packet.
//
// Note that for serialization we don't use much of the support provided by
// the serialization framework. Serialize/Unserialize do all the work by
// themselves. In particular, Packets aren't derived from SerialObj. They are
// completely seperate and self-contained entities, and we don't need any of
// the sophisticated features like object caching.

class Packet {
public:
	Packet()
		{
		struct timeval ts = {0, 0};
		Init(0, &ts, 0, 0, 0);
		}
	// Construct and initialize from packet data.
	//
	// arg_free: If true makes an internal copy of the *data*. If false,
	// stores just a pointer to *data*, which must remain valid.
	Packet(int arg_link_type, struct timeval *arg_ts, uint32 arg_caplen,
		uint32 arg_len, const u_char *arg_data, int arg_free = false,
		std::string arg_tag = std::string(""))
		{
		Init(arg_link_type, arg_ts, arg_caplen, arg_len, arg_data, arg_free, arg_tag);
		}

	~Packet()
		{
		if ( free )
			delete [] data;
		}

	// Initialize with data from pointer.
	//
	// arg_free: If true makes an internal copy of the *data*. If false,
	// stores just a pointer to *data*, which must remain valid.
	void Init(int arg_link_type, struct timeval *arg_ts, uint32 arg_caplen,
		uint32 arg_len, const u_char *arg_data, int arg_free = false,
		std::string arg_tag = std::string(""), uint32 arg_hdrsize = 0)
		{
		link_type = arg_link_type;
		ts = *arg_ts;
		cap_len = arg_caplen;
		len = arg_len;
		free = arg_free;

		if ( free )
			{
			data = new u_char[cap_len];
			memcpy(const_cast<u_char *>(data), arg_data, cap_len);
			}
		else
			data = arg_data;

		hdr_size = arg_hdrsize;
		l3_proto = L3_UNKNOWN;
		tag = arg_tag;
		time = ts.tv_sec + double(ts.tv_usec) / 1e6;
		eth_type = 0;
		vlan = 0;

		l2_valid = false;

		if ( data )
			ProcessLayer2();
		}

	const IP_Hdr IP() const
		{ return IP_Hdr((struct ip *) (data + hdr_size), false); }

	// Returns true if parsing the Layer 2 fields failed, including when
	// no data was passed into the constructor in the first place.
	bool Layer2Valid()
		{
		return l2_valid;
		}

	void Describe(ODesc* d) const;

	/**
	 * Helper method to return the header size for a given link tyoe.
	 *
	 * @param link_type The link tyoe.
	 *
	 * @return The header size in bytes, or -1 if not known.
	 */
	static int GetLinkHeaderSize(int link_type);

	bool Serialize(SerialInfo* info) const;
	static Packet* Unserialize(UnserialInfo* info);

	// These are passed in through the constructor.
	std::string tag;		/// Used in serialization
	double time;			/// Timestamp reconstituted as float
	struct timeval ts;		/// Capture timestamp
	const u_char* data;		/// Packet data.
	uint32 len;			/// Actual length on wire
	uint32 cap_len;			/// Captured packet length
	uint32 link_type;		/// pcap link_type (DLT_EN10MB, DLT_RAW, etc)

	// These are computed from Layer 2 data. These fields are only valid if
	// Layer2Valid() returns true.
	uint32 hdr_size;		/// Layer 2 header size
	Layer3Proto l3_proto;		/// Layer 3 protocol identified (if any)
	uint32 eth_type;		/// If L2==ethernet, innermost ethertype field
	uint32 vlan;			/// (Outermost) VLan tag if any, else 0

private:
	// Calculate layer 2 attributes. Sets
	void ProcessLayer2();

	// Wrapper to generate a packet-level weird.
	void Weird(const char* name);

	// should we delete associated packet memory upon destruction.
	bool free;

	// True if L2 processing succeeded.
	bool l2_valid;
};

#endif // packet_h
