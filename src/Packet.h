#ifndef packet_h
#define packet_h

#include "Desc.h"
#include "IP.h"

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
	Packet(int arg_link_type, struct timeval *arg_ts, uint32 arg_caplen,
		uint32 arg_len, const u_char *arg_data, int arg_free = false,
		std::string arg_tag = std::string(""), uint32 arg_hdrsize = 0,
		int arg_l3_proto = -1)
		{
		Init(arg_link_type, arg_ts, arg_caplen, arg_len, arg_data, arg_free, arg_tag,
			arg_hdrsize, arg_l3_proto);
		}

	~Packet()
		{
		if ( free )
			delete [] data;
		}

	// Initialize with data from pointer
	void Init(int arg_link_type, struct timeval *arg_ts, uint32 arg_caplen,
		uint32 arg_len, const u_char *arg_data, int arg_free = false,
		std::string arg_tag = std::string(""), uint32 arg_hdrsize = 0,
		int arg_l3_proto = -1)
		{
		link_type = arg_link_type;
		ts = *arg_ts;
		cap_len = arg_caplen;
		len = arg_len;
		free = arg_free;
		if ( free )
			{
			data = new u_char [cap_len];
			memcpy(const_cast<u_char *>(data), arg_data, cap_len);
			}
		else
			data = arg_data;
		hdr_size = arg_hdrsize;
		l3_proto = arg_l3_proto;
		tag = arg_tag;
		time = ts.tv_sec + double(ts.tv_usec) / 1e6;
		eth_type = 0;
		vlan = 0;
		}

	const IP_Hdr IP() const
		{ return IP_Hdr((struct ip *) (data + hdr_size), false); }

	void Describe(ODesc* d) const;

	bool Serialize(SerialInfo* info) const;
	static Packet* Unserialize(UnserialInfo* info);

	std::string tag;		// Used in serialization
	double time;			// Timestamp reconstituted as float

	struct timeval ts;		// Capture timestamp
	const u_char* data;		// Packet data.
	uint32 link_type;		// pcap link_type (DLT_EN10MB, DLT_RAW, etc)
	uint32 cap_len;			// Captured packet length
	uint32 len;			// Actual length on wire
	uint32 hdr_size;		// Layer 2 header size
	uint32 l3_proto;		// Layer 3 protocol identified (if any)
	uint32 eth_type;		// If L2==ethernet, innermost ethertype field
	uint32 vlan;			// (Outermost) VLan tag if any, else 0

private:
	// should we delete associated packet memory upon destruction.
	bool free;
};

#endif // packet_h
