// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ip_h
#define ip_h

#include "zeek-config.h"
#include "net_util.h"
#include "IPAddr.h"
#include "Reporter.h"
#include "Val.h"
#include "Type.h"
#include <vector>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef ENABLE_MOBILE_IPV6

#ifndef IPPROTO_MOBILITY
#define IPPROTO_MOBILITY 135
#endif

struct ip6_mobility {
	uint8 ip6mob_payload;
	uint8 ip6mob_len;
	uint8 ip6mob_type;
	uint8 ip6mob_rsv;
	uint16 ip6mob_chksum;
};

#endif //ENABLE_MOBILE_IPV6

/**
 * Base class for IPv6 header/extensions.
 */
class IPv6_Hdr {
public:
	/**
	 * Construct an IPv6 header or extension header from assigned type number.
	 */
	IPv6_Hdr(uint8 t, const u_char* d) : type(t), data(d) {}

	/**
	 * Replace the value of the next protocol field.
	 */
	void ChangeNext(uint8 next_type)
		{
		switch ( type ) {
		case IPPROTO_IPV6:
			((ip6_hdr*)data)->ip6_nxt = next_type;
			break;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_AH:
#ifdef ENABLE_MOBILE_IPV6
		case IPPROTO_MOBILITY:
#endif
			((ip6_ext*)data)->ip6e_nxt = next_type;
			break;
		case IPPROTO_ESP:
		default:
			break;
		}
		}

	~IPv6_Hdr() {}

	/**
	 * Returns the assigned IPv6 extension header type number of the header
	 * that immediately follows this one.
	 */
	uint8 NextHdr() const
		{
		switch ( type ) {
		case IPPROTO_IPV6:
			return ((ip6_hdr*)data)->ip6_nxt;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_FRAGMENT:
		case IPPROTO_AH:
#ifdef ENABLE_MOBILE_IPV6
		case IPPROTO_MOBILITY:
#endif
			return ((ip6_ext*)data)->ip6e_nxt;
		case IPPROTO_ESP:
		default:
			return IPPROTO_NONE;
		}
		}

	/**
	 * Returns the length of the header in bytes.
	 */
	uint16 Length() const
		{
		switch ( type ) {
		case IPPROTO_IPV6:
			return 40;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
#ifdef ENABLE_MOBILE_IPV6
		case IPPROTO_MOBILITY:
#endif
			return 8 + 8 * ((ip6_ext*)data)->ip6e_len;
		case IPPROTO_FRAGMENT:
			return 8;
		case IPPROTO_AH:
			return 8 + 4 * ((ip6_ext*)data)->ip6e_len;
		case IPPROTO_ESP:
			return 8; //encrypted payload begins after 8 bytes
		default:
			return 0;
		}
		}

	/**
	 * Returns the RFC 1700 et seq. IANA assigned number for the header.
	 */
	uint8 Type() const { return type; }

	/**
	 * Returns pointer to the start of where header structure resides in memory.
	 */
	const u_char* Data() const { return data; }

	/**
	 * Returns the script-layer record representation of the header.
	 */
	RecordVal* BuildRecordVal(VectorVal* chain = 0) const;

protected:
	uint8 type;
	const u_char* data;
};

class IPv6_Hdr_Chain {
public:
	/**
	 * Initializes the header chain from an IPv6 header structure.
	 */
	IPv6_Hdr_Chain(const struct ip6_hdr* ip6, int len) :
#ifdef ENABLE_MOBILE_IPV6
		homeAddr(0),
#endif
		finalDst(0)
		{ Init(ip6, len, false); }

	~IPv6_Hdr_Chain()
		{
		for ( size_t i = 0; i < chain.size(); ++i ) delete chain[i];
#ifdef ENABLE_MOBILE_IPV6
		delete homeAddr;
#endif
		delete finalDst;
		}

	/**
	 * @return a copy of the header chain, but with pointers to individual
	 * IPv6 headers now pointing within \a new_hdr.
	 */
	IPv6_Hdr_Chain* Copy(const struct ip6_hdr* new_hdr) const;

	/**
	 * Returns the number of headers in the chain.
	 */
	size_t Size() const { return chain.size(); }

	/**
	 * Returns the sum of the length of all headers in the chain in bytes.
	 */
	uint16 TotalLength() const { return length; }

	/**
	 * Accesses the header at the given location in the chain.
	 */
	const IPv6_Hdr* operator[](const size_t i) const { return chain[i]; }

	/**
	 * Returns whether the header chain indicates a fragmented packet.
	 */
	bool IsFragment() const
		{
		if ( chain.empty() )
			{
			reporter->InternalWarning("empty IPv6 header chain");
			return false;
			}

		return chain[chain.size()-1]->Type() == IPPROTO_FRAGMENT;
		}

	/**
	 * Returns pointer to fragment header structure if the chain contains one.
	 */
	const struct ip6_frag* GetFragHdr() const
		{ return IsFragment() ?
				(const struct ip6_frag*)chain[chain.size()-1]->Data(): 0; }

	/**
	 * If the header chain is a fragment, returns the offset in number of bytes
	 * relative to the start of the Fragmentable Part of the original packet.
	 */
	uint16 FragOffset() const
		{ return IsFragment() ?
				(ntohs(GetFragHdr()->ip6f_offlg) & 0xfff8) : 0; }

	/**
	 * If the header chain is a fragment, returns the identification field.
	 */
	uint32 ID() const
		{ return IsFragment() ?	ntohl(GetFragHdr()->ip6f_ident) : 0; }

	/**
	 * If the header chain is a fragment, returns the M (more fragments) flag.
	 */
	int MF() const
		{ return IsFragment() ?
				(ntohs(GetFragHdr()->ip6f_offlg) & 0x0001) != 0 : 0; }

	/**
	 * If the chain contains a Destination Options header with a Home Address
	 * option as defined by Mobile IPv6 (RFC 6275), then return it, else
	 * return the source address in the main IPv6 header.
	 */
	IPAddr SrcAddr() const
		{
#ifdef ENABLE_MOBILE_IPV6
		if ( homeAddr )
			return IPAddr(*homeAddr);
#endif
		if ( chain.empty() )
			{
			reporter->InternalWarning("empty IPv6 header chain");
			return IPAddr();
			}

		return IPAddr(((const struct ip6_hdr*)(chain[0]->Data()))->ip6_src);
		}

	/**
	 * If the chain contains a Routing header with non-zero segments left,
	 * then return the last address of the first such header, else return
	 * the destination address of the main IPv6 header.
	 */
	IPAddr DstAddr() const
		{
		if ( finalDst )
			return IPAddr(*finalDst);

		if ( chain.empty() )
			{
			reporter->InternalWarning("empty IPv6 header chain");
			return IPAddr();
			}

		return IPAddr(((const struct ip6_hdr*)(chain[0]->Data()))->ip6_dst);
		}

	/**
	 * Returns a vector of ip6_ext_hdr RecordVals that includes script-layer
	 * representation of all extension headers in the chain.
	 */
	VectorVal* BuildVal() const;

protected:
	// for access to protected ctor that changes next header values that
	// point to a fragment
	friend class FragReassembler;

	IPv6_Hdr_Chain() :
		length(0),
#ifdef ENABLE_MOBILE_IPV6
		homeAddr(0),
#endif
		finalDst(0)
		{}

	/**
	 * Initializes the header chain from an IPv6 header structure, and replaces
	 * the first next protocol pointer field that points to a fragment header.
	 */
	IPv6_Hdr_Chain(const struct ip6_hdr* ip6, uint16 next, int len) :
#ifdef ENABLE_MOBILE_IPV6
		homeAddr(0),
#endif
		finalDst(0)
		{ Init(ip6, len, true, next); }

	/**
	 * Initializes the header chain from an IPv6 header structure of a given
	 * length, possibly setting the first next protocol pointer field that
	 * points to a fragment header.
	 */
	void Init(const struct ip6_hdr* ip6, int total_len, bool set_next,
	          uint16 next = 0);

	/**
	 * Process a routing header and allocate/remember the final destination
	 * address if it has segments left and is a valid routing header.
	 */
	void ProcessRoutingHeader(const struct ip6_rthdr* r, uint16 len);

#ifdef ENABLE_MOBILE_IPV6
	/**
	 * Inspect a Destination Option header's options for things we need to
	 * remember, such as the Home Address option from Mobile IPv6.
	 */
	void ProcessDstOpts(const struct ip6_dest* d, uint16 len);
#endif

	vector<IPv6_Hdr*> chain;

	/**
	 * The summation of all header lengths in the chain in bytes.
	 */
	uint16 length;

#ifdef ENABLE_MOBILE_IPV6
	/**
	 * Home Address of the packet's source as defined by Mobile IPv6 (RFC 6275).
	 */
	IPAddr* homeAddr;
#endif

	/**
	 * The final destination address in chain's first Routing header that has
	 * non-zero segments left.
	 */
	IPAddr* finalDst;
};

/**
 * A class that wraps either an IPv4 or IPv6 packet and abstracts methods
 * for inquiring about common features between the two.
 */
class IP_Hdr {
public:
	/**
	 * Construct the header wrapper from an IPv4 packet.  Caller must have
	 * already checked that the header is not truncated.
	 * @param arg_ip4 pointer to memory containing an IPv4 packet.
	 * @param arg_del whether to take ownership of \a arg_ip4 pointer's memory.
	 */
	IP_Hdr(const struct ip* arg_ip4, bool arg_del)
		: ip4(arg_ip4), ip6(0), del(arg_del), ip6_hdrs(0)
		{
		}

	/**
	 * Construct the header wrapper from an IPv6 packet.  Caller must have
	 * already checked that the static IPv6 header is not truncated.  If
	 * the packet contains extension headers and they are truncated, that can
	 * be checked afterwards by comparing \a len with \a TotalLen.  E.g.
	 * NetSessions::DoNextPacket does this to skip truncated packets.
	 * @param arg_ip6 pointer to memory containing an IPv6 packet.
	 * @param arg_del whether to take ownership of \a arg_ip6 pointer's memory.
	 * @param len the packet's length in bytes.
	 * @param c an already-constructed header chain to take ownership of.
	 */
	IP_Hdr(const struct ip6_hdr* arg_ip6, bool arg_del, int len,
	       const IPv6_Hdr_Chain* c = 0)
		: ip4(0), ip6(arg_ip6), del(arg_del),
		  ip6_hdrs(c ? c : new IPv6_Hdr_Chain(ip6, len))
		{
		}

	/**
	 * Copy a header.  The internal buffer which contains the header data
	 * must not be truncated.  Also note that if that buffer points to a full
	 * packet payload, only the IP header portion is copied.
	 */
	IP_Hdr* Copy() const;

	/**
	 * Destructor.
	 */
	~IP_Hdr()
		{
		delete ip6_hdrs;

		if ( del )
			{
			delete [] (struct ip*) ip4;
			delete [] (struct ip6_hdr*) ip6;
			}
		}

	/**
	 * If an IPv4 packet is wrapped, return a pointer to it, else null.
	 */
	const struct ip* IP4_Hdr() const	{ return ip4; }

	/**
	 * If an IPv6 packet is wrapped, return a pointer to it, else null.
	 */
	const struct ip6_hdr* IP6_Hdr() const	{ return ip6; }

	/**
	 * Returns the source address held in the IP header.
	 */
	IPAddr IPHeaderSrcAddr() const
		{ return ip4 ? IPAddr(ip4->ip_src) : IPAddr(ip6->ip6_src); }

	/**
	 * Returns the destination address held in the IP header.
	 */
	IPAddr IPHeaderDstAddr() const
		{ return ip4 ? IPAddr(ip4->ip_dst) : IPAddr(ip6->ip6_dst); }

	/**
	 * For IPv4 or IPv6 headers that don't contain a Home Address option
	 * (Mobile IPv6, RFC 6275), return source address held in the IP header.
	 * For IPv6 headers that contain a Home Address option, return that address.
	 */
	IPAddr SrcAddr() const
		{ return ip4 ? IPAddr(ip4->ip_src) : ip6_hdrs->SrcAddr(); }

	/**
	 * For IPv4 or IPv6 headers that don't contain a Routing header with
	 * non-zero segments left, return destination address held in the IP header.
	 * For IPv6 headers with a Routing header that has non-zero segments left,
	 * return the last address in the first such Routing header.
	 */
	IPAddr DstAddr() const
		{ return ip4 ? IPAddr(ip4->ip_dst) : ip6_hdrs->DstAddr(); }

	/**
	 * Returns a pointer to the payload of the IP packet, usually an
	 * upper-layer protocol.
	 */
	const u_char* Payload() const
		{
		if ( ip4 )
			return ((const u_char*) ip4) + ip4->ip_hl * 4;
		else
			return ((const u_char*) ip6) + ip6_hdrs->TotalLength();
		}

#ifdef ENABLE_MOBILE_IPV6
	/**
	 * Returns a pointer to the mobility header of the IP packet, if present,
	 * else a null pointer.
	 */
	const ip6_mobility* MobilityHeader() const
		{
		if ( ip4 )
			return 0;
		else if ( (*ip6_hdrs)[ip6_hdrs->Size()-1]->Type() != IPPROTO_MOBILITY )
			return 0;
		else
			return (const ip6_mobility*)(*ip6_hdrs)[ip6_hdrs->Size()-1]->Data();
		}
#endif

	/**
	 * Returns the length of the IP packet's payload (length of packet minus
	 * header length or, for IPv6, also minus length of all extension headers).
	 */
	uint16 PayloadLen() const
		{
		if ( ip4 )
			return ntohs(ip4->ip_len) - ip4->ip_hl * 4;
		else
			return ntohs(ip6->ip6_plen) + 40 - ip6_hdrs->TotalLength();
		}

	/**
	 * Returns the length of the IP packet (length of headers and payload).
	 */
	uint32 TotalLen() const
		{ return ip4 ? ntohs(ip4->ip_len) : ntohs(ip6->ip6_plen) + 40; }

	/**
	 * Returns length of IP packet header (includes extension headers for IPv6).
	 */
	uint16 HdrLen() const
		{ return ip4 ? ip4->ip_hl * 4 : ip6_hdrs->TotalLength(); }

	/**
	 * For IPv6 header chains, returns the type of the last header in the chain.
	 */
	uint8 LastHeader() const
		{
		if ( ip4 )
			return IPPROTO_RAW;

		size_t i = ip6_hdrs->Size();
		if ( i > 0 )
			return (*ip6_hdrs)[i-1]->Type();

		return IPPROTO_NONE;
		}

	/**
	 * Returns the protocol type of the IP packet's payload, usually an
	 * upper-layer protocol.  For IPv6, this returns the last (extension)
	 * header's Next Header value.
	 */
	unsigned char NextProto() const
		{
		if ( ip4 )
			return ip4->ip_p;

		size_t i = ip6_hdrs->Size();
		if ( i > 0 )
			return (*ip6_hdrs)[i-1]->NextHdr();

		return IPPROTO_NONE;
		}

	/**
	 * Returns the IPv4 Time to Live or IPv6 Hop Limit field.
	 */
	unsigned char TTL() const
		{ return ip4 ? ip4->ip_ttl : ip6->ip6_hlim; }

	/**
	 * Returns whether the IP header indicates this packet is a fragment.
	 */
	bool IsFragment() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x3fff) != 0 :
				ip6_hdrs->IsFragment(); }

	/**
	 * Returns the fragment packet's offset in relation to the original
	 * packet in bytes.
	 */
	uint16 FragOffset() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x1fff) * 8 :
				ip6_hdrs->FragOffset(); }

	/**
	 * Returns the fragment packet's identification field.
	 */
	uint32 ID() const
		{ return ip4 ? ntohs(ip4->ip_id) : ip6_hdrs->ID(); }

	/**
	 * Returns whether a fragment packet's "More Fragments" field is set.
	 */
	int MF() const
		{ return ip4 ? (ntohs(ip4->ip_off) & 0x2000) != 0 : ip6_hdrs->MF(); }

	/**
	 * Returns whether a fragment packet's "Don't Fragment" field is set.
	 * Note that IPv6 has no such field.
	 */
	int DF() const
		{ return ip4 ? ((ntohs(ip4->ip_off) & 0x4000) != 0) : 0; }

	/**
	 * Returns value of an IPv6 header's flow label field or 0 if it's IPv4.
	 */
	uint32 FlowLabel() const
		{ return ip4 ? 0 : (ntohl(ip6->ip6_flow) & 0x000fffff); }

	/**
	 * Returns number of IP headers in packet (includes IPv6 extension headers).
	 */
	size_t NumHeaders() const
		{ return ip4 ? 1 : ip6_hdrs->Size(); }

	/**
	 * Returns an ip_hdr or ip6_hdr_chain RecordVal.
	 */
	RecordVal* BuildIPHdrVal() const;

	/**
	 * Returns a pkt_hdr RecordVal, which includes not only the IP header, but
	 * also upper-layer (tcp/udp/icmp) headers.
	 */
	RecordVal* BuildPktHdrVal() const;

	/**
	 * Same as above, but simply add our values into the record at the
	 * specified starting index.
	 */
	RecordVal* BuildPktHdrVal(RecordVal* pkt_hdr, int sindex) const;

private:
	const struct ip* ip4;
	const struct ip6_hdr* ip6;
	bool del;
	const IPv6_Hdr_Chain* ip6_hdrs;
};

#endif
