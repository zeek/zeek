// $Id:$
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef dns_rewriter_h
#define dns_rewriter_h

#include "UDP.h"
#include "UDP_Rewriter.h"
#include "Rewriter.h"

#define DNS_HDR_SIZE 12

// DNS packets size. 512 is the *normal* size, but some packets are bigger
// than this, and the anonymization process can expand packets, so we
// pad this way out.
#define DNS_PKT_SIZE (512*4)

class DNS_Rewriter: public UDP_Rewriter {
public:
	DNS_Rewriter(Analyzer* analyzer, int arg_MTU, PacketDumper* dumper);
	virtual ~DNS_Rewriter()	{ delete pkt;}

	void DnsCopyHeader(Val* val);

	int DnsCopyQuery(const BroString* query, uint32 qtype, uint32 qclass);
	int DnsCopyQuery(Val* val);

	void DnsCopyNS(Val* ans, const BroString* name);
	void DnsCopyPTR(Val* ans, const BroString* name);
	void DnsCopyCNAME(Val* ans, const BroString* name);
	void DnsCopyTXT(Val* ans, const BroString* name);
	void DnsCopyA(Val* ans, uint32 addr);

	// AAAA is weird, because the address is an IPv4 type.
	// If we don't have IPv6, and if it's IPv6, it's a pointer
	// to valid data.
	void DnsCopyAAAA(Val* ans, addr_type addr, const BroString* addrstr);

	void DnsCopyMX(Val* ans, const BroString* name, uint32 preference);
	void DnsCopySOA(Val* ans, Val* soa);
	void DnsCopyEDNSaddl(Val* ans);

	int DnsPktMatch(Val* val);
	const u_char* Packet() const	{ return pkt; }
	int PacketSize() const	{ return pkt_size; }
	void SetOrig( int orig )	{ is_orig = orig; }
	int IsOrig()			{ return is_orig; }

	int WriteDoubleAsInt(double d)	{ return WriteVal(uint32(d)); }
	int WriteShortVal(uint16 val)	{ return WriteVal(uint16(val)); }
	int WriteVal(uint32 val);
	int WriteVal(uint16 val);
	int WriteVal(uint8 val);
	int WriteVal(const uint32* val);
	int WriteVal(const BroString* val);

private:
	u_char* pkt;		// the DNS packet
	int pkt_size;		// size of the packet
	int current_pkt_id;	// current ID (sanity checking)

	int is_orig;

	u_char* dn_ptrs[30];	// pointer to names in DNS packet
	u_char** dpp;		// points to current position in DNS packet
	u_char** last_dn_ptr;	// points to last entry in dn_ptrs
};

#endif
