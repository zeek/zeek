// $Id:$
//
// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#include "NetVar.h"
#include "DNS.h"
#include "Val.h"
#include "TCP.h"
#include "Anon.h"
#include "DNS_Rewriter.h"

DNS_Rewriter::DNS_Rewriter(Analyzer* analyzer, int arg_MTU,
				PacketDumper* dumper)
: UDP_Rewriter(analyzer, arg_MTU, dumper)
	{
	pkt_size = 0;
	current_pkt_id = 0;

	pkt = new u_char[DNS_PKT_SIZE + DNS_HDR_SIZE];
	}

void DNS_Rewriter::DnsCopyHeader(Val* msg)
	{
	// New header - reset packet size.
	pkt_size = 0;

	// Move msg->AsRecordVal() to a RecordVal* to optimize.
	const RecordVal* msg_rec = msg->AsRecordVal();
	int id = msg_rec->Lookup(0)->AsCount();
	int opcode = msg_rec->Lookup(1)->AsCount();
	int rcode = msg_rec->Lookup(2)->AsCount();
	int QR = msg_rec->Lookup(3)->AsBool();
	int AA = msg_rec->Lookup(4)->AsBool();
	int TC = msg_rec->Lookup(5)->AsBool();
	int RD = msg_rec->Lookup(6)->AsBool();
	int RA = msg_rec->Lookup(7)->AsBool();
	int Z = msg_rec->Lookup(8)->AsCount();
	int qdcount = msg_rec->Lookup(9)->AsCount();
	int ancount = msg_rec->Lookup(10)->AsCount();
	int nscount = msg_rec->Lookup(11)->AsCount();
	int arcount = msg_rec->Lookup(12)->AsCount();

	current_pkt_id = id;

	// Set the DNS flags.
	uint16 flags = (QR << 15) | (AA << 10) | (TC << 9) |
			(RD << 8) | (RA << 7) | (Z << 4);

	flags |= rcode | (opcode << 11);

	(void) WriteShortVal(id);
	(void) WriteShortVal(flags);
	(void) WriteShortVal(qdcount);
	(void) WriteShortVal(ancount);
	(void) WriteShortVal(nscount);
	(void) WriteShortVal(arcount);

	// We've finished the header.
	pkt_size = DNS_HDR_SIZE;

	// Assign all the pointers for dn_comp().
	dpp = dn_ptrs;
	*dpp++ = pkt;
	*dpp++ = 0;

	last_dn_ptr = dn_ptrs + sizeof dn_ptrs / sizeof dn_ptrs[0];
	}

int DNS_Rewriter::DnsCopyQuery(Val* val)
	{
	const RecordVal* val_rec = val->AsRecordVal();

	// int type = val_rec->Lookup(0)->AsCount();

	const BroString* query = val_rec->Lookup(1)->AsString();
	int atype = val_rec->Lookup(2)->AsCount();
	int aclass = val_rec->Lookup(3)->AsCount();

	return DnsCopyQuery(query, atype, aclass);
	}

// Copy the question part of the query into memory.
// Return the number of bytes that the query string compressed to.
int DNS_Rewriter::DnsCopyQuery(const BroString* query, uint32 qtype,
				uint32 qclass)
	{
	int len = query->Len();
	int psize = pkt_size;

	// Encode the query string.
	const char* dname = (char*) query->Bytes();
	len = dn_comp(dname, pkt + pkt_size, DNS_PKT_SIZE - pkt_size,
			dn_ptrs, last_dn_ptr);

	// Can't encode in less than 2 bytes, or about to overwrite.
	if ( len < 1 || pkt_size + len + 4 > DNS_PKT_SIZE )
		{
		warn("dn_comp couldn't encode name into packet");
		return 0;
		}

	pkt_size += len;

	// Set type.
	if ( ! WriteShortVal(qtype) )
		{
		pkt_size = psize;
		return 0;
		}

	// Set class.
	if ( ! WriteShortVal(qclass) )
		{
		pkt_size = psize;
		return 0;
		}

	return len;
	}


// PTR, NS and CNAME are all the same.
void DNS_Rewriter::DnsCopyPTR(Val* ans, const BroString* name)
	{
	DnsCopyCNAME(ans, name);
	}

// Copy an NS RR into the packet.
void DNS_Rewriter::DnsCopyNS( Val* ans, const BroString* name)
	{
	DnsCopyCNAME(ans, name);
	}

// Copy an A RR into the packet.
void DNS_Rewriter::DnsCopyA(Val* ans, uint32 addr)
	{
	int psize = pkt_size;

	// Put query part into packet.
	int len = DnsCopyQuery(ans);

	if ( ! len )
		return;

	double TTL = ans->AsRecordVal()->Lookup(4)->AsInterval();
	if ( ! WriteDoubleAsInt(TTL) )
		{
		pkt_size = psize;
		return;
		}

	// Now we put in how long the resource data is (A rec is always 4).
	if ( ! WriteShortVal(4) )
		{
		pkt_size = psize;
		return;
		}

	// Stick in the address (already in network byte order).
	if ( ! WriteVal(uint32(ntohl(addr))) )
		{
		pkt_size = psize;
		return;
		}
	}

// Copy an AAAA RR into the packet.
void DNS_Rewriter::DnsCopyAAAA(Val* ans, addr_type addr, const BroString* addrstr)
	{
	int psize = pkt_size;


	// Put query part into packet.
	int len = DnsCopyQuery(ans);
	if ( ! len || pkt_size + 6 > DNS_PKT_SIZE )
		return;

	double TTL = ans->AsRecordVal()->Lookup(4)->AsInterval();
	if ( ! WriteDoubleAsInt(TTL))
		{
		pkt_size = psize;
		return;
		}

	// Now we put in how long the resource data is (AAAA rec is always 16).
	if ( ! WriteShortVal(16) )
		{
		pkt_size = psize;
		return;
		}
#ifdef BROv6
	if ( ! WriteVal(addr) )
		{
		pkt_size = psize;
		return;
		}
#else
	uint32 addr_copy[4];
	char* addr_tmp = addrstr->Render(BroString::ESC_NONE);
	inet_pton(AF_INET6, addr_tmp, addr_copy);

	if ( ! WriteVal(addr_copy) )
		{
		pkt_size = psize;
		return;
		}

	delete addr_tmp;
#endif

	}

// Copy a CNAME RR into the packet.
void DNS_Rewriter::DnsCopyCNAME(Val* ans, const BroString* name)
	{
	int psize = pkt_size;

	// Put query part into packet.
	int len = DnsCopyQuery(ans);
	if ( ! len || pkt_size + 6 > DNS_PKT_SIZE )
		return;

	double TTL = ans->AsRecordVal()->Lookup(4)->AsInterval();
	if ( ! WriteDoubleAsInt(TTL))
		{
		pkt_size = psize;
		return;
		}

	// Resource length (domain name length in packet).
	// Have to skip till it's encoded, remember this spot.
	u_char* resource_len = pkt + pkt_size;
	pkt_size += 2;

	// Encode the domain name.
	const char* dname = (char*) name->CheckString();
	len = dn_comp(dname, pkt + pkt_size, DNS_PKT_SIZE - pkt_size,
			dn_ptrs, last_dn_ptr);

	if ( len < 1 )
		{
		pkt_size = psize;
		return;
		}

	pkt_size += len;

	// Now we put in how long the name was to encode.
	uint16 net_rdlen = htons(short(len));
	memcpy(resource_len, &net_rdlen, sizeof(uint16));
	}

// Copy a CNAME RR into the packet.
void DNS_Rewriter::DnsCopyTXT(Val* ans, const BroString* name)
	{
	int psize = pkt_size;

	// Put query part into packet.
	int len = DnsCopyQuery(ans);
	if ( ! len || pkt_size + 6 > DNS_PKT_SIZE )
		return;

	double TTL = ans->AsRecordVal()->Lookup(4)->AsInterval();
	if ( ! WriteDoubleAsInt(TTL))
		{
		pkt_size = psize;
		return;
		}

	if ( ! WriteShortVal(name->Len()+1))
		{
		pkt_size = psize;
		return;
		}

	if ( ! WriteVal(uint8(name->Len())))
		{
		pkt_size = psize;
		return;
		}

	if ( ! WriteVal(name))
		{
		pkt_size = psize;
		return;
		}

	}

// Copy an MX RR into the packet.
void DNS_Rewriter::DnsCopyMX(Val* ans, const BroString* name, uint32 preference)
	{
	int psize = pkt_size;

	// Put query part into packet.
	int len = DnsCopyQuery(ans);

	if ( ! len || pkt_size + len + 6 > DNS_PKT_SIZE )
		{
		warn("DnsCopyMX: packet too large");
		return;
		}

	double TTL = ans->AsRecordVal()->Lookup(4)->AsInterval();
	if ( ! WriteDoubleAsInt(TTL) )
		{
		pkt_size = psize;
		warn("DnsCopyMX: packet too large");
		return;
		}

	// Resource length (domain name length in packet).
	// Have to skip till it's, remember this spot.
	u_char* resource_len = pkt + pkt_size;
	pkt_size += 2;

	if ( ! WriteShortVal(preference))
		{
		pkt_size = psize;
		warn("DnsCopyMX: packet too large");
		return;
		}

	// Encode the domain name.
	const char* dname = (char*) name->CheckString();
	len += dn_comp(dname, pkt + pkt_size, DNS_PKT_SIZE - pkt_size,
			dn_ptrs, last_dn_ptr);

	if ( len < 1 )
		{
		pkt_size = psize;
		warn("DnsCopyMX: packet too large");
		return;
		}

	pkt_size += len;

	// 2 bytes for the preference size above.
	len += 2;

	// Now we put in how long the name was to encode.
	uint16 net_rdlen = htons(short(len));
	memcpy(resource_len, &net_rdlen, sizeof(uint16));
	}

// Copy an SOA RR into the packet.
void DNS_Rewriter::DnsCopySOA(Val* ans, Val* soa)
	{
	u_char* resource_len;
	int resource_offset = 0;
	int psize = pkt_size;

	const RecordVal* soa_rec = soa->AsRecordVal();

	const BroString* mname = soa_rec->Lookup(0)->AsString();
	const BroString* rname = soa_rec->Lookup(1)->AsString();
	uint32 serial = soa_rec->Lookup(2)->AsCount();
	double refresh = soa_rec->Lookup(3)->AsInterval();
	double retry = soa_rec->Lookup(4)->AsInterval();
	double expire = soa_rec->Lookup(5)->AsInterval();
	double minimum = soa_rec->Lookup(6)->AsInterval();

	// Put query part into packet.
	int len = DnsCopyQuery(ans);

	if ( ! len || len + 6 > DNS_PKT_SIZE )
		return;

	double TTL = ans->AsRecordVal()->Lookup(4)->AsInterval();
	if ( ! WriteDoubleAsInt(TTL) )
		{
		pkt_size = psize;
		return;
		}

	// Resource length: have to skip till it's encoded.
	// Remember this spot and offset.
	resource_len = pkt + pkt_size;
	pkt_size += 2;

	// Start counting from here (after rdlength).
	resource_offset = pkt_size;

	// Encode the domain name.
	const char* dname = (char*) mname->CheckString();
	len = dn_comp(dname, pkt + pkt_size, DNS_PKT_SIZE - pkt_size,
			dn_ptrs, last_dn_ptr);

	if ( len < 1 )
		{
		pkt_size = psize;
		return;
		}

	pkt_size += len;

	// Encode the domain name.
	dname = (char*) rname->CheckString();
	len = dn_comp(dname, pkt + pkt_size, DNS_PKT_SIZE - pkt_size,
			dn_ptrs, last_dn_ptr);
	if ( len < 1 )
		{
		pkt_size = psize;
		return;
		}

	pkt_size += len;

	if ( ! WriteVal(serial) || ! WriteDoubleAsInt(refresh) ||
	     ! WriteDoubleAsInt(retry) || ! WriteDoubleAsInt(expire) ||
	     ! WriteDoubleAsInt(minimum) )
		{
		pkt_size = psize;
		return;
		}

	// Now we put in how long this packet was.
	uint16 net_rdlen = htons(short(pkt_size - resource_offset));
	memcpy(resource_len, &net_rdlen, sizeof(uint16));
	}

void DNS_Rewriter::DnsCopyEDNSaddl(Val* ans)
	{
	const RecordVal* ans_rec = ans->AsRecordVal();

	int ans_type = ans_rec->Lookup(0)->AsCount();
	// BroString* query_name = ans_rec->Lookup(1)->AsString();
	int atype = ans_rec->Lookup(2)->AsCount();
	int aclass = ans_rec->Lookup(3)->AsCount();
	int return_error = ans_rec->Lookup(4)->AsCount();
	int version = ans_rec->Lookup(5)->AsCount();
	int z = ans_rec->Lookup(6)->AsCount();
	double ttl = ans_rec->Lookup(7)->AsInterval();
	int is_query = ans_rec->Lookup(8)->AsCount();

	int rcode = return_error;
	int ecode = 0;

	int psize = pkt_size;

	if ( return_error > 0xff )
		{
		rcode &= 0xff;
		ecode = return_error >> 8;
		}

	// Stick the version onto the ecode.
	ecode = (ecode << 8) | version;

	// Write fixed part of OPT RR
	// Name '0'.
	memset(pkt + pkt_size, 0, 1);
	++pkt_size;

	// Type (either 29 or 41).
	if ( ! WriteShortVal(atype) )
		{
		pkt_size = psize;
		return;
		}

	// UDP playload size
	if ( ! WriteShortVal(aclass) )
		{
		pkt_size = psize;
		return;
		}

	// Extended rcode + version.
	if ( ! WriteShortVal(ecode) )
		{
		pkt_size = psize;
		return;
		}

	// Z field.
	if ( ! WriteShortVal(z) )
		{
		pkt_size = psize;
		return;
		}

	// Data length (XXX:for now its zero!).
	if ( ! WriteShortVal(0) )
		{
		pkt_size = psize;
		return;
		}

	// Don't write data (XXX:we don't have it!).
	}

// Does this packet match the current packet being worked on?
int DNS_Rewriter::DnsPktMatch(Val* msg)
	{
	return msg->AsRecordVal()->Lookup(0)->AsInt() == current_pkt_id;
	}

// Supports copying of TXT values.
int DNS_Rewriter::WriteVal(const BroString* val)
	{
	int n = val->Len();

        if ( pkt_size + n > DNS_PKT_SIZE )
		{
		warn("WriteVal: couldn't write data into packet");
		return 0;
		}

        char* new_val = val->Render(BroString::ESC_NONE);
        memcpy(pkt + pkt_size, new_val, n);
        pkt_size += n;

        delete[] new_val;

        return n;
	}

int DNS_Rewriter::WriteVal(const uint32* val)
	{
	if ( pkt_size + 16 > DNS_PKT_SIZE )
		{
		warn("WriteVal: couldn't write data into packet");
		return 0;
		}

	memcpy(pkt + pkt_size, &val[0], sizeof(uint32)); pkt_size += 4;
	memcpy(pkt + pkt_size, &val[1], sizeof(uint32)); pkt_size += 4;
	memcpy(pkt + pkt_size, &val[2], sizeof(uint32)); pkt_size += 4;
	memcpy(pkt + pkt_size, &val[3], sizeof(uint32)); pkt_size += 4;

	return sizeof(uint32) * 4;
	}

// Write a 32 bit value given in host order to the packet.
int DNS_Rewriter::WriteVal(uint32 val)
	{
	if ( pkt_size + 4 > DNS_PKT_SIZE )
		{
		warn("WriteVal: couldn't write data into packet");
		return 0;
		}

	uint32 net_val = htonl(val);
	memcpy(pkt + pkt_size, &net_val, sizeof(uint32));
	pkt_size += 4;

	return sizeof(uint32);
	}

// Write a 16 bit value given in host order to the packet.
int DNS_Rewriter::WriteVal(uint16 val)
	{
	if ( pkt_size + 2 > DNS_PKT_SIZE )
		{
		warn("WriteShortVal: couldn't write data into packet");
		return 0;
		}

	uint16 net_val = htons(val);
	memcpy(pkt + pkt_size, &net_val, sizeof(uint16));
	pkt_size += 2;

	return sizeof(uint16);
	}

// Write a 8 bit value given in host order to the packet.
int DNS_Rewriter::WriteVal(uint8 val)
	{
	if ( pkt_size + 1 > DNS_PKT_SIZE )
		{
		warn("WriteVal: couldn't write data into packet");
		return 0;
		}

	memcpy(pkt + pkt_size, &val, sizeof(uint8));
	pkt_size += sizeof(uint8);

	return sizeof(uint8);
	}
