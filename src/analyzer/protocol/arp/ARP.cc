// See the file "COPYING" in the main distribution directory for copyright.

#include "ARP.h"
#include "Event.h"
#include "Reporter.h"
#include "Desc.h"

#include "events.bif.h"

namespace zeek::analyzer::arp {

ARP_Analyzer::ARP_Analyzer()
	{
	}

ARP_Analyzer::~ARP_Analyzer()
	{
	}

// Argh! FreeBSD and Linux have almost completely different net/if_arp.h .
// ... and on Solaris we are missing half of the ARPOP codes, so define
// them here as necessary:

#ifndef ARPOP_REQUEST
#define ARPOP_REQUEST    1 // ARP request.
#endif
#ifndef ARPOP_REPLY
#define ARPOP_REPLY      2 // ARP reply.
#endif
#ifndef ARPOP_PREQUEST
#define ARPOP_RREQUEST   3 // RARP request.
#endif
#ifndef ARPOP_RREPLY
#define ARPOP_RREPLY     4 // RARP reply.
#endif
#ifndef ARPOP_InREQUEST
#define ARPOP_InREQUEST  8 // InARP request.
#endif
#ifndef ARPOP_InREPLY
#define ARPOP_InREPLY    9 // InARP reply.
#endif
#ifndef ARPOP_NAK
#define ARPOP_NAK       10 // (ATM)ARP NAK.
#endif

#ifndef ar_sha
#define ar_sha(ap)  ((caddr_t((ap)+1)) + 0)
#endif

#ifndef ar_spa
#define ar_spa(ap)  ((caddr_t((ap)+1)) + (ap)->ar_hln)
#endif

#ifndef ar_tha
#define ar_tha(ap)  ((caddr_t((ap)+1)) + (ap)->ar_hln + (ap)->ar_pln)
#endif

#ifndef ar_tpa
#define ar_tpa(ap)  ((caddr_t((ap)+1)) + 2*(ap)->ar_hln + (ap)->ar_pln)
#endif

#ifndef ARPOP_REVREQUEST
#define ARPOP_REVREQUEST ARPOP_RREQUEST
#endif

#ifndef ARPOP_REVREPLY
#define ARPOP_REVREPLY ARPOP_RREPLY
#endif

#ifndef ARPOP_INVREQUEST
#define ARPOP_INVREQUEST ARPOP_InREQUEST
#endif

#ifndef ARPOP_INVREPLY
#define ARPOP_INVREPLY ARPOP_InREPLY
#endif


void ARP_Analyzer::NextPacket(double t, const zeek::Packet* pkt)
	{
	const u_char *data = pkt->data;
	// Check whether the packet is OK ("inspired" in tcpdump's print-arp.c).
	const struct arp_pkthdr* ah =
		(const struct arp_pkthdr*) (data + pkt->hdr_size);

	// Check the size.
	int min_length = (ar_tpa(ah) - (char*) (data + pkt->hdr_size)) + ah->ar_pln;
	int real_length = pkt->cap_len - pkt->hdr_size;
	if ( min_length > real_length )
		{
		Corrupted("truncated_ARP");
		return;
		}

	char errbuf[1024];

	// Check the address description fields.
	switch ( ntohs(ah->ar_hrd) ) {
	case ARPHRD_ETHER:
		if ( ah->ar_hln != 6 )
			{ // don't know how to handle the opcode
			snprintf(errbuf, sizeof(errbuf),
					"corrupt-arp-header (hrd=%i, hln=%i)",
					ntohs(ah->ar_hrd), ah->ar_hln);
			BadARP(ah, errbuf);
			return;
			}
		break;

	default:
		{ // don't know how to proceed
		snprintf(errbuf, sizeof(errbuf),
			"unknown-arp-hw-address (hrd=%i)", ntohs(ah->ar_hrd));
		BadARP(ah, errbuf);
		return;
		}
	}

	// ### Note, we don't support IPv6 addresses yet.
	switch ( ntohs(ah->ar_pro) ) {
	case ETHERTYPE_IP:
		if ( ah->ar_pln != 4 )
			{ // don't know how to handle the opcode
			snprintf(errbuf, sizeof(errbuf),
					"corrupt-arp-header (pro=%i, pln=%i)",
					ntohs(ah->ar_pro), ah->ar_pln);
			BadARP(ah, errbuf);
			return;
			}
		break;

	default:
		{ // don't know how to proceed
		snprintf(errbuf, sizeof(errbuf),
				"unknown-arp-proto-address (pro=%i)",
				ntohs(ah->ar_pro));
		BadARP(ah, errbuf);
		return;
		}
	}


	// Check MAC src address = ARP sender MAC address.
	if ( memcmp(pkt->l2_src, ar_sha(ah), ah->ar_hln) )
		{
		BadARP(ah, "weird-arp-sha");
		return;
		}

	// Check the code is supported.
	switch ( ntohs(ah->ar_op) ) {
	case ARPOP_REQUEST:
		RREvent(arp_request, pkt->l2_src, pkt->l2_dst,
				ar_spa(ah), ar_sha(ah), ar_tpa(ah), ar_tha(ah));
		break;

	case ARPOP_REPLY:
		RREvent(arp_reply, pkt->l2_src, pkt->l2_dst,
				ar_spa(ah), ar_sha(ah), ar_tpa(ah), ar_tha(ah));
		break;

	case ARPOP_REVREQUEST:
	case ARPOP_REVREPLY:
	case ARPOP_INVREQUEST:
	case ARPOP_INVREPLY:
		{ // don't know how to handle the opcode
		snprintf(errbuf, sizeof(errbuf),
			"unimplemented-arp-opcode (%i)", ntohs(ah->ar_op));
		BadARP(ah, errbuf);
		break;
		}

	default:
		{ // invalid opcode
		snprintf(errbuf, sizeof(errbuf),
			"invalid-arp-opcode (opcode=%i)", ntohs(ah->ar_op));
		BadARP(ah, errbuf);
		return;
		}
	}
	}

void ARP_Analyzer::Describe(zeek::ODesc* d) const
	{
	d->Add("<ARP analyzer>");
	d->NL();
	}

void ARP_Analyzer::BadARP(const struct arp_pkthdr* hdr, const char* msg)
	{
	if ( ! bad_arp )
		return;

	zeek::event_mgr.Enqueue(bad_arp,
	                        ToAddrVal(ar_spa(hdr)),
	                        ToEthAddrStr((const u_char*) ar_sha(hdr)),
	                        ToAddrVal(ar_tpa(hdr)),
	                        ToEthAddrStr((const u_char*) ar_tha(hdr)),
	                        zeek::make_intrusive<zeek::StringVal>(msg));
	}

void ARP_Analyzer::Corrupted(const char* msg)
	{
	zeek::reporter->Weird(msg);
	}

void ARP_Analyzer::RREvent(zeek::EventHandlerPtr e,
                           const u_char* src, const u_char *dst,
                           const char* spa, const char* sha,
                           const char* tpa, const char* tha)
	{
	if ( ! e )
		return;

	zeek::event_mgr.Enqueue(e,
	                        ToEthAddrStr(src),
	                        ToEthAddrStr(dst),
	                        ToAddrVal(spa),
	                        ToEthAddrStr((const u_char*) sha),
	                        ToAddrVal(tpa),
	                        ToEthAddrStr((const u_char*) tha));
	}

zeek::AddrVal* ARP_Analyzer::ConstructAddrVal(const void* addr)
	{ return ToAddrVal(addr).release(); }

zeek::AddrValPtr ARP_Analyzer::ToAddrVal(const void* addr)
	{
	// ### For now, we only handle IPv4 addresses.
	return zeek::make_intrusive<zeek::AddrVal>(*(const uint32_t*) addr);
	}

zeek::StringVal* ARP_Analyzer::EthAddrToStr(const u_char* addr)
	{ return ToEthAddrStr(addr).release(); }

zeek::StringValPtr ARP_Analyzer::ToEthAddrStr(const u_char* addr)
	{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return zeek::make_intrusive<zeek::StringVal>(buf);
	}

} // namespace zeek::analyzer::arp
