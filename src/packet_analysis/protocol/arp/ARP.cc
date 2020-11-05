// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "zeek/packet_analysis/protocol/arp/ARP.h"

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif

#include "zeek/Event.h"

#include "packet_analysis/protocol/arp/events.bif.h"

using namespace zeek::packet_analysis::ARP;

ARPAnalyzer::ARPAnalyzer()
	: zeek::packet_analysis::Analyzer("ARP")
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

bool ARPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet)
	{
	packet->l3_proto = L3_ARP;

	// Check whether the header is complete.
	if ( sizeof(struct arp_pkthdr) > len )
		{
		Weird("truncated_ARP", packet);
		return false;
		}

	// Check whether the packet is OK ("inspired" in tcpdump's print-arp.c).
	auto ah = (const struct arp_pkthdr*) data;

	// Check the size.
	size_t min_length = (ar_tpa(ah) - (char*) data) + ah->ar_pln;
	if ( min_length > len )
		{
		Weird("truncated_ARP", packet);
		return false;
		}

	// Check the address description fields.
	switch ( ntohs(ah->ar_hrd) ) {
		case ARPHRD_ETHER:
			if ( ah->ar_hln != 6 )
				{
				// don't know how to handle the opcode
				BadARPEvent(ah, "corrupt-arp-header (hrd=%i, hln=%i)",
						ntohs(ah->ar_hrd), ah->ar_hln);
				return false;
				}
			break;

		default:
			{
			// don't know how to proceed
			BadARPEvent(ah, "unknown-arp-hw-address (hrd=%i)", ntohs(ah->ar_hrd));
			return false;
			}
		}

	// Note: We don't support IPv6 addresses.
	switch ( ntohs(ah->ar_pro) ) {
		case ETHERTYPE_IP:
			if ( ah->ar_pln != 4 )
				{
				// don't know how to handle the opcode
				BadARPEvent(ah,"corrupt-arp-header (pro=%i, pln=%i)",
						ntohs(ah->ar_pro), ah->ar_pln);
				return false;
				}
			break;

		default:
			{
			// don't know how to proceed
			BadARPEvent(ah,"unknown-arp-proto-address (pro=%i)", ntohs(ah->ar_pro));
			return false;
			}
		}


	// Check MAC src address = ARP sender MAC address.
	if ( memcmp(packet->l2_src, ar_sha(ah), ah->ar_hln) != 0 )
		{
		BadARPEvent(ah, "weird-arp-sha");
		return false;
		}

	// Check the code is supported.
	switch ( ntohs(ah->ar_op) ) {
		case ARPOP_REQUEST:
			RequestReplyEvent(arp_request, packet->l2_src, packet->l2_dst,
					ar_spa(ah), ar_sha(ah), ar_tpa(ah), ar_tha(ah));
			break;

		case ARPOP_REPLY:
			RequestReplyEvent(arp_reply, packet->l2_src, packet->l2_dst,
					ar_spa(ah), ar_sha(ah), ar_tpa(ah), ar_tha(ah));
			break;

		case ARPOP_REVREQUEST:
		case ARPOP_REVREPLY:
		case ARPOP_INVREQUEST:
		case ARPOP_INVREPLY:
			{
			// don't know how to handle the opcode
			BadARPEvent(ah, "unimplemented-arp-opcode (%i)", ntohs(ah->ar_op));
			return false;
			}

		default:
			{
			// invalid opcode
			BadARPEvent(ah, "invalid-arp-opcode (opcode=%i)", ntohs(ah->ar_op));
			return false;
			}
		}


	// Leave packet analyzer land
	return true;
	}

zeek::AddrValPtr ARPAnalyzer::ToAddrVal(const void* addr)
	{
	//Note: We only handle IPv4 addresses.
	return zeek::make_intrusive<zeek::AddrVal>(*(const uint32_t*) addr);
	}

zeek::StringValPtr ARPAnalyzer::ToEthAddrStr(const u_char* addr)
	{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
			 addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return zeek::make_intrusive<zeek::StringVal>(buf);
	}

void ARPAnalyzer::BadARPEvent(const struct arp_pkthdr* hdr, const char* fmt, ...)
	{
	if ( ! bad_arp )
		return;

	char msg[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	event_mgr.Enqueue(bad_arp,
			ToAddrVal(ar_spa(hdr)), ToEthAddrStr((const u_char*) ar_sha(hdr)),
			ToAddrVal(ar_tpa(hdr)), ToEthAddrStr((const u_char*) ar_tha(hdr)),
			zeek::make_intrusive<zeek::StringVal>(msg));
	}

void ARPAnalyzer::RequestReplyEvent(EventHandlerPtr e, const u_char *src, const u_char *dst,
		const char *spa, const char *sha, const char *tpa, const char *tha)
	{
	if ( ! e )
		return;

	event_mgr.Enqueue(e, ToEthAddrStr(src), ToEthAddrStr(dst),
			ToAddrVal(spa), ToEthAddrStr((const u_char*) sha),
			ToAddrVal(tpa),	ToEthAddrStr((const u_char*) tha));
	}
