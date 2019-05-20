// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_ARP_ARP_H
#define ANALYZER_PROTOCOL_ARP_ARP_H

#include "zeek-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif

#ifndef arp_pkthdr
#define arp_pkthdr arphdr
#endif

#include "NetVar.h"

class Packet;

extern "C" {
#include <pcap.h>
}

namespace analyzer { namespace arp {

class ARP_Analyzer : public BroObj {
public:
	ARP_Analyzer();
	~ARP_Analyzer() override;

	void NextPacket(double t, const Packet* pkt);

	void Describe(ODesc* d) const override;
	void RREvent(EventHandlerPtr e, const u_char* src, const u_char* dst,
			const char* spa, const char* sha,
			const char* tpa, const char* tha);

protected:
	AddrVal* ConstructAddrVal(const void* addr);
	StringVal* EthAddrToStr(const u_char* addr);
	void BadARP(const struct arp_pkthdr* hdr, const char* string);
	void Corrupted(const char* string);
};

} } // namespace analyzer::* 

#endif
