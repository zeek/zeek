// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_GOOSE_GOOSE_H
#define ANALYZER_PROTOCOL_GOOSE_GOOSE_H

#include "bro-config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#elif defined(HAVE_SYS_ETHERNET_H)
#include <sys/ethernet.h>
#elif defined(HAVE_NETINET_IF_ETHER_H)
#include <netinet/if_ether.h>
#elif defined(HAVE_NET_ETHERTYPES_H)
#include <net/ethertypes.h>
#endif

#include "NetVar.h"

class Packet;

extern "C" {
#include <pcap.h>
}

namespace analyzer { namespace goose {

class GOOSE_Analyzer : public BroObj {
public:
	GOOSE_Analyzer();
	virtual ~GOOSE_Analyzer();

	void NextPacket(double t, const Packet* pkt);

	void Describe(ODesc* d) const;
	void GeneratePDUEvent(RecordVal * packetInfo, RecordVal * gPdu);

	static StringVal* EthAddrToStr(const u_char* addr);

protected:
	void Corrupted(const char* string);
};

} } // namespace analyzer::* 

#endif
