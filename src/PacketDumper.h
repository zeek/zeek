// See the file "COPYING" in the main distribution directory for copyright.

#ifndef packetdumper_h
#define packetdumper_h

using namespace std;

#include <queue>
#include <set>

#include <pcap.h>

class PacketDumper {
public:
	PacketDumper(pcap_dumper_t* pkt_dump);

	void DumpPacket(const struct pcap_pkthdr* hdr,
			const u_char* pkt, int len);

protected:
	pcap_dumper_t* pkt_dump;
	struct timeval last_timestamp;

	void SortTimeStamp(struct timeval* timestamp);
};

struct IP_ID {
	uint32 ip, id;
};

struct ltipid {
	bool operator()(IP_ID id1, IP_ID id2) const
		{
		return id1.ip != id2.ip ? (id1.ip < id2.ip) :
					  (id1.id < id2.id);
		}
};

typedef set<IP_ID, ltipid> IP_IDSet;
uint16 NextIP_ID(const uint32 src_addr, const uint16 id);

#endif
