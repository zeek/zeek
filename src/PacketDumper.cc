// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"
#include "PacketDumper.h"
#include "Reporter.h"
#include "util.h"
#include "iosource/PktDumper.h"

namespace zeek::detail {

PacketDumper::PacketDumper(pcap_dumper_t* arg_pkt_dump)
	{
	last_timestamp.tv_sec = last_timestamp.tv_usec = 0;

	pkt_dump = arg_pkt_dump;
	if ( ! pkt_dump )
		zeek::reporter->InternalError("PacketDumper: nil dump file");
	}

void PacketDumper::DumpPacket(const struct pcap_pkthdr* hdr,
				const u_char* pkt, int len)
	{
	if ( pkt_dump )
		{
		struct pcap_pkthdr h = *hdr;
		h.caplen = len;
		if ( h.caplen > hdr->caplen )
			zeek::reporter->InternalError("bad modified caplen");

		pcap_dump((u_char*) pkt_dump, &h, pkt);
		}
	}

void PacketDumper::SortTimeStamp(struct timeval* timestamp)
	{
	if ( zeek::util::time_compare(&last_timestamp, timestamp) > 0 )
		*timestamp = last_timestamp;
	else
		last_timestamp = *timestamp;
	}

} // namespace zeek::detail
