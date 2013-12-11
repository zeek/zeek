
#include "plugin/Plugin.h"
#include "iosource/pktsrc/Component.h"

#include "Source.h"
#include "Dumper.h"

BRO_PLUGIN_BEGIN(Bro, Pcap)
	BRO_PLUGIN_DESCRIPTION("Packet I/O via libpcap");
	BRO_PLUGIN_PKTSRC("PcapReader", "pcap", SourceComponent::BOTH, PcapSource);
	BRO_PLUGIN_PKTDUMPER("PcapTraceWriter", "pcap", PcapDumper);
BRO_PLUGIN_END
