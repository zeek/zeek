#warning                                                                                           \
	"Remove in v5.1. This analyzer has been moved to packet analysis, use 'zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h'."

#include "zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h"

namespace zeek::analyzer::udp
	{

using UDP_Analyzer
	[[deprecated("Remove in v5.1. Use zeek::packet_analysis::UDP::UDPSessionAdapter.")]] =
		zeek::packet_analysis::UDP::UDPSessionAdapter;

	} // namespace zeek::analyzer::udp
