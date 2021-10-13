#warning                                                                                           \
	"Remove in v5.1. This analyzer has been moved to packet analysis, use 'zeek/packet_analysis/protocol/icmp/ICMPSessionAdapter.h' and/or 'zeek/packet_analysis/protocol/icmp/ICMP.h'."

#include "zeek/packet_analysis/protocol/icmp/ICMP.h"
#include "zeek/packet_analysis/protocol/icmp/ICMPSessionAdapter.h"

namespace zeek::analyzer::icmp
	{

using ICMP_Analyzer
	[[deprecated("Remove in v5.1. Use zeek::packet_analysis::ICMP::ICMPSessionAdapter.")]] =
		zeek::packet_analysis::ICMP::ICMPSessionAdapter;
constexpr auto ICMP4_counterpart
	[[deprecated("Remove in v5.1. Use zeek::packet_analysis::ICMP::ICMP4_counterpart.")]] =
		zeek::packet_analysis::ICMP::ICMP4_counterpart;
constexpr auto ICMP6_counterpart
	[[deprecated("Remove in v5.1. Use zeek::packet_analysis::ICMP::ICMP6_counterpart.")]] =
		zeek::packet_analysis::ICMP::ICMP6_counterpart;

	} // namespace zeek::analyzer::icmp
