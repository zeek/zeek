// Provides some very limited but fast packet filter mechanisms

#ifndef PACKETFILTER_H
#define PACKETFILTER_H

#include "IP.h"
#include "PrefixTable.h"

class PacketFilter {
public:
	PacketFilter(bool arg_default)	{ default_match = arg_default; }
	~PacketFilter()	{}

	// Drops all packets from a particular source (which may be given
	// as an AddrVal or a SubnetVal) which hasn't any of TCP flags set
	// (TH_*) with the given probability (from 0..MAX_PROB).
	void AddSrc(const IPAddr& src, uint32 tcp_flags, double probability);
	void AddSrc(Val* src, uint32 tcp_flags, double probability);
	void AddDst(const IPAddr& src, uint32 tcp_flags, double probability);
	void AddDst(Val* src, uint32 tcp_flags, double probability);

	// Removes the filter entry for the given src/dst
	// Returns false if filter doesn not exist.
	bool RemoveSrc(const IPAddr& src);
	bool RemoveSrc(Val* dst);
	bool RemoveDst(const IPAddr& dst);
	bool RemoveDst(Val* dst);

	// Returns true if packet matches a drop filter
	bool Match(const IP_Hdr* ip, int len, int caplen);

private:
	struct Filter {
		uint32 tcp_flags;
		uint32 probability;
	};

	bool MatchFilter(const Filter& f, const IP_Hdr& ip, int len, int caplen);

	bool default_match;
	PrefixTable src_filter;
	PrefixTable dst_filter;
};

#endif
