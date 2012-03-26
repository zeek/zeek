#include "PacketFilter.h"

void PacketFilter::AddSrc(const IPAddr& src, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	src_filter.Insert(src, 128, f);
	}

void PacketFilter::AddSrc(Val* src, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	src_filter.Insert(src, f);
	}

void PacketFilter::AddDst(const IPAddr& dst, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	dst_filter.Insert(dst, 128, f);
	}

void PacketFilter::AddDst(Val* dst, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	dst_filter.Insert(dst, f);
	}

bool PacketFilter::RemoveSrc(const IPAddr& src)
	{
	return src_filter.Remove(src, 128) != 0;
	}

bool PacketFilter::RemoveSrc(Val* src)
	{
	return src_filter.Remove(src) != NULL;
	}

bool PacketFilter::RemoveDst(const IPAddr& dst)
	{
	return dst_filter.Remove(dst, 128) != NULL;
	}

bool PacketFilter::RemoveDst(Val* dst)
	{
	return dst_filter.Remove(dst) != NULL;
	}

bool PacketFilter::Match(const IP_Hdr* ip, int len, int caplen)
	{
	Filter* f = (Filter*) src_filter.Lookup(ip->SrcAddr(), 128);
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

	f = (Filter*) dst_filter.Lookup(ip->DstAddr(), 128);
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

	return default_match;
	}

bool PacketFilter::MatchFilter(const Filter& f, const IP_Hdr& ip,
				int len, int caplen)
	{
	if ( ip.NextProto() == IPPROTO_TCP && f.tcp_flags )
		{
		// Caution! The packet sanity checks have not been performed yet
		int ip_hdr_len = ip.HdrLen();
		len -= ip_hdr_len;	// remove IP header
		caplen -= ip_hdr_len;

		if ( (unsigned int) len < sizeof(struct tcphdr) ||
		     (unsigned int) caplen < sizeof(struct tcphdr) )
			// Packet too short, will be dropped anyway.
			return false;

		const struct tcphdr* tp = (const struct tcphdr*) ip.Payload();

		if ( tp->th_flags & f.tcp_flags )
			 // At least one of the flags is set, so don't drop
			return false;
		}

	return uint32(bro_random()) < f.probability;
	}
