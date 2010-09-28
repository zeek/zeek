// $Id: PacketFilter.cc 967 2005-01-03 07:19:06Z vern $

#include "PacketFilter.h"

void PacketFilter::AddSrc(addr_type src, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	src_filter.Insert(src, NUM_ADDR_WORDS * 32, f);
	}

void PacketFilter::AddSrc(Val* src, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	src_filter.Insert(src, f);
	}

void PacketFilter::AddDst(addr_type dst, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	dst_filter.Insert(dst, NUM_ADDR_WORDS * 32, f);
	}

void PacketFilter::AddDst(Val* dst, uint32 tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = uint32(probability * RAND_MAX);
	dst_filter.Insert(dst, f);
	}

bool PacketFilter::RemoveSrc(addr_type src)
	{
	return src_filter.Remove(src, NUM_ADDR_WORDS * 32) != 0;
	}

bool PacketFilter::RemoveSrc(Val* src)
	{
	return src_filter.Remove(src) != NULL;
	}

bool PacketFilter::RemoveDst(addr_type dst)
	{
	return dst_filter.Remove(dst, NUM_ADDR_WORDS * 32) != NULL;
	}

bool PacketFilter::RemoveDst(Val* dst)
	{
	return dst_filter.Remove(dst) != NULL;
	}

bool PacketFilter::Match(const IP_Hdr* ip, int len, int caplen)
	{
#ifdef BROv6
	Filter* f = (Filter*) src_filter.Lookup(ip->SrcAddr(),
						NUM_ADDR_WORDS * 32);
#else
	Filter* f = (Filter*) src_filter.Lookup(*ip->SrcAddr(),
						NUM_ADDR_WORDS * 32);
#endif
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

#ifdef BROv6
	f = (Filter*) dst_filter.Lookup(ip->DstAddr(), NUM_ADDR_WORDS * 32);
#else
	f = (Filter*) dst_filter.Lookup(*ip->DstAddr(), NUM_ADDR_WORDS * 32);
#endif
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
		const struct ip* ip4 = ip.IP4_Hdr();

		int ip_hdr_len = ip4->ip_hl * 4;
		len -= ip_hdr_len;	// remove IP header
		caplen -= ip_hdr_len;

		if ( (unsigned int) len < sizeof(struct tcphdr) ||
		     (unsigned int) caplen < sizeof(struct tcphdr) )
			// Packet too short, will be dropped anyway.
			return false;

		const struct tcphdr* tp =
			(const struct tcphdr*) ((u_char*) ip4 + ip_hdr_len);

		if ( tp->th_flags & f.tcp_flags )
			 // At least one of the flags is set, so don't drop
			return false;
		}

	return uint32(random()) < f.probability;
	}
