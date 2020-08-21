#include "PacketFilter.h"
#include "IP.h"

namespace zeek::detail {

void PacketFilter::DeleteFilter(void* data)
	{
	auto f = static_cast<Filter*>(data);
	delete f;
	}

PacketFilter::PacketFilter(bool arg_default)
	{
	default_match = arg_default;
	src_filter.SetDeleteFunction(PacketFilter::DeleteFilter);
	dst_filter.SetDeleteFunction(PacketFilter::DeleteFilter);
	}

void PacketFilter::AddSrc(const zeek::IPAddr& src, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(zeek::util::detail::max_random());
	auto prev = static_cast<Filter*>(src_filter.Insert(src, 128, f));
	delete prev;
	}

void PacketFilter::AddSrc(zeek::Val* src, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(zeek::util::detail::max_random());
	auto prev = static_cast<Filter*>(src_filter.Insert(src, f));
	delete prev;
	}

void PacketFilter::AddDst(const zeek::IPAddr& dst, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(zeek::util::detail::max_random());
	auto prev = static_cast<Filter*>(dst_filter.Insert(dst, 128, f));
	delete prev;
	}

void PacketFilter::AddDst(zeek::Val* dst, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(zeek::util::detail::max_random());
	auto prev = static_cast<Filter*>(dst_filter.Insert(dst, f));
	delete prev;
	}

bool PacketFilter::RemoveSrc(const zeek::IPAddr& src)
	{
	auto f = static_cast<Filter*>(src_filter.Remove(src, 128));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::RemoveSrc(zeek::Val* src)
	{
	auto f = static_cast<Filter*>(src_filter.Remove(src));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::RemoveDst(const zeek::IPAddr& dst)
	{
	auto f = static_cast<Filter*>(dst_filter.Remove(dst, 128));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::RemoveDst(zeek::Val* dst)
	{
	auto f = static_cast<Filter*>(dst_filter.Remove(dst));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::Match(const zeek::IP_Hdr* ip, int len, int caplen)
	{
	Filter* f = (Filter*) src_filter.Lookup(ip->SrcAddr(), 128);
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

	f = (Filter*) dst_filter.Lookup(ip->DstAddr(), 128);
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

	return default_match;
	}

bool PacketFilter::MatchFilter(const Filter& f, const zeek::IP_Hdr& ip,
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

	return zeek::util::detail::random_number() < f.probability;
	}

} // namespace zeek::detail
