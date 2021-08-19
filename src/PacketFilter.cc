#include "zeek/PacketFilter.h"

#include "zeek/IP.h"

namespace zeek::detail
	{

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

void PacketFilter::AddSrc(const IPAddr& src, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(util::detail::max_random());
	auto prev = static_cast<Filter*>(src_filter.Insert(src, 128, f));
	delete prev;
	}

void PacketFilter::AddSrc(Val* src, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(util::detail::max_random());
	auto prev = static_cast<Filter*>(src_filter.Insert(src, f));
	delete prev;
	}

void PacketFilter::AddDst(const IPAddr& dst, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(util::detail::max_random());
	auto prev = static_cast<Filter*>(dst_filter.Insert(dst, 128, f));
	delete prev;
	}

void PacketFilter::AddDst(Val* dst, uint32_t tcp_flags, double probability)
	{
	Filter* f = new Filter;
	f->tcp_flags = tcp_flags;
	f->probability = probability * static_cast<double>(util::detail::max_random());
	auto prev = static_cast<Filter*>(dst_filter.Insert(dst, f));
	delete prev;
	}

bool PacketFilter::RemoveSrc(const IPAddr& src)
	{
	auto f = static_cast<Filter*>(src_filter.Remove(src, 128));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::RemoveSrc(Val* src)
	{
	auto f = static_cast<Filter*>(src_filter.Remove(src));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::RemoveDst(const IPAddr& dst)
	{
	auto f = static_cast<Filter*>(dst_filter.Remove(dst, 128));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::RemoveDst(Val* dst)
	{
	auto f = static_cast<Filter*>(dst_filter.Remove(dst));
	delete f;
	return f != nullptr;
	}

bool PacketFilter::Match(const std::shared_ptr<IP_Hdr>& ip, int len, int caplen)
	{
	Filter* f = (Filter*)src_filter.Lookup(ip->SrcAddr(), 128);
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

	f = (Filter*)dst_filter.Lookup(ip->DstAddr(), 128);
	if ( f )
		return MatchFilter(*f, *ip, len, caplen);

	return default_match;
	}

bool PacketFilter::MatchFilter(const Filter& f, const IP_Hdr& ip, int len, int caplen)
	{
	if ( ip.NextProto() == IPPROTO_TCP && f.tcp_flags )
		{
		// Caution! The packet sanity checks have not been performed yet
		int ip_hdr_len = ip.HdrLen();
		len -= ip_hdr_len; // remove IP header
		caplen -= ip_hdr_len;

		if ( (unsigned int)len < sizeof(struct tcphdr) ||
		     (unsigned int)caplen < sizeof(struct tcphdr) )
			// Packet too short, will be dropped anyway.
			return false;

		const struct tcphdr* tp = (const struct tcphdr*)ip.Payload();

		if ( tp->th_flags & f.tcp_flags )
			// At least one of the flags is set, so don't drop
			return false;
		}

	return util::detail::random_number() < f.probability;
	}

	} // namespace zeek::detail
