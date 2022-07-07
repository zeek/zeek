// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Frag.h"

#include "zeek/zeek-config.h"

#include "zeek/Hash.h"
#include "zeek/IP.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/session/Manager.h"

constexpr uint32_t MIN_ACCEPTABLE_FRAG_SIZE = 64;
constexpr uint32_t MAX_ACCEPTABLE_FRAG_SIZE = 64000;

namespace zeek::detail
	{

FragTimer::~FragTimer()
	{
	if ( f )
		f->ClearTimer();
	}

void FragTimer::Dispatch(double t, bool /* is_expire */)
	{
	if ( f )
		f->Expire(t);
	else
		reporter->InternalWarning("fragment timer dispatched w/o reassembler");
	}

FragReassembler::FragReassembler(session::Manager* arg_s, const std::shared_ptr<IP_Hdr>& ip,
                                 const u_char* pkt, const FragReassemblerKey& k, double t)
	: Reassembler(0, REASSEM_FRAG)
	{
	s = arg_s;
	key = k;

	const struct ip* ip4 = ip->IP4_Hdr();
	if ( ip4 )
		{
		proto_hdr_len = ip->HdrLen();
		proto_hdr = new u_char[64]; // max IP header + slop
		// Don't do a structure copy - need to pick up options, too.
		memcpy((void*)proto_hdr, (const void*)ip4, proto_hdr_len);
		}
	else
		{
		proto_hdr_len = ip->HdrLen() - 8; // minus length of fragment header
		proto_hdr = new u_char[proto_hdr_len];
		memcpy(proto_hdr, ip->IP6_Hdr(), proto_hdr_len);
		}

	reassembled_pkt = nullptr;
	frag_size = 0; // flag meaning "not known"
	next_proto = ip->NextProto();

	if ( frag_timeout != 0.0 )
		{
		expire_timer = new FragTimer(this, t + frag_timeout);
		timer_mgr->Add(expire_timer);
		}
	else
		expire_timer = nullptr;

	AddFragment(t, ip, pkt);
	}

FragReassembler::~FragReassembler()
	{
	DeleteTimer();
	delete[] proto_hdr;
	}

void FragReassembler::AddFragment(double t, const std::shared_ptr<IP_Hdr>& ip, const u_char* pkt)
	{
	const struct ip* ip4 = ip->IP4_Hdr();

	if ( ip4 )
		{
		if ( ip4->ip_p != ((const struct ip*)proto_hdr)->ip_p ||
		     ip4->ip_hl != ((const struct ip*)proto_hdr)->ip_hl )
			// || ip4->ip_tos != proto_hdr->ip_tos
			// don't check TOS, there's at least one stack that actually
			// uses different values, and it's hard to see an associated
			// attack.
			s->Weird("fragment_protocol_inconsistency", ip.get());
		}
	else
		{
		if ( ip->NextProto() != next_proto || ip->HdrLen() - 8 != proto_hdr_len )
			s->Weird("fragment_protocol_inconsistency", ip.get());
		// TODO: more detailed unfrag header consistency checks?
		}

	if ( ip->DF() )
		// Linux MTU discovery for UDP can do this, for example.
		s->Weird("fragment_with_DF", ip.get());

	uint16_t offset = ip->FragOffset();
	uint32_t len = ip->TotalLen();
	uint16_t hdr_len = ip->HdrLen();

	if ( len < hdr_len )
		{
		s->Weird("fragment_protocol_inconsistency", ip.get());
		return;
		}

	uint64_t upper_seq = offset + len - hdr_len;

	if ( ! offset )
		// Make sure to use the first fragment header's next field.
		next_proto = ip->NextProto();

	if ( ! ip->MF() )
		{
		// Last fragment.
		if ( frag_size == 0 )
			frag_size = upper_seq;

		else if ( upper_seq != frag_size )
			{
			s->Weird("fragment_size_inconsistency", ip.get());

			if ( upper_seq > frag_size )
				frag_size = upper_seq;
			}
		}

	else if ( len < MIN_ACCEPTABLE_FRAG_SIZE )
		s->Weird("excessively_small_fragment", ip.get());

	if ( upper_seq > MAX_ACCEPTABLE_FRAG_SIZE )
		s->Weird("excessively_large_fragment", ip.get());

	if ( frag_size && upper_seq > frag_size )
		{
		// This can happen if we receive a fragment that's *not*
		// the last fragment, but still imputes a size that's
		// larger than the size we derived from a previously-seen
		// "last fragment".

		s->Weird("fragment_size_inconsistency", ip.get());
		frag_size = upper_seq;
		}

	// Do we need to check for consistent options?  That's tricky
	// for things like LSRR that get modified in route.

	// Remove header.
	pkt += hdr_len;
	len -= hdr_len;

	NewBlock(run_state::network_time, offset, len, pkt);
	}

void FragReassembler::Weird(const char* name) const
	{
	unsigned int version = ((const ip*)proto_hdr)->ip_v;

	if ( version == 4 )
		{
		IP_Hdr hdr((const ip*)proto_hdr, false);
		s->Weird(name, &hdr);
		}

	else if ( version == 6 )
		{
		IP_Hdr hdr((const ip6_hdr*)proto_hdr, false, proto_hdr_len);
		s->Weird(name, &hdr);
		}

	else
		{
		reporter->InternalWarning("Unexpected IP version in FragReassembler");
		reporter->Weird(name);
		}
	}

void FragReassembler::Overlap(const u_char* b1, const u_char* b2, uint64_t n)
	{
	if ( memcmp((const void*)b1, (const void*)b2, n) )
		Weird("fragment_inconsistency");
	else
		Weird("fragment_overlap");
	}

void FragReassembler::BlockInserted(DataBlockMap::const_iterator /* it */)
	{
	auto it = block_list.Begin();

	if ( it->second.seq > 0 || ! frag_size )
		// For sure don't have it all yet.
		return;

	auto next = std::next(it);

	// We might have it all - look for contiguous all the way.
	while ( next != block_list.End() )
		{
		if ( it->second.upper != next->second.seq )
			break;

		++it;
		++next;
		}

	const auto& last = block_list.LastBlock();

	if ( next != block_list.End() )
		{
		// We have a hole.
		if ( it->second.upper >= frag_size )
			{
			// We're stuck.  The point where we stopped is
			// contiguous up through the expected end of
			// the fragment, but there's more stuff still
			// beyond it, which is not contiguous.  This
			// can happen for benign reasons when we're
			// intermingling parts of two fragmented packets.
			Weird("fragment_size_inconsistency");

			// We decide to analyze the contiguous portion now.
			// Extend the fragment up through the end of what
			// we have.
			frag_size = it->second.upper;
			}
		else
			return;
		}

	else if ( last.upper > frag_size )
		{
		Weird("fragment_size_inconsistency");
		frag_size = last.upper;
		}

	else if ( last.upper < frag_size )
		// Missing the tail.
		return;

	// We have it all.  Compute the expected size of the fragment.
	uint64_t n = proto_hdr_len + frag_size;

	// It's possible that we have blocks associated with this fragment
	// that exceed this size, if we saw MF fragments (which don't lead
	// to us setting frag_size) that went beyond the size indicated by
	// the final, non-MF fragment.  This can happen for benign reasons
	// due to intermingling of fragments from an older datagram with those
	// for a more recent one.

	u_char* pkt = new u_char[n];
	memcpy((void*)pkt, (const void*)proto_hdr, proto_hdr_len);

	u_char* pkt_start = pkt;

	pkt += proto_hdr_len;

	for ( it = block_list.Begin(); it != block_list.End(); ++it )
		{
		const auto& b = it->second;

		if ( it != block_list.Begin() )
			{
			const auto& prev = std::prev(it)->second;

			// If we're above a hole, stop.  This can happen because
			// the logic above regarding a hole that's above the
			// expected fragment size.
			if ( prev.upper < b.seq )
				break;
			}

		if ( b.upper > n )
			{
			reporter->InternalWarning("bad fragment reassembly");
			DeleteTimer();
			Expire(run_state::network_time);
			delete[] pkt_start;
			return;
			}

		memcpy(&pkt[b.seq], b.block, b.upper - b.seq);
		}

	reassembled_pkt.reset();

	unsigned int version = ((const struct ip*)pkt_start)->ip_v;

	if ( version == 4 )
		{
		struct ip* reassem4 = (struct ip*)pkt_start;
		reassem4->ip_len = htons(frag_size + proto_hdr_len);
		reassembled_pkt = std::make_shared<IP_Hdr>(reassem4, true, true);
		DeleteTimer();
		}

	else if ( version == 6 )
		{
		struct ip6_hdr* reassem6 = (struct ip6_hdr*)pkt_start;
		reassem6->ip6_plen = htons(frag_size + proto_hdr_len - 40);
		const IPv6_Hdr_Chain* chain = new IPv6_Hdr_Chain(reassem6, next_proto, n);
		reassembled_pkt = std::make_shared<IP_Hdr>(reassem6, true, n, chain, true);
		DeleteTimer();
		}

	else
		{
		reporter->InternalWarning("bad IP version in fragment reassembly: %d", version);
		delete[] pkt_start;
		}
	}

void FragReassembler::Expire(double t)
	{
	block_list.Clear();
	expire_timer->ClearReassembler();
	expire_timer = nullptr; // timer manager will delete it

	fragment_mgr->Remove(this);
	}

void FragReassembler::DeleteTimer()
	{
	if ( expire_timer )
		{
		expire_timer->ClearReassembler();
		timer_mgr->Cancel(expire_timer);
		expire_timer = nullptr; // timer manager will delete it
		}
	}

FragmentManager::~FragmentManager()
	{
	Clear();
	}

FragReassembler* FragmentManager::NextFragment(double t, const std::shared_ptr<IP_Hdr>& ip,
                                               const u_char* pkt)
	{
	uint32_t frag_id = ip->ID();
	FragReassemblerKey key = std::make_tuple(ip->SrcAddr(), ip->DstAddr(), frag_id);

	FragReassembler* f = nullptr;
	auto it = fragments.find(key);
	if ( it != fragments.end() )
		f = it->second;

	if ( ! f )
		{
		f = new FragReassembler(session_mgr, ip, pkt, key, t);
		fragments[key] = f;
		if ( fragments.size() > max_fragments )
			max_fragments = fragments.size();
		return f;
		}

	f->AddFragment(t, ip, pkt);
	return f;
	}

void FragmentManager::Clear()
	{
	for ( const auto& entry : fragments )
		Unref(entry.second);

	fragments.clear();
	}

void FragmentManager::Remove(detail::FragReassembler* f)
	{
	if ( ! f )
		return;

	if ( fragments.erase(f->Key()) == 0 )
		reporter->InternalWarning("fragment reassembler not in dict");

	Unref(f);
	}

	} // namespace zeek::detail
