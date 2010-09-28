// $Id: Frag.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "util.h"
#include "Hash.h"
#include "Frag.h"
#include "NetVar.h"
#include "Sessions.h"

#define MIN_ACCEPTABLE_FRAG_SIZE 64
#define MAX_ACCEPTABLE_FRAG_SIZE 64000

FragTimer::~FragTimer()
	{
	if ( f )
		f->ClearTimer();
	}

void FragTimer::Dispatch(double t, int /* is_expire */)
	{
	if ( f )
		f->Expire(t);
	else
		internal_error("fragment timer dispatched w/o reassembler");
	}

FragReassembler::FragReassembler(NetSessions* arg_s,
			const IP_Hdr* ip, const u_char* pkt,
			uint32 frag_field, HashKey* k, double t)
: Reassembler(0, ip->DstAddr(), REASSEM_IP)
	{
	s = arg_s;
	key = k;
	const struct ip* ip4 = ip->IP4_Hdr();
	proto_hdr_len = ip4->ip_hl * 4;
	proto_hdr = (struct ip*) new u_char[64];	// max IP header + slop
	// Don't do a structure copy - need to pick up options, too.
	memcpy((void*) proto_hdr, (const void*) ip4, proto_hdr_len);

	reassembled_pkt = 0;
	frag_size = 0;	// flag meaning "not known"

	AddFragment(t, ip, pkt, frag_field);

	if ( frag_timeout != 0.0 )
		{
		expire_timer = new FragTimer(this, t + frag_timeout);
		timer_mgr->Add(expire_timer);
		}
	else
		expire_timer = 0;
	}

FragReassembler::~FragReassembler()
	{
	DeleteTimer();
	delete [] proto_hdr;
	delete reassembled_pkt;
	delete key;
	}

void FragReassembler::AddFragment(double t, const IP_Hdr* ip, const u_char* pkt,
				uint32 frag_field)
	{
	const struct ip* ip4 = ip->IP4_Hdr();

	if ( ip4->ip_p != proto_hdr->ip_p || ip4->ip_hl != proto_hdr->ip_hl )
		// || ip4->ip_tos != proto_hdr->ip_tos
		// don't check TOS, there's at least one stack that actually
		// uses different values, and it's hard to see an associated
		// attack.
		s->Weird("fragment_protocol_inconsistency", ip);

	if ( frag_field & 0x4000 )
		// Linux MTU discovery for UDP can do this, for example.
		s->Weird("fragment_with_DF", ip);

	int offset = (ntohs(ip4->ip_off) & 0x1fff) * 8;
	int len = ntohs(ip4->ip_len);
	int hdr_len = proto_hdr->ip_hl * 4;
	int upper_seq = offset + len - hdr_len;

	if ( (frag_field & 0x2000) == 0 )
		{
		// Last fragment.
		if ( frag_size == 0 )
			frag_size = upper_seq;

		else if ( upper_seq != frag_size )
			{
			s->Weird("fragment_size_inconsistency", ip);

			if ( upper_seq > frag_size )
				frag_size = upper_seq;
			}
		}

	else if ( len < MIN_ACCEPTABLE_FRAG_SIZE )
		s->Weird("excessively_small_fragment", ip);

	if ( upper_seq > MAX_ACCEPTABLE_FRAG_SIZE )
		s->Weird("excessively_large_fragment", ip);

	if ( frag_size && upper_seq > frag_size )
		{
		// This can happen if we receive a fragment that's *not*
		// the last fragment, but still imputes a size that's
		// larger than the size we derived from a previously-seen
		// "last fragment".

		s->Weird("fragment_size_inconsistency", ip);
		frag_size = upper_seq;
		}

	// Do we need to check for consistent options?  That's tricky
	// for things like LSRR that get modified in route.

	// Remove header.
	pkt += hdr_len;
	len -= hdr_len;

	NewBlock(network_time, offset, len, pkt);
	}

void FragReassembler::Overlap(const u_char* b1, const u_char* b2, int n)
	{
	IP_Hdr proto_h((const struct ip*) proto_hdr);

	if ( memcmp((const void*) b1, (const void*) b2, n) )
		s->Weird("fragment_inconsistency", &proto_h);
	else
		s->Weird("fragment_overlap", &proto_h);
	}

void FragReassembler::BlockInserted(DataBlock* /* start_block */)
	{
	if ( blocks->seq > 0 || ! frag_size )
		// For sure don't have it all yet.
		return;

	// We might have it all - look for contiguous all the way.
	DataBlock* b;
	for ( b = blocks; b->next; b = b->next )
		if ( b->upper != b->next->seq )
			break;

	if ( b->next )
		{
		// We have a hole.
		if ( b->upper >= frag_size )
			{
			// We're stuck.  The point where we stopped is
			// contiguous up through the expected end of
			// the fragment, but there's more stuff still
			// beyond it, which is not contiguous.  This
			// can happen for benign reasons when we're
			// intermingling parts of two fragmented packets.

			IP_Hdr proto_h((const struct ip*) proto_hdr);
			s->Weird("fragment_size_inconsistency", &proto_h);

			// We decide to analyze the contiguous portion now.
			// Extend the fragment up through the end of what
			// we have.
			frag_size = b->upper;
			}
		else
			return;
		}

	else if ( last_block->upper > frag_size )
		{
		IP_Hdr proto_h((const struct ip*) proto_hdr);
		s->Weird("fragment_size_inconsistency", &proto_h);
		frag_size = last_block->upper;
		}

	else if ( last_block->upper < frag_size )
		// Missing the tail.
		return;

	// We have it all.  Compute the expected size of the fragment.
	int n = proto_hdr_len + frag_size;

	// It's possible that we have blocks associated with this fragment
	// that exceed this size, if we saw MF fragments (which don't lead
	// to us setting frag_size) that went beyond the size indicated by
	// the final, non-MF fragment.  This can happen for benign reasons
	// due to intermingling of fragments from an older datagram with those
	// for a more recent one.

	u_char* pkt = new u_char[n];
	memcpy((void*) pkt, (const void*) proto_hdr, proto_hdr_len);

	struct ip* reassem4 = (struct ip*) pkt;
	reassem4->ip_len = htons(frag_size + proto_hdr_len);

	pkt += proto_hdr_len;

	for ( b = blocks; b; b = b->next )
		{
		// If we're above a hole, stop.  This can happen because
		// the logic above regarding a hole that's above the
		// expected fragment size.
		if ( b->prev && b->prev->upper < b->seq )
			break;

		if ( b->upper > n )
			internal_error("bad fragment reassembly");

		memcpy((void*) &pkt[b->seq], (const void*) b->block,
			b->upper - b->seq);
		}

	delete reassembled_pkt;
	reassembled_pkt = new IP_Hdr(reassem4);

	DeleteTimer();
	}

void FragReassembler::Expire(double t)
	{
	while ( blocks )
		{
		DataBlock* b = blocks->next;
		delete blocks;
		blocks = b;
		}

	expire_timer->ClearReassembler();
	expire_timer = 0;	// timer manager will delete it

	sessions->Remove(this);
	}

void FragReassembler::DeleteTimer()
	{
	if ( expire_timer )
		{
		expire_timer->ClearReassembler();
		timer_mgr->Cancel(expire_timer);
		expire_timer = 0;	// timer manager will delete it
		}
	}
