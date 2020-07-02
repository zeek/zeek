// See the file "COPYING" in the main distribution directory for copyright.

#include "analyzer/protocol/tcp/TCP.h"

#include <vector>

#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "analyzer/protocol/pia/PIA.h"

#include "IP.h"
#include "Net.h"
#include "NetVar.h"
#include "File.h"
#include "Event.h"
#include "Reporter.h"
#include "Sessions.h"
#include "DebugLogger.h"

#include "events.bif.h"
#include "types.bif.h"

using namespace analyzer::tcp;

namespace { // local namespace
	const bool DEBUG_tcp_data_sent = false;
	const bool DEBUG_tcp_connection_close = false;
}

// The following are not included in all systems' tcp.h.

#ifndef TH_ECE
#define TH_ECE  0x40
#endif

#ifndef TH_CWR
#define TH_CWR  0x80
#endif


#define TOO_LARGE_SEQ_DELTA 1048576

static const int ORIG = 1;
static const int RESP = 2;

static zeek::RecordVal* build_syn_packet_val(bool is_orig, const IP_Hdr* ip,
                                             const struct tcphdr* tcp)
	{
	int winscale = -1;
	int MSS = 0;
	int SACK = 0;

	// Parse TCP options.
	u_char* options = (u_char*) tcp + sizeof(struct tcphdr);
	u_char* opt_end = (u_char*) tcp + tcp->th_off * 4;

	while ( options < opt_end )
		{
		unsigned int opt = options[0];

		if ( opt == TCPOPT_EOL )
			// All done - could flag if more junk left over ....
			break;

		if ( opt == TCPOPT_NOP )
			{
			++options;
			continue;
			}

		if ( options + 1 >= opt_end )
			// We've run off the end, no room for the length.
			break;

		unsigned int opt_len = options[1];

		if ( options + opt_len > opt_end )
			// No room for rest of option.
			break;

		if ( opt_len == 0 )
			// Trashed length field.
			break;

		switch ( opt ) {
		case TCPOPT_SACK_PERMITTED:
			SACK = 1;
			break;

		case TCPOPT_MAXSEG:
			if ( opt_len < 4 )
				break;	// bad length

			MSS = (options[2] << 8) | options[3];
			break;

		case 3: // TCPOPT_WSCALE
			if ( opt_len < 3 )
				break;	// bad length

			winscale = options[2];
			break;

		default:	// just skip over
			break;
		}

		options += opt_len;
		}

	static auto SYN_packet = zeek::id::find_type<zeek::RecordType>("SYN_packet");
	auto* v = new zeek::RecordVal(SYN_packet);

	v->Assign(0, zeek::val_mgr->Bool(is_orig));
	v->Assign(1, zeek::val_mgr->Bool(int(ip->DF())));
	v->Assign(2, zeek::val_mgr->Count((ip->TTL())));
	v->Assign(3, zeek::val_mgr->Count((ip->TotalLen())));
	v->Assign(4, zeek::val_mgr->Count(ntohs(tcp->th_win)));
	v->Assign(5, zeek::val_mgr->Int(winscale));
	v->Assign(6, zeek::val_mgr->Count(MSS));
	v->Assign(7, zeek::val_mgr->Bool(SACK));

	return v;
	}


TCP_Analyzer::TCP_Analyzer(Connection* conn)
: TransportLayerAnalyzer("TCP", conn)
	{
	// Set a timer to eventually time out this connection.
	ADD_ANALYZER_TIMER(&TCP_Analyzer::ExpireTimer,
				network_time + tcp_SYN_timeout, false,
				TIMER_TCP_EXPIRE);

	deferred_gen_event = close_deferred = 0;

	seen_first_ACK = 0;
	is_active = 1;
	finished = 0;
	reassembling = 0;
	first_packet_seen = 0;
	is_partial = 0;

	orig = new TCP_Endpoint(this, true);
	resp = new TCP_Endpoint(this, false);

	orig->SetPeer(resp);
	resp->SetPeer(orig);
	}

TCP_Analyzer::~TCP_Analyzer()
	{
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		delete *i;

	delete orig;
	delete resp;
	}

void TCP_Analyzer::Init()
	{
	Analyzer::Init();
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		(*i)->Init();
	}

void TCP_Analyzer::Done()
	{
	Analyzer::Done();

	if ( terminating && connection_pending && is_active && ! BothClosed() )
		Event(connection_pending);

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		(*i)->Done();

	orig->Done();
	resp->Done();

	finished = 1;
	}

zeek::analyzer::Analyzer* TCP_Analyzer::FindChild(zeek::analyzer::ID arg_id)
	{
	zeek::analyzer::Analyzer* child = zeek::analyzer::TransportLayerAnalyzer::FindChild(arg_id);

	if ( child )
		return child;

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		{
		zeek::analyzer::Analyzer* child = (*i)->FindChild(arg_id);
		if ( child )
			return child;
		}

	return nullptr;
	}

zeek::analyzer::Analyzer* TCP_Analyzer::FindChild(zeek::analyzer::Tag arg_tag)
	{
	zeek::analyzer::Analyzer* child = zeek::analyzer::TransportLayerAnalyzer::FindChild(arg_tag);

	if ( child )
		return child;

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		{
		zeek::analyzer::Analyzer* child = (*i)->FindChild(arg_tag);
		if ( child )
			return child;
		}

	return nullptr;
	}

bool TCP_Analyzer::RemoveChildAnalyzer(zeek::analyzer::ID id)
	{
	auto rval = zeek::analyzer::TransportLayerAnalyzer::RemoveChildAnalyzer(id);

	if ( rval )
		return rval;

	return RemoveChild(packet_children, id);
	}

void TCP_Analyzer::EnableReassembly()
	{
	SetReassembler(new TCP_Reassembler(this, this,
	                                   TCP_Reassembler::Forward, orig),
	               new TCP_Reassembler(this, this,
	                                   TCP_Reassembler::Forward, resp));
	}

void TCP_Analyzer::SetReassembler(TCP_Reassembler* rorig,
                                  TCP_Reassembler* rresp)
	{
	orig->AddReassembler(rorig);
	rorig->SetDstAnalyzer(this);
	resp->AddReassembler(rresp);
	rresp->SetDstAnalyzer(this);

	if ( new_connection_contents && reassembling == 0 )
		Event(new_connection_contents);

	reassembling = 1;
	}

const struct tcphdr* TCP_Analyzer::ExtractTCP_Header(const u_char*& data,
							int& len, int& caplen)
	{
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint32_t tcp_hdr_len = tp->th_off * 4;

	if ( tcp_hdr_len < sizeof(struct tcphdr) )
		{
		Weird("bad_TCP_header_len");
		return nullptr;
		}

	if ( tcp_hdr_len > uint32_t(len) ||
	     tcp_hdr_len > uint32_t(caplen) )
		{
		// This can happen even with the above test, due to TCP
		// options.
		Weird("truncated_header");
		return nullptr;
		}

	len -= tcp_hdr_len;	// remove TCP header
	caplen -= tcp_hdr_len;
	data += tcp_hdr_len;

	return tp;
	}

bool TCP_Analyzer::ValidateChecksum(const struct tcphdr* tp,
				TCP_Endpoint* endpoint, int len, int caplen)
	{
	if ( ! current_pkt->l3_checksummed && ! ignore_checksums && caplen >= len &&
	     ! endpoint->ValidChecksum(tp, len) )
		{
		Weird("bad_TCP_checksum");
		endpoint->ChecksumError();
		return false;
		}
	else
		return true;
	}

void TCP_Analyzer::SetPartialStatus(TCP_Flags flags, bool is_orig)
	{
	if ( is_orig )
		{
		if ( ! (first_packet_seen & ORIG) )
			is_partial = ! flags.SYN() || flags.ACK();
		}
	else
		{
		if ( ! (first_packet_seen & RESP) && ! is_partial )
			is_partial = ! flags.SYN();
		}
	}

static void update_history(TCP_Flags flags, TCP_Endpoint* endpoint,
			   uint64_t rel_seq, int len)
	{
	int bits_set = (flags.SYN() ? 1 : 0) + (flags.FIN() ? 1 : 0) +
			(flags.RST() ? 1 : 0);
	if ( bits_set > 1 )
		{
		if ( flags.FIN() && flags.RST() )
			endpoint->CheckHistory(HIST_FIN_RST_PKT, 'I');
		else
			endpoint->CheckHistory(HIST_MULTI_FLAG_PKT, 'Q');
		}

	else if ( bits_set == 1 )
		{
		if ( flags.SYN() )
			{
			char code = flags.ACK() ? 'H' : 'S';

			if ( endpoint->CheckHistory(HIST_SYN_PKT, code) &&
			     rel_seq != endpoint->hist_last_SYN )
				endpoint->AddHistory(code);

			endpoint->hist_last_SYN = rel_seq;
			}

		if ( flags.FIN() )
			{
			// For FIN's, the sequence number comes at the
			// end of (any data in) the packet, not the
			// beginning as for SYNs and RSTs.
			if ( endpoint->CheckHistory(HIST_FIN_PKT, 'F') &&
			     rel_seq + len != endpoint->hist_last_FIN )
				endpoint->AddHistory('F');

			endpoint->hist_last_FIN = rel_seq + len;
			}

		if ( flags.RST() )
			{
			if ( endpoint->CheckHistory(HIST_RST_PKT, 'R') &&
			     rel_seq != endpoint->hist_last_RST )
				endpoint->AddHistory('R');

			endpoint->hist_last_RST = rel_seq;
			}
		}

	else
		{ // bits_set == 0
		if ( len )
			endpoint->CheckHistory(HIST_DATA_PKT, 'D');

		else if ( flags.ACK() )
			endpoint->CheckHistory(HIST_ACK_PKT, 'A');
		}
	}

static void init_window(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			TCP_Flags flags, bro_int_t scale, uint32_t base_seq,
			uint32_t ack_seq)
	{
	// ### In the following, we could be fooled by an
	// inconsistent SYN retransmission.  Where's a normalizer
	// when you need one?

	if ( scale < 0 )
		{ // no window scaling option
		if ( flags.ACK() )
			{ // window scaling not negotiated
			endpoint->window_scale = 0;
			peer->window_scale = 0;
			}
		else
			// We're not offering window scaling.
			// Ideally, we'd remember this fact so that
			// if the SYN/ACK *does* include window
			// scaling, we know it won't be negotiated.
			// But it's a pain to track that, and hard
			// to see how an adversarial responder could
			// use it to evade.  Also, if we *do* want
			// to track it, we could do so using
			// connection_SYN_packet.
			endpoint->window_scale = 0;
		}
	else
		{
		endpoint->window_scale = scale;
		endpoint->window_seq = base_seq;
		endpoint->window_ack_seq = ack_seq;

		peer->window_seq = ack_seq;
		peer->window_ack_seq = base_seq;
		}
	}

static void update_window(TCP_Endpoint* endpoint, unsigned int window,
                          uint32_t base_seq, uint32_t ack_seq, TCP_Flags flags)
	{
	// Note, applying scaling here would be incorrect for an initial SYN,
	// whose window value is always unscaled.  However, we don't
	// check the window's value for recision in that case anyway, so
	// no-harm-no-foul.
	int scale = endpoint->window_scale;
	window = window << scale;

	// Zero windows are boring if either (1) they come with a RST packet
	// or after a RST packet, or (2) they come after the peer has sent
	// a FIN (because there's no relevant window at that point anyway).
	// (They're also boring if they come after the peer has sent a RST,
	// but *nothing* should be sent in response to a RST, so we ignore
	// that case.)
	//
	// However, they *are* potentially interesting if sent by an
	// endpoint that's already sent a FIN, since that FIN meant "I'm
	// not going to send any more", but doesn't mean "I won't receive
	// any more".
	if ( window == 0 && ! flags.RST() &&
	     endpoint->peer->state != TCP_ENDPOINT_CLOSED &&
	     endpoint->state != TCP_ENDPOINT_RESET )
		endpoint->ZeroWindow();

	// Don't analyze window values off of SYNs, they're sometimes
	// immediately rescinded.  Also don't do so for FINs or RSTs,
	// or if the connection has already been partially closed, since
	// such recisions occur frequently in practice, probably as the
	// receiver loses buffer memory due to its process going away.

	if ( ! flags.SYN() && ! flags.FIN() && ! flags.RST() &&
	     endpoint->state != TCP_ENDPOINT_CLOSED &&
	     endpoint->state != TCP_ENDPOINT_RESET )
		{
		// ### Decide whether to accept new window based on Active
		// Mapping policy.
		if ( seq_delta(base_seq, endpoint->window_seq) >= 0 &&
		     seq_delta(ack_seq, endpoint->window_ack_seq) >= 0 )
			{
			uint32_t new_edge = ack_seq + window;
			uint32_t old_edge = endpoint->window_ack_seq + endpoint->window;
			int32_t advance = seq_delta(new_edge, old_edge);

			if ( advance < 0 )
				{
				// An apparent window recision.  Allow a
				// bit of slop for window scaling.  This is
				// because sometimes there will be an
				// apparent recision due to the granularity
				// of the scaling.
				if ( (-advance) >= (1 << scale) )
					endpoint->Conn()->Weird("window_recision");
				}

			endpoint->window = window;
			endpoint->window_ack_seq = ack_seq;
			endpoint->window_seq = base_seq;
			}
		}
	}

static void syn_weirds(TCP_Flags flags, TCP_Endpoint* endpoint, int data_len)
	{
	if ( flags.RST() )
		endpoint->Conn()->Weird("TCP_christmas");

	if ( flags.URG() )
		endpoint->Conn()->Weird("baroque_SYN");

	if ( data_len > 0 )
		// Not technically wrong according to RFC 793, but the other side
		// would be forced to buffer data until the handshake succeeds, and
		// that could be bad in some cases, e.g. SYN floods.
		// T/TCP definitely complicates this.
		endpoint->Conn()->Weird("SYN_with_data");
	}

void TCP_Analyzer::UpdateInactiveState(double t,
			TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			uint32_t base_seq, uint32_t ack_seq,
			int len, bool is_orig, TCP_Flags flags,
			bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( is_orig )
			{
			if ( flags.ACK() )
				{
				Weird("connection_originator_SYN_ack");
				endpoint->SetState(TCP_ENDPOINT_SYN_ACK_SENT);
				}
			else
				endpoint->SetState(TCP_ENDPOINT_SYN_SENT);

			if ( tcp_attempt_delay )
				ADD_ANALYZER_TIMER(&TCP_Analyzer::AttemptTimer,
					t + tcp_attempt_delay, true,
					TIMER_TCP_ATTEMPT);
			}
		else
			{
			if ( flags.ACK() )
				{
				if ( peer->state != TCP_ENDPOINT_INACTIVE &&
				     peer->state != TCP_ENDPOINT_PARTIAL &&
				     ! seq_between(ack_seq, peer->StartSeq(), peer->LastSeq()) )
					Weird("bad_SYN_ack");
				}

			else if ( peer->state == TCP_ENDPOINT_SYN_ACK_SENT &&
				  base_seq == endpoint->StartSeq() )
				{
				// This is a SYN/SYN-ACK reversal,
				// per the discussion in IsReuse.
				// Flip the endpoints and establish
				// the connection.
				is_partial = 0;
				Conn()->FlipRoles();
				peer->SetState(TCP_ENDPOINT_ESTABLISHED);
				}

			else
				Weird("simultaneous_open");

			if ( peer->state == TCP_ENDPOINT_SYN_SENT )
				peer->SetState(TCP_ENDPOINT_ESTABLISHED);
			else if ( peer->state == TCP_ENDPOINT_INACTIVE )
				{
				// If we were to ignore SYNs and
				// only instantiate state on SYN
				// acks, then we'd do:
				//    peer->SetState(TCP_ENDPOINT_ESTABLISHED);
				// here.
				Weird("unsolicited_SYN_response");
				}

			endpoint->SetState(TCP_ENDPOINT_ESTABLISHED);

			if ( peer->state != TCP_ENDPOINT_PARTIAL )
				{
				Event(connection_established);
				Conn()->EnableStatusUpdateTimer();
				}
			}
		}

	if ( flags.FIN() )
		{
		endpoint->SetState(TCP_ENDPOINT_CLOSED);
		do_close = gen_event = true;
		if ( peer->state != TCP_ENDPOINT_PARTIAL && ! flags.SYN() )
			Weird("spontaneous_FIN");
		}

	if ( flags.RST() )
		{
		endpoint->SetState(TCP_ENDPOINT_RESET);

		bool is_reject = false;

		if ( is_orig )
			{
			// If our peer is established then we saw
			// a SYN-ack but not SYN - so a reverse
			// scan, and we should treat this as a
			// reject.
			if ( peer->state == TCP_ENDPOINT_ESTABLISHED )
				is_reject = true;
			}

		else if ( peer->state == TCP_ENDPOINT_SYN_SENT ||
			  peer->state == TCP_ENDPOINT_SYN_ACK_SENT )
			// We're rejecting an initial SYN.
			is_reject = true;

		do_close = true;
		gen_event = ! is_reject;

		if ( is_reject )
			Event(connection_rejected);

		else if ( peer->state == TCP_ENDPOINT_INACTIVE )
			Weird("spontaneous_RST");
		}

	if ( endpoint->state == TCP_ENDPOINT_INACTIVE )
		{ // No control flags to change the state.
		if ( ! is_orig && len == 0 &&
		     orig->state == TCP_ENDPOINT_SYN_SENT )
			// Some eccentric TCP's will ack an initial
			// SYN prior to sending a SYN reply (hello,
			// ftp.microsoft.com).  For those, don't
			// consider the ack as forming a partial
			// connection.
			;

		else if ( flags.ACK() && peer->state == TCP_ENDPOINT_ESTABLISHED )
			{
			// No SYN packet from originator but SYN/ACK from
			// responder, and now a pure ACK. Problably means we
			// just missed that initial SYN. Let's not treat it
			// as partial and instead establish the connection.
			endpoint->SetState(TCP_ENDPOINT_ESTABLISHED);
			is_partial = 0;
			}

		else
			{
			endpoint->SetState(TCP_ENDPOINT_PARTIAL);
			Conn()->EnableStatusUpdateTimer();

			if ( peer->state == TCP_ENDPOINT_PARTIAL )
				// We've seen both sides of a partial
				// connection, report it.
				Event(partial_connection);
			}
		}
	}

void TCP_Analyzer::UpdateSYN_SentState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				       int len, bool is_orig, TCP_Flags flags,
				       bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( is_orig )
			{
			if ( flags.ACK() && ! flags.FIN() && ! flags.RST() &&
			     endpoint->state != TCP_ENDPOINT_SYN_ACK_SENT )
				Weird("repeated_SYN_with_ack");
			}
		else
			{
			if ( ! flags.ACK() &&
			     endpoint->state != TCP_ENDPOINT_SYN_SENT )
				Weird("repeated_SYN_reply_wo_ack");
			}
		}

	if ( flags.FIN() )
		{
		if ( peer->state == TCP_ENDPOINT_INACTIVE ||
		     peer->state == TCP_ENDPOINT_SYN_SENT )
			Weird("inappropriate_FIN");

		endpoint->SetState(TCP_ENDPOINT_CLOSED);
		do_close = gen_event = true;
		}

	if ( flags.RST() )
		{
		endpoint->SetState(TCP_ENDPOINT_RESET);
		ConnectionReset();
		do_close = true;
		}

	else if ( len > 0 )
		Weird("data_before_established");
	}

void TCP_Analyzer::UpdateEstablishedState(
			TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			TCP_Flags flags, bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( endpoint->state == TCP_ENDPOINT_PARTIAL &&
		     peer->state == TCP_ENDPOINT_INACTIVE && ! flags.ACK() )
			{
			Weird("SYN_after_partial");
			endpoint->SetState(TCP_ENDPOINT_SYN_SENT);
			}
		}

	if ( flags.FIN() && ! flags.RST() )	// ###
		{ // should check sequence/ack numbers here ###
		endpoint->SetState(TCP_ENDPOINT_CLOSED);

		if ( peer->state == TCP_ENDPOINT_RESET &&
		     peer->prev_state == TCP_ENDPOINT_CLOSED )
			// The peer sent a FIN followed by a RST.
			// Turn it back into CLOSED state, because
			// this was actually normal termination.
			peer->SetState(TCP_ENDPOINT_CLOSED);

		do_close = gen_event = true;
		}

	if ( flags.RST() )
		{
		endpoint->SetState(TCP_ENDPOINT_RESET);
		do_close = true;

		if ( peer->state != TCP_ENDPOINT_RESET ||
		     peer->prev_state != TCP_ENDPOINT_ESTABLISHED )
			ConnectionReset();
		}
	}

void TCP_Analyzer::UpdateClosedState(double t, TCP_Endpoint* endpoint,
				int32_t delta_last, TCP_Flags flags, bool& do_close)
	{
	if ( flags.SYN() )
		Weird("SYN_after_close");

	if ( flags.FIN() && delta_last > 0 )
		// Probably should also complain on FIN recision.
		// That requires an extra state variable to avoid
		// generating slews of weird's when a TCP gets
		// seriously confused (this from experience).
		Weird("FIN_advanced_last_seq");

	// Previously, our state was CLOSED, since we sent a FIN.
	// If our peer was also closed, then don't change our state
	// now on a RST, since this connection has already seen a FIN
	// exchange.
	if ( flags.RST() && endpoint->peer->state != TCP_ENDPOINT_CLOSED )
		{
		endpoint->SetState(TCP_ENDPOINT_RESET);

		if ( ! endpoint->did_close )
			// RST after FIN.
			do_close = true;

		if ( connection_reset )
			ADD_ANALYZER_TIMER(&TCP_Analyzer::ResetTimer,
					t + tcp_reset_delay, true,
					TIMER_TCP_RESET);
		}
	}

void TCP_Analyzer::UpdateResetState(int len, TCP_Flags flags)
	{
	if ( flags.SYN() )
		Weird("SYN_after_reset");

	if ( flags.FIN() )
		Weird("FIN_after_reset");

	if ( len > 0 && ! flags.RST() )
		Weird("data_after_reset");
	}

void TCP_Analyzer::UpdateStateMachine(double t,
			TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			uint32_t base_seq, uint32_t ack_seq,
			int len, int32_t delta_last, bool is_orig, TCP_Flags flags,
			bool& do_close, bool& gen_event)
	{
	do_close = false;	// whether to report the connection as closed
	gen_event = false;	// if so, whether to generate an event

	switch ( endpoint->state ) {

	case TCP_ENDPOINT_INACTIVE:
		UpdateInactiveState(t, endpoint, peer, base_seq, ack_seq,
					len, is_orig, flags,
					do_close, gen_event);
		break;

	case TCP_ENDPOINT_SYN_SENT:
	case TCP_ENDPOINT_SYN_ACK_SENT:
		UpdateSYN_SentState(endpoint, peer, len, is_orig, flags, do_close,
		                    gen_event);
		break;

	case TCP_ENDPOINT_ESTABLISHED:
	case TCP_ENDPOINT_PARTIAL:
		UpdateEstablishedState(endpoint, peer, flags, do_close, gen_event);
		break;

	case TCP_ENDPOINT_CLOSED:
		UpdateClosedState(t, endpoint, delta_last, flags, do_close);
		break;

	case TCP_ENDPOINT_RESET:
		UpdateResetState(len, flags);
		break;
	}
	}

void TCP_Analyzer::GeneratePacketEvent(
					uint64_t rel_seq, uint64_t rel_ack,
					const u_char* data, int len, int caplen,
					bool is_orig, TCP_Flags flags)
	{
	EnqueueConnEvent(tcp_packet,
		ConnVal(),
		zeek::val_mgr->Bool(is_orig),
		zeek::make_intrusive<zeek::StringVal>(flags.AsString()),
		zeek::val_mgr->Count(rel_seq),
		zeek::val_mgr->Count(flags.ACK() ? rel_ack : 0),
		zeek::val_mgr->Count(len),
		// We need the min() here because Ethernet padding can lead to
		// caplen > len.
		zeek::make_intrusive<zeek::StringVal>(std::min(caplen, len), (const char*) data)
	);
	}

bool TCP_Analyzer::DeliverData(double t, const u_char* data, int len, int caplen,
				const IP_Hdr* ip, const struct tcphdr* tp,
				TCP_Endpoint* endpoint, uint64_t rel_data_seq,
				bool is_orig, TCP_Flags flags)
	{
	return endpoint->DataSent(t, rel_data_seq, len, caplen, data, ip, tp);
	}

void TCP_Analyzer::CheckRecording(bool need_contents, TCP_Flags flags)
	{
	bool record_current_content = need_contents || Conn()->RecordContents();
	bool record_current_packet =
		Conn()->RecordPackets() ||
		flags.SYN() || flags.FIN() || flags.RST();

	Conn()->SetRecordCurrentContent(record_current_content);
	Conn()->SetRecordCurrentPacket(record_current_packet);
	}

void TCP_Analyzer::CheckPIA_FirstPacket(bool is_orig, const IP_Hdr* ip)
	{
	if ( is_orig && ! (first_packet_seen & ORIG) )
		{
		pia::PIA_TCP* pia = static_cast<pia::PIA_TCP*>(Conn()->GetPrimaryPIA());
		if ( pia )
			pia->FirstPacket(is_orig, ip);
		first_packet_seen |= ORIG;
		}

	if ( ! is_orig && ! (first_packet_seen & RESP) )
		{
		pia::PIA_TCP* pia = static_cast<pia::PIA_TCP*>(Conn()->GetPrimaryPIA());
		if ( pia )
			pia->FirstPacket(is_orig, ip);
		first_packet_seen |= RESP;
		}
	}

uint64_t TCP_Analyzer::get_relative_seq(const TCP_Endpoint* endpoint,
                                      uint32_t cur_base, uint32_t last,
                                      uint32_t wraps, bool* underflow)
	{
	int32_t delta = seq_delta(cur_base, last);

	if ( delta < 0 )
		{
		if ( wraps && cur_base > last )
			// Seems to be a part of a previous 32-bit sequence space.
			--wraps;
		}

	else if ( delta > 0 )
		{
		if ( cur_base < last )
			// The sequence space wrapped around.
			++wraps;
		}

	if ( wraps == 0 )
		{
		delta = seq_delta(cur_base, endpoint->StartSeq());

		if ( underflow && delta < 0 )
			*underflow = true;

		return delta;
		}

	return endpoint->ToRelativeSeqSpace(cur_base, wraps);
	}

int TCP_Analyzer::get_segment_len(int payload_len, TCP_Flags flags)
	{
	int seg_len = payload_len;

	if ( flags.SYN() )
		// SYN consumes a byte of sequence space.
		++seg_len;

	if ( flags.FIN() )
		// FIN consumes a bytes of sequence space.
		++seg_len;

	if ( flags.RST() )
		// Don't include the data in the computation of
		// the sequence space for this connection, as
		// it's not in fact part of the TCP stream.
		seg_len -= payload_len;

	return seg_len;
	}

static void init_endpoint(TCP_Endpoint* endpoint, TCP_Flags flags,
                          uint32_t first_seg_seq, uint32_t last_seq, double t)
	{
	switch ( endpoint->state ) {
	case TCP_ENDPOINT_INACTIVE:
		if ( flags.SYN() )
			{
			endpoint->InitAckSeq(first_seg_seq);
			endpoint->InitStartSeq(first_seg_seq);
			}
		else
			{
			// This is a partial connection - set up the initial sequence
			// numbers as though we saw a SYN, to keep the relative byte
			// numbering consistent.
			endpoint->InitAckSeq(first_seg_seq - 1);
			endpoint->InitStartSeq(first_seg_seq - 1);
			// But ensure first packet is not marked duplicate
			last_seq = first_seg_seq;
			}

		endpoint->InitLastSeq(last_seq);
		endpoint->start_time = t;
		break;

	case TCP_ENDPOINT_SYN_SENT:
	case TCP_ENDPOINT_SYN_ACK_SENT:
		if ( flags.SYN() && first_seg_seq != endpoint->StartSeq() )
			{
			endpoint->Conn()->Weird("SYN_seq_jump");
			endpoint->InitStartSeq(first_seg_seq);
			endpoint->InitAckSeq(first_seg_seq);
			endpoint->InitLastSeq(last_seq);
			}
		break;

	case TCP_ENDPOINT_ESTABLISHED:
	case TCP_ENDPOINT_PARTIAL:
		if ( flags.SYN() )
			{
			if ( endpoint->Size() > 0 )
				endpoint->Conn()->Weird("SYN_inside_connection");

			if ( first_seg_seq != endpoint->StartSeq() )
				endpoint->Conn()->Weird("SYN_seq_jump");

			// Make a guess that somehow the connection didn't get established,
			// and this SYN will be the one that actually sets it up.
			endpoint->InitStartSeq(first_seg_seq);
			endpoint->InitAckSeq(first_seg_seq);
			endpoint->InitLastSeq(last_seq);
			}
		break;

	case TCP_ENDPOINT_RESET:
		if ( flags.SYN() )
			{
			if ( endpoint->prev_state == TCP_ENDPOINT_INACTIVE )
				{
				// Seq. numbers were initialized by a RST packet from this
				// endpoint, but now that a SYN is seen from it, that could mean
				// the earlier RST was spoofed/injected, so re-initialize.  This
				// mostly just helps prevent misrepresentations of payload sizes
				// that are based on bad initial sequence values.
				endpoint->InitStartSeq(first_seg_seq);
				endpoint->InitAckSeq(first_seg_seq);
				endpoint->InitLastSeq(last_seq);
				}
			}
		break;

	default:
		break;
	}
	}

static void init_peer(TCP_Endpoint* peer, TCP_Endpoint* endpoint,
                      TCP_Flags flags, uint32_t ack_seq)
	{
	if ( ! flags.SYN() && ! flags.FIN() && ! flags.RST() )
		{
		if ( endpoint->state == TCP_ENDPOINT_SYN_SENT ||
			 endpoint->state == TCP_ENDPOINT_SYN_ACK_SENT ||
			 endpoint->state == TCP_ENDPOINT_ESTABLISHED )
			{
			// We've already sent a SYN, but that
			// hasn't roused the other end, yet we're
			// ack'ing their data.

			if ( ! endpoint->Conn()->DidWeird() )
				endpoint->Conn()->Weird("possible_split_routing");
			}
		}

	// Start the sequence numbering as if there was an initial
	// SYN, so the relative numbering of subsequent data packets
	// stays consistent.
	peer->InitStartSeq(ack_seq - 1);
	peer->InitAckSeq(ack_seq - 1);
	peer->InitLastSeq(ack_seq - 1);
	}

static void update_ack_seq(TCP_Endpoint* endpoint, uint32_t ack_seq)
	{
	int32_t delta_ack = seq_delta(ack_seq, endpoint->AckSeq());

	if ( ack_seq == 0 && delta_ack > TOO_LARGE_SEQ_DELTA )
		// More likely that this is a broken ack than a
		// large connection that happens to land on 0 in the
		// sequence space.
		;
	else if ( delta_ack > 0 )
		endpoint->UpdateAckSeq(ack_seq);
	}

// Returns the difference between last_seq and the last sequence
// seen by the endpoint (may be negative).
static int32_t update_last_seq(TCP_Endpoint* endpoint, uint32_t last_seq,
                             TCP_Flags flags, int len)
	{
	int32_t delta_last = seq_delta(last_seq, endpoint->LastSeq());

	if ( (flags.SYN() || flags.RST()) &&
	     (delta_last > TOO_LARGE_SEQ_DELTA ||
		 delta_last < -TOO_LARGE_SEQ_DELTA) )
		// ### perhaps trust RST seq #'s if initial and not too
		// outlandish, but not if they're coming after the other
		// side has sent a FIN - trust the FIN ack instead
		;

	else if ( flags.FIN() &&
		  endpoint->LastSeq() == endpoint->StartSeq() + 1 )
		// Update last_seq based on the FIN even if delta_last < 0.
		// This is to accommodate > 2 GB connections for which
		// we've only seen the SYN and the FIN (hence the check
		// for last_seq == start_seq + 1).
		endpoint->UpdateLastSeq(last_seq);

	else if ( endpoint->state == TCP_ENDPOINT_RESET )
		// don't trust any subsequent sequence numbers
		;

	else if ( delta_last > 0 )
		// ### check for large jumps here.
		// ## endpoint->last_seq = last_seq;
		endpoint->UpdateLastSeq(last_seq);

	else if ( delta_last <= 0 && len > 0 )
		endpoint->DidRxmit();

	return delta_last;
	}

void TCP_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig,
					uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	TransportLayerAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	const struct tcphdr* tp = ExtractTCP_Header(data, len, caplen);
	if ( ! tp )
		return;

	// We need the min() here because Ethernet frame padding can lead to
	// caplen > len.
	if ( packet_contents )
		PacketContents(data, std::min(len, caplen));

	TCP_Endpoint* endpoint = is_orig ? orig : resp;
	TCP_Endpoint* peer = endpoint->peer;

	if ( ! ValidateChecksum(tp, endpoint, len, caplen) )
		return;

	uint32_t tcp_hdr_len = data - (const u_char*) tp;
	TCP_Flags flags(tp);
	SetPartialStatus(flags, endpoint->IsOrig());

	uint32_t base_seq = ntohl(tp->th_seq);
	uint32_t ack_seq = ntohl(tp->th_ack);

	int seg_len = get_segment_len(len, flags);
	uint32_t seq_one_past_segment = base_seq + seg_len;

	init_endpoint(endpoint, flags, base_seq, seq_one_past_segment,
	              current_timestamp);

	bool seq_underflow = false;
	uint64_t rel_seq = get_relative_seq(endpoint, base_seq, endpoint->LastSeq(),
					  endpoint->SeqWraps(), &seq_underflow);

	if ( seq_underflow && ! flags.RST() )
		// Can't tell if if this is a retransmit/out-of-order or something
		// before the sequence Bro initialized the endpoint at or the TCP is
		// just broken and sending garbage sequences.  In either case, some
		// standard analysis doesn't apply (e.g. reassembly).
		Weird("TCP_seq_underflow_or_misorder");

	update_history(flags, endpoint, rel_seq, len);
	update_window(endpoint, ntohs(tp->th_win), base_seq, ack_seq, flags);

	if ( ! orig->did_close || ! resp->did_close )
		Conn()->SetLastTime(current_timestamp);

	if ( flags.SYN() )
		{
		syn_weirds(flags, endpoint, len);
		zeek::RecordVal* SYN_vals = build_syn_packet_val(is_orig, ip, tp);
		init_window(endpoint, peer, flags, SYN_vals->GetField(5)->CoerceToInt(),
		            base_seq, ack_seq);

		if ( connection_SYN_packet )
			EnqueueConnEvent(connection_SYN_packet,
				ConnVal(),
				zeek::IntrusivePtr{zeek::NewRef{}, SYN_vals}
			);

		Unref(SYN_vals);
		}

	if ( flags.FIN() )
		{
		++endpoint->FIN_cnt;

		if ( endpoint->FIN_cnt >= tcp_storm_thresh && current_timestamp <
		     endpoint->last_time + tcp_storm_interarrival_thresh )
			Weird("FIN_storm");

		endpoint->FIN_seq = rel_seq + seg_len;
		}

	if ( flags.RST() )
		{
		++endpoint->RST_cnt;

		if ( endpoint->RST_cnt >= tcp_storm_thresh && current_timestamp <
		     endpoint->last_time + tcp_storm_interarrival_thresh )
			Weird("RST_storm");

		// This now happens often enough that it's
		// not in the least interesting.
		//if ( len > 0 )
		//	Weird("RST_with_data");

		PacketWithRST();
		}

	uint64_t rel_ack = 0;

	if ( flags.ACK() )
		{
		if ( is_orig && ! seen_first_ACK &&
		     (endpoint->state == TCP_ENDPOINT_ESTABLISHED ||
		      endpoint->state == TCP_ENDPOINT_SYN_SENT) )
			{
			seen_first_ACK = 1;
			Event(connection_first_ACK);
			}

		if ( peer->state == TCP_ENDPOINT_INACTIVE )
			{
			rel_ack = 1;
			init_peer(peer, endpoint, flags, ack_seq);
			}
		else
			{
			bool ack_underflow = false;
			rel_ack = get_relative_seq(peer, ack_seq, peer->AckSeq(),
			                           peer->AckWraps(), &ack_underflow);

			if ( ack_underflow )
				{
				rel_ack = 0;
				Weird("TCP_ack_underflow_or_misorder");
				}
			else if ( ! flags.RST() )
				// Don't trust ack's in RST packets.
				update_ack_seq(peer, ack_seq);
			}
		}

	int32_t delta_last = update_last_seq(endpoint, seq_one_past_segment, flags, len);
	endpoint->last_time = current_timestamp;

	bool do_close;
	bool gen_event;
	UpdateStateMachine(current_timestamp, endpoint, peer, base_seq, ack_seq,
	                   len, delta_last, is_orig, flags, do_close, gen_event);

	if ( flags.ACK() )
		// We wait on doing this until we've updated the state
		// machine so that if the ack reveals a content gap,
		// we can tell whether it came at the very end of the
		// connection (in a FIN or RST).  Those gaps aren't
		// reliable - especially those for RSTs - and we refrain
		// from flagging them in the connection history.
		peer->AckReceived(rel_ack);

	if ( tcp_packet )
		GeneratePacketEvent(rel_seq, rel_ack, data, len, caplen, is_orig,
		                    flags);

	if ( (tcp_option || tcp_options) && tcp_hdr_len > sizeof(*tp) )
		ParseTCPOptions(tp, is_orig);

	// PIA/signature matching state needs to be initialized before
	// processing/reassembling any TCP data, since that processing may
	// itself try to perform signature matching.  Also note that a SYN
	// packet may technically carry data (see RFC793 Section 3.4 and also
	// TCP Fast Open).
	CheckPIA_FirstPacket(is_orig, ip);

	// Note the similar/inverse logic to connection_attempt.
	if ( resp->state != TCP_ENDPOINT_INACTIVE ||
	     (orig->state != TCP_ENDPOINT_SYN_SENT &&
	      orig->state != TCP_ENDPOINT_SYN_ACK_SENT))
		Conn()->SetSuccessful();

	if ( DEBUG_tcp_data_sent )
		{
		DEBUG_MSG("%.6f before DataSent: len=%d caplen=%d skip=%d\n",
			  network_time, len, caplen, Skipping());
		}

	uint64_t rel_data_seq = flags.SYN() ? rel_seq + 1 : rel_seq;

	int need_contents = 0;
	if ( len > 0 && (caplen >= len || packet_children.size()) &&
	     ! flags.RST() && ! Skipping() && ! seq_underflow )
		need_contents = DeliverData(current_timestamp, data, len, caplen, ip,
		                            tp, endpoint, rel_data_seq, is_orig, flags);

	endpoint->CheckEOF();

	if ( do_close )
		{
		// We need to postpone doing this until after we process
		// DataSent, so we don't generate a connection_finished event
		// until after data perhaps included with the FIN is processed.
		ConnectionClosed(endpoint, peer, gen_event);
		}

	CheckRecording(need_contents, flags);

	// Handle child_packet analyzers.  Note: This happens *after* the
	// packet has been processed and the TCP state updated.
	analyzer_list::iterator next;

	for ( auto i = packet_children.begin(); i != packet_children.end(); /* nop */ )
		{
		auto child = *i;

		if ( child->IsFinished() || child->Removing() )
			{
			if ( child->Removing() )
				child->Done();

			DBG_LOG(DBG_ANALYZER, "%s deleted child %s",
			        fmt_analyzer(this).c_str(), fmt_analyzer(child).c_str());
			i = packet_children.erase(i);
			delete child;
			}
		else
			{
			child->NextPacket(len, data, is_orig, rel_data_seq, ip, caplen);
			++i;
			}
		}

	if ( ! reassembling )
		ForwardPacket(len, data, is_orig, rel_data_seq, ip, caplen);
	}

void TCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	Analyzer::DeliverStream(len, data, orig);
	}

void TCP_Analyzer::Undelivered(uint64_t seq, int len, bool is_orig)
	{
	Analyzer::Undelivered(seq, len, orig);
	}

void TCP_Analyzer::FlipRoles()
	{
	Analyzer::FlipRoles();

	sessions->tcp_stats.FlipState(orig->state, resp->state);
	TCP_Endpoint* tmp_ep = resp;
	resp = orig;
	orig = tmp_ep;
	orig->is_orig = !orig->is_orig;
	resp->is_orig = !resp->is_orig;
	}

void TCP_Analyzer::UpdateConnVal(zeek::RecordVal *conn_val)
	{
	zeek::RecordVal* orig_endp_val = conn_val->GetField("orig")->AsRecordVal();
	zeek::RecordVal* resp_endp_val = conn_val->GetField("resp")->AsRecordVal();

	orig_endp_val->Assign(0, zeek::val_mgr->Count(orig->Size()));
	orig_endp_val->Assign(1, zeek::val_mgr->Count(int(orig->state)));
	resp_endp_val->Assign(0, zeek::val_mgr->Count(resp->Size()));
	resp_endp_val->Assign(1, zeek::val_mgr->Count(int(resp->state)));

	// Call children's UpdateConnVal
	Analyzer::UpdateConnVal(conn_val);

	// Have to do packet_children ourselves.
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		(*i)->UpdateConnVal(conn_val);
	}

int TCP_Analyzer::ParseTCPOptions(const struct tcphdr* tcp, bool is_orig)
	{
	// Parse TCP options.
	const u_char* options = (const u_char*) tcp + sizeof(struct tcphdr);
	const u_char* opt_end = (const u_char*) tcp + tcp->th_off * 4;
	std::vector<const u_char*> opts;

	while ( options < opt_end )
		{
		unsigned int opt = options[0];

		unsigned int opt_len;

		if ( opt < 2 )
			opt_len = 1;

		else if ( options + 1 >= opt_end )
			// We've run off the end, no room for the length.
			break;

		else
			opt_len = options[1];

		if ( opt_len == 0 )
			break;	// trashed length field

		if ( options + opt_len > opt_end )
			// No room for rest of option.
			break;

		opts.emplace_back(options);
		options += opt_len;

		if ( opt == TCPOPT_EOL )
			// All done - could flag if more junk left over ....
			break;
		}

	if ( tcp_option )
		for ( const auto& o : opts )
			{
			auto kind = o[0];
			auto length = kind < 2 ? 1 : o[1];
			EnqueueConnEvent(tcp_option,
				ConnVal(),
				zeek::val_mgr->Bool(is_orig),
				zeek::val_mgr->Count(kind),
				zeek::val_mgr->Count(length)
				);
			}

	if ( tcp_options )
		{
		auto option_list = zeek::make_intrusive<zeek::VectorVal>(zeek::BifType::Vector::TCP::OptionList);

		auto add_option_data = [](const zeek::RecordValPtr& rv, const u_char* odata, int olen)
			{
			if ( olen <= 2 )
				return;

			auto data_len = olen - 2;
			auto data = reinterpret_cast<const char*>(odata + 2);
			rv->Assign(2, zeek::make_intrusive<zeek::StringVal>(data_len, data));
			};

		for ( const auto& o : opts )
			{
			auto kind = o[0];
			auto length = kind < 2 ? 1 : o[1];
			auto option_record = zeek::make_intrusive<zeek::RecordVal>(zeek::BifType::Record::TCP::Option);
			option_list->Assign(option_list->Size(), option_record);
			option_record->Assign(0, zeek::val_mgr->Count(kind));
			option_record->Assign(1, zeek::val_mgr->Count(length));

			switch ( kind ) {
			case 2:
				// MSS
				if ( length == 4 )
					{
					auto mss = ntohs(*reinterpret_cast<const uint16_t*>(o + 2));
					option_record->Assign(3, zeek::val_mgr->Count(mss));
					}
				else
					{
					add_option_data(option_record, o, length);
					Weird("tcp_option_mss_invalid_len", fmt("%d", length));
					}
				break;

			case 3:
				// window scale
				if ( length == 3 )
					{
					auto scale = o[2];
					option_record->Assign(4, zeek::val_mgr->Count(scale));
					}
				else
					{
					add_option_data(option_record, o, length);
					Weird("tcp_option_window_scale_invalid_len", fmt("%d", length));
					}
				break;

			case 4:
				// sack permitted (implicit boolean)
				if ( length != 2 )
					{
					add_option_data(option_record, o, length);
					Weird("tcp_option_sack_invalid_len", fmt("%d", length));
					}
				break;

			case 5:
				// SACK blocks (1-4 pairs of 32-bit begin+end pointers)
				if ( length == 10 || length == 18 ||
				     length == 26 || length == 34 )
					{
					auto p = reinterpret_cast<const uint32_t*>(o + 2);
					auto num_pointers = (length - 2) / 4;
					auto vt = zeek::id::index_vec;
					auto sack = zeek::make_intrusive<zeek::VectorVal>(std::move(vt));

					for ( auto i = 0; i < num_pointers; ++i )
						sack->Assign(sack->Size(), zeek::val_mgr->Count(ntohl(p[i])));

					option_record->Assign(5, sack);
					}
				else
					{
					add_option_data(option_record, o, length);
					Weird("tcp_option_sack_blocks_invalid_len", fmt("%d", length));
					}
				break;

			case 8:
				// timestamps
				if ( length == 10 )
					{
					auto send = ntohl(*reinterpret_cast<const uint32_t*>(o + 2));
					auto echo = ntohl(*reinterpret_cast<const uint32_t*>(o + 6));
					option_record->Assign(6, zeek::val_mgr->Count(send));
					option_record->Assign(7, zeek::val_mgr->Count(echo));
					}
				else
					{
					add_option_data(option_record, o, length);
					Weird("tcp_option_timestamps_invalid_len", fmt("%d", length));
					}
				break;

			default:
				add_option_data(option_record, o, length);
				break;
			}
			}

		EnqueueConnEvent(tcp_options,
			ConnVal(),
			zeek::val_mgr->Bool(is_orig),
			std::move(option_list)
			);
		}

	if ( options < opt_end )
		return -1;

	return 0;
	}

void TCP_Analyzer::AttemptTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( (orig->state == TCP_ENDPOINT_SYN_SENT ||
	      orig->state == TCP_ENDPOINT_SYN_ACK_SENT) &&
	     resp->state == TCP_ENDPOINT_INACTIVE )
		{
		Event(connection_attempt);
		is_active = 0;

		// All done with this connection.
		sessions->Remove(Conn());
		}
	}

void TCP_Analyzer::PartialCloseTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( orig->state != TCP_ENDPOINT_INACTIVE &&
	     resp->state != TCP_ENDPOINT_INACTIVE &&
	     (! orig->did_close || ! resp->did_close) )
		{
		if ( orig->state == TCP_ENDPOINT_RESET ||
		     resp->state == TCP_ENDPOINT_RESET )
			// Presumably the RST is what caused the partial
			// close.  Don't report it.
			return;

		Event(connection_partial_close);
		sessions->Remove(Conn());
		}
	}

void TCP_Analyzer::ExpireTimer(double t)
	{
	if ( ! is_active )
		return;

	if ( Conn()->LastTime() + tcp_connection_linger < t )
		{
		if ( orig->did_close || resp->did_close )
			{
			// No activity for tcp_connection_linger seconds, and
			// at least one side has closed.  See whether
			// connection has likely terminated.
			if ( (orig->did_close && resp->did_close) ||
			     (orig->state == TCP_ENDPOINT_RESET ||
			      resp->state == TCP_ENDPOINT_RESET) ||
			     (orig->state == TCP_ENDPOINT_INACTIVE ||
			      resp->state == TCP_ENDPOINT_INACTIVE) )
				{
				// Either both closed, or one RST,
				// or half-closed.

				// The Timer has Ref()'d us and won't Unref()
				// us until we return, so it's safe to have
				// the session remove and Unref() us here.
				Event(connection_timeout);
				is_active = 0;
				sessions->Remove(Conn());
				return;
				}
			}

		if ( resp->state == TCP_ENDPOINT_INACTIVE )
			{
			if ( orig->state == TCP_ENDPOINT_INACTIVE )
				{
				// Nothing ever happened on this connection.
				// This can occur when we see a trashed
				// packet - it's discarded by NextPacket
				// before setting up an attempt timer,
				// so we need to clean it up here.
				Event(connection_timeout);
				sessions->Remove(Conn());
				return;
				}
			}
		}

	// Connection still active, so reschedule timer.
	// ### if PQ_Element's were Obj's, could just Ref the timer
	// and adjust its value here, instead of creating a new timer.
	ADD_ANALYZER_TIMER(&TCP_Analyzer::ExpireTimer, t + tcp_session_timer,
			false, TIMER_TCP_EXPIRE);
	}

void TCP_Analyzer::ResetTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( ! BothClosed() )
		ConnectionReset();

	sessions->Remove(Conn());
	}

void TCP_Analyzer::DeleteTimer(double /* t */)
	{
	sessions->Remove(Conn());
	}

void TCP_Analyzer::ConnDeleteTimer(double t)
	{
	Conn()->DeleteTimer(t);
	}

void TCP_Analyzer::SetContentsFile(unsigned int direction, BroFilePtr f)
	{
	if ( direction == CONTENTS_NONE )
		{
		orig->SetContentsFile(nullptr);
		resp->SetContentsFile(nullptr);
		}

	else
		{
		if ( direction == CONTENTS_ORIG || direction == CONTENTS_BOTH )
			orig->SetContentsFile(f);
		if ( direction == CONTENTS_RESP || direction == CONTENTS_BOTH )
			resp->SetContentsFile(f);
		}
	}

BroFilePtr TCP_Analyzer::GetContentsFile(unsigned int direction) const
	{
	switch ( direction ) {
	case CONTENTS_NONE:
		return nullptr;

	case CONTENTS_ORIG:
		return orig->GetContentsFile();

	case CONTENTS_RESP:
		return resp->GetContentsFile();

	case CONTENTS_BOTH:
		if ( orig->GetContentsFile() != resp->GetContentsFile())
			// This is an "error".
			return nullptr;
		else
			return orig->GetContentsFile();

	default:
		break;
	}

	reporter->Error("bad direction %u in TCP_Analyzer::GetContentsFile",
	                direction);
	return nullptr;
	}

void TCP_Analyzer::ConnectionClosed(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
					bool gen_event)
	{
	const analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		// Using this type of cast here is nasty (will crash if
		// we inadvertantly have a child analyzer that's not a
		// TCP_ApplicationAnalyzer), but we have to ...
		static_cast<TCP_ApplicationAnalyzer*>
			(*i)->ConnectionClosed(endpoint, peer, gen_event);

	if ( DataPending(endpoint) )
		{
		// Don't close out the connection yet, there's still data to
		// deliver.
		close_deferred = 1;
		if ( ! deferred_gen_event )
			deferred_gen_event = gen_event;
		return;
		}

	close_deferred = 0;

	if ( endpoint->did_close )
		return;	// nothing new to report

	endpoint->did_close = true;

	int close_complete =
		endpoint->state == TCP_ENDPOINT_RESET ||
					peer->did_close ||
					peer->state == TCP_ENDPOINT_INACTIVE;

	if ( DEBUG_tcp_connection_close )
		{
		DEBUG_MSG("%.6f close_complete=%d tcp_close_delay=%f\n",
				network_time, close_complete, tcp_close_delay);
		}

	if ( close_complete )
		{
		if ( endpoint->prev_state != TCP_ENDPOINT_INACTIVE ||
		     peer->state != TCP_ENDPOINT_INACTIVE )
			{
			if ( deferred_gen_event )
				{
				gen_event = true;
				deferred_gen_event = 0;	// clear flag
				}

			// We have something interesting to report.
			if ( gen_event )
				{
				if ( peer->state == TCP_ENDPOINT_INACTIVE )
					ConnectionFinished(true);
				else
					ConnectionFinished(false);
				}
			}

		CancelTimers();

		// Note, even if tcp_close_delay is zero, we can't
		// simply do:
		//
		//	sessions->Remove(this);
		//
		// here, because that would cause the object to be
		// deleted out from under us.
		if ( tcp_close_delay != 0.0 )
			ADD_ANALYZER_TIMER(&TCP_Analyzer::ConnDeleteTimer,
				Conn()->LastTime() + tcp_close_delay, false,
				TIMER_CONN_DELETE);
		else
			ADD_ANALYZER_TIMER(&TCP_Analyzer::DeleteTimer, Conn()->LastTime(), false,
					TIMER_TCP_DELETE);
		}

	else
		{ // We haven't yet seen a full close.
		if ( endpoint->prev_state == TCP_ENDPOINT_INACTIVE )
			{ // First time we've seen anything from this side.
			if ( connection_partial_close )
				ADD_ANALYZER_TIMER(&TCP_Analyzer::PartialCloseTimer,
					Conn()->LastTime() + tcp_partial_close_delay, false,
					TIMER_TCP_PARTIAL_CLOSE );
			}

		else
			{
			// Create a timer to look for the other side closing,
			// too.
			ADD_ANALYZER_TIMER(&TCP_Analyzer::ExpireTimer,
					Conn()->LastTime() + tcp_session_timer, false,
					TIMER_TCP_EXPIRE);
			}
		}
	}

void TCP_Analyzer::ConnectionFinished(bool half_finished)
	{
	const analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		// Again, nasty - see TCP_Analyzer::ConnectionClosed.
		static_cast<TCP_ApplicationAnalyzer*>
			(*i)->ConnectionFinished(half_finished);

	if ( half_finished )
		Event(connection_half_finished);
	else
		Event(connection_finished);

	is_active = 0;
	}

void TCP_Analyzer::ConnectionReset()
	{
	Event(connection_reset);

	const analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		static_cast<TCP_ApplicationAnalyzer*>(*i)->ConnectionReset();

	is_active = 0;
	}

bool TCP_Analyzer::HadGap(bool is_orig) const
	{
	TCP_Endpoint* endp = is_orig ? orig : resp;
	return endp && endp->HadGap();
	}

void TCP_Analyzer::AddChildPacketAnalyzer(zeek::analyzer::Analyzer* a)
	{
	DBG_LOG(DBG_ANALYZER, "%s added packet child %s",
			this->GetAnalyzerName(), a->GetAnalyzerName());

	packet_children.push_back(a);
	a->SetParent(this);
	}

bool TCP_Analyzer::DataPending(TCP_Endpoint* closing_endp)
	{
	if ( Skipping() )
		return false;

	return closing_endp->DataPending();
	}

void TCP_Analyzer::EndpointEOF(TCP_Reassembler* endp)
	{
	if ( connection_EOF )
		EnqueueConnEvent(connection_EOF,
			ConnVal(),
			zeek::val_mgr->Bool(endp->IsOrig())
		);

	const analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		static_cast<TCP_ApplicationAnalyzer*>(*i)->EndpointEOF(endp->IsOrig());

	if ( close_deferred )
		{
		if ( DataPending(endp->Endpoint()) )
			{
			if ( BothClosed() )
				Weird("pending_data_when_closed");

			// Defer further, until the other endpoint
			// EOF's, too.
			}

		ConnectionClosed(endp->Endpoint(), endp->Endpoint()->peer,
					deferred_gen_event);
		close_deferred = 0;
		}
	}

void TCP_Analyzer::PacketWithRST()
	{
	const analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
		static_cast<TCP_ApplicationAnalyzer *>(*i)->PacketWithRST();
	}

bool TCP_Analyzer::IsReuse(double t, const u_char* pkt)
	{
	const struct tcphdr* tp = (const struct tcphdr*) pkt;

	if ( unsigned(tp->th_off) < sizeof(struct tcphdr) / 4 )
		// Bogus header, don't interpret further.
		return false;

	TCP_Endpoint* conn_orig = orig;

	// Reuse only occurs on initial SYN's, except for half connections
	// it can occur on SYN-acks.
	if ( ! (tp->th_flags & TH_SYN) )
		return false;

	if ( (tp->th_flags & TH_ACK) )
		{
		if ( orig->state != TCP_ENDPOINT_INACTIVE )
			// Not a half connection.
			return false;

		conn_orig = resp;
		}

	if ( ! IsClosed() )
		{
		uint32_t base_seq = ntohl(tp->th_seq);
		if ( base_seq == conn_orig->StartSeq() )
			return false;

		if ( (tp->th_flags & TH_ACK) == 0 &&
		     conn_orig->state == TCP_ENDPOINT_SYN_ACK_SENT &&
		     resp->state == TCP_ENDPOINT_INACTIVE &&
		     base_seq == resp->StartSeq() )
			{
			// This is an initial SYN with the right sequence
			// number, and the state is consistent with the
			// SYN & the SYN-ACK being flipped (e.g., due to
			// reading from two interfaces w/ interrupt
			// coalescence).  Don't treat this as a reuse.
			// NextPacket() will flip set the connection
			// state correctly
			return false;
			}

		if ( conn_orig->state == TCP_ENDPOINT_SYN_SENT )
			Weird("SYN_seq_jump");
		else
			Weird("active_connection_reuse");
		}

	else if ( (orig->IsActive() || resp->IsActive()) &&
		  orig->state != TCP_ENDPOINT_RESET &&
		  resp->state != TCP_ENDPOINT_RESET )
		Weird("active_connection_reuse");

	else if ( t - Conn()->LastTime() < tcp_connection_linger &&
		  orig->state != TCP_ENDPOINT_RESET &&
		  resp->state != TCP_ENDPOINT_RESET )
		Weird("premature_connection_reuse");

	return true;
	}

void TCP_ApplicationAnalyzer::Init()
	{
	Analyzer::Init();

	if ( Parent()->IsAnalyzer("TCP") )
		SetTCP(static_cast<TCP_Analyzer*>(Parent()));
	}

void TCP_ApplicationAnalyzer::ProtocolViolation(const char* reason,
						const char* data, int len)
	{
	TCP_Analyzer* tcp = TCP();

	if ( tcp &&
	     (tcp->IsPartial() || tcp->HadGap(false) || tcp->HadGap(true)) )
		// Filter out incomplete connections.  Parsing them is
		// too unreliable.
		return;

	Analyzer::ProtocolViolation(reason, data, len);
	}

void TCP_ApplicationAnalyzer::DeliverPacket(int len, const u_char* data,
						bool is_orig, uint64_t seq,
						const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);
	DBG_LOG(DBG_ANALYZER, "TCP_ApplicationAnalyzer ignoring DeliverPacket(%d, %s, %" PRIu64", %p, %d) [%s%s]",
			len, is_orig ? "T" : "F", seq, ip, caplen,
			fmt_bytes((const char*) data, std::min(40, len)), len > 40 ? "..." : "");
	}

void TCP_ApplicationAnalyzer::SetEnv(bool /* is_orig */, char* name, char* val)
	{
	delete [] name;
	delete [] val;
	}

void TCP_ApplicationAnalyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::SupportAnalyzer* sa = is_orig ? orig_supporters : resp_supporters;
	for ( ; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->EndpointEOF(is_orig);
	}

void TCP_ApplicationAnalyzer::ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, bool gen_event)
	{
	zeek::analyzer::SupportAnalyzer* sa =
		endpoint->IsOrig() ? orig_supporters : resp_supporters;

	for ( ; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)
			->ConnectionClosed(endpoint, peer, gen_event);
	}

void TCP_ApplicationAnalyzer::ConnectionFinished(bool half_finished)
	{
	for ( zeek::analyzer::SupportAnalyzer* sa = orig_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)
			->ConnectionFinished(half_finished);

	for ( zeek::analyzer::SupportAnalyzer* sa = resp_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)
			->ConnectionFinished(half_finished);
	}

void TCP_ApplicationAnalyzer::ConnectionReset()
	{
	for ( zeek::analyzer::SupportAnalyzer* sa = orig_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->ConnectionReset();

	for ( zeek::analyzer::SupportAnalyzer* sa = resp_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->ConnectionReset();
	}

void TCP_ApplicationAnalyzer::PacketWithRST()
	{
	for ( zeek::analyzer::SupportAnalyzer* sa = orig_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->PacketWithRST();

	for ( zeek::analyzer::SupportAnalyzer* sa = resp_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->PacketWithRST();
	}

TCPStats_Endpoint::TCPStats_Endpoint(TCP_Endpoint* e)
	{
	endp = e;
	num_pkts = 0;
	num_rxmit = 0;
	num_rxmit_bytes = 0;
	num_in_order = 0;
	num_OO = 0;
	num_repl = 0;
	max_top_seq = 0;
	last_id = 0;
	endian_type = ENDIAN_UNKNOWN;
	}

int endian_flip(int n)
	{
	return ((n & 0xff) << 8) | ((n & 0xff00) >> 8);
	}

bool TCPStats_Endpoint::DataSent(double /* t */, uint64_t seq, int len, int caplen,
			const u_char* /* data */,
			const IP_Hdr* ip, const struct tcphdr* /* tp */)
	{
	if ( ++num_pkts == 1 )
		{ // First packet.
		last_id = ip->ID();
		return false;
		}

	int id = ip->ID();

	if ( id == last_id )
		{
		++num_repl;
		return false;
		}

	short id_delta = id - last_id;
	short id_endian_delta = endian_flip(id) - endian_flip(last_id);

	int abs_id_delta = id_delta > 0 ? id_delta : -id_delta;
	int abs_id_endian_delta =
		id_endian_delta > 0 ? id_endian_delta : -id_endian_delta;

	int final_id_delta;

	if ( abs_id_delta < abs_id_endian_delta )
		{ // Consistent with big-endian.
		if ( endian_type == ENDIAN_UNKNOWN )
			endian_type = ENDIAN_BIG;
		else if ( endian_type == ENDIAN_BIG )
			;
		else
			endian_type = ENDIAN_CONFUSED;

		final_id_delta = id_delta;
		}
	else
		{ // Consistent with little-endian.
		if ( endian_type == ENDIAN_UNKNOWN )
			endian_type = ENDIAN_LITTLE;
		else if ( endian_type == ENDIAN_LITTLE )
			;
		else
			endian_type = ENDIAN_CONFUSED;

		final_id_delta = id_endian_delta;
		}

	if ( final_id_delta < 0 && final_id_delta > -256 )
		{
		++num_OO;
		return false;
		}

	last_id = id;

	++num_in_order;

	uint64_t top_seq = seq + len;

	int32_t data_in_flight = seq_delta(endp->LastSeq(), endp->AckSeq());
	if ( data_in_flight < 0 )
		data_in_flight = 0;

	int64_t sequence_delta = top_seq - max_top_seq;
	if ( sequence_delta <= 0 )
		{
		if ( ! zeek::BifConst::ignore_keep_alive_rexmit || len > 1 || data_in_flight > 0 )
			{
			++num_rxmit;
			num_rxmit_bytes += len;
			}

		DEBUG_MSG("%.6f rexmit %" PRIu64" + %d <= %" PRIu64" data_in_flight = %d\n",
		 	network_time, seq, len, max_top_seq, data_in_flight);

		if ( tcp_rexmit )
			endp->TCP()->EnqueueConnEvent(tcp_rexmit,
				endp->TCP()->ConnVal(),
				zeek::val_mgr->Bool(endp->IsOrig()),
				zeek::val_mgr->Count(seq),
				zeek::val_mgr->Count(len),
				zeek::val_mgr->Count(data_in_flight),
				zeek::val_mgr->Count(endp->peer->window)
			);
		}
	else
		max_top_seq = top_seq;

	return false;
	}

zeek::RecordVal* TCPStats_Endpoint::BuildStats()
	{
	static auto endpoint_stats = zeek::id::find_type<zeek::RecordType>("endpoint_stats");
	auto* stats = new zeek::RecordVal(endpoint_stats);

	stats->Assign(0, zeek::val_mgr->Count(num_pkts));
	stats->Assign(1, zeek::val_mgr->Count(num_rxmit));
	stats->Assign(2, zeek::val_mgr->Count(num_rxmit_bytes));
	stats->Assign(3, zeek::val_mgr->Count(num_in_order));
	stats->Assign(4, zeek::val_mgr->Count(num_OO));
	stats->Assign(5, zeek::val_mgr->Count(num_repl));
	stats->Assign(6, zeek::val_mgr->Count(endian_type));

	return stats;
	}

TCPStats_Analyzer::TCPStats_Analyzer(Connection* c)
	: TCP_ApplicationAnalyzer("TCPSTATS", c),
	  orig_stats(), resp_stats()
	{
	}

TCPStats_Analyzer::~TCPStats_Analyzer()
	{
	delete orig_stats;
	delete resp_stats;
	}

void TCPStats_Analyzer::Init()
	{
	TCP_ApplicationAnalyzer::Init();

	orig_stats = new TCPStats_Endpoint(TCP()->Orig());
	resp_stats = new TCPStats_Endpoint(TCP()->Resp());
	}

void TCPStats_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	if ( conn_stats )
		EnqueueConnEvent(conn_stats,
			ConnVal(),
			zeek::IntrusivePtr{zeek::AdoptRef{}, orig_stats->BuildStats()},
			zeek::IntrusivePtr{zeek::AdoptRef{}, resp_stats->BuildStats()}
		);
	}

void TCPStats_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	if ( is_orig )
		orig_stats->DataSent(network_time, seq, len, caplen, data, ip, nullptr);
	else
		resp_stats->DataSent(network_time, seq, len, caplen, data, ip, nullptr);
	}
