// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

#include "zeek/RunState.h"
#include "zeek/Val.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"
#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/analyzer/protocol/tcp/types.bif.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"

constexpr int ORIG = 1;
constexpr int RESP = 2;
constexpr int32_t TOO_LARGE_SEQ_DELTA = 1048576;

using namespace zeek;
using namespace zeek::packet_analysis::TCP;

TCPSessionAdapter::TCPSessionAdapter(Connection* conn)
	: packet_analysis::IP::SessionAdapter("TCP", conn)
	{
	// Set a timer to eventually time out this connection.
	ADD_ANALYZER_TIMER(&TCPSessionAdapter::ExpireTimer,
	                   run_state::network_time + detail::tcp_SYN_timeout, false,
	                   detail::TIMER_TCP_EXPIRE);

	deferred_gen_event = close_deferred = 0;

	seen_first_ACK = 0;
	is_active = 1;
	finished = 0;
	reassembling = 0;
	first_packet_seen = 0;
	is_partial = 0;

	orig = new analyzer::tcp::TCP_Endpoint(this, true);
	resp = new analyzer::tcp::TCP_Endpoint(this, false);

	orig->SetPeer(resp);
	resp->SetPeer(orig);
	}

TCPSessionAdapter::~TCPSessionAdapter()
	{
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
	delete *i;

	delete orig;
	delete resp;
	}

void TCPSessionAdapter::Init()
	{
	Analyzer::Init();
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
	(*i)->Init();
	}

void TCPSessionAdapter::Done()
	{
	Analyzer::Done();

	if ( run_state::terminating && connection_pending && is_active && ! BothClosed() )
		Event(connection_pending);

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
	(*i)->Done();

	orig->Done();
	resp->Done();

	finished = 1;
	}

static int get_segment_len(int payload_len, analyzer::tcp::TCP_Flags flags)
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

static void init_endpoint(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Flags flags,
                          uint32_t first_seg_seq, uint32_t last_seq, double t)
	{
	switch ( endpoint->state )
		{
		case analyzer::tcp::TCP_ENDPOINT_INACTIVE:
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

		case analyzer::tcp::TCP_ENDPOINT_SYN_SENT:
		case analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT:
			if ( flags.SYN() && first_seg_seq != endpoint->StartSeq() )
				{
				endpoint->Conn()->Weird("SYN_seq_jump");
				endpoint->InitStartSeq(first_seg_seq);
				endpoint->InitAckSeq(first_seg_seq);
				endpoint->InitLastSeq(last_seq);
				}
			break;

		case analyzer::tcp::TCP_ENDPOINT_ESTABLISHED:
		case analyzer::tcp::TCP_ENDPOINT_PARTIAL:
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

		case analyzer::tcp::TCP_ENDPOINT_RESET:
			if ( flags.SYN() )
				{
				if ( endpoint->prev_state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
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

static uint64_t get_relative_seq(const analyzer::tcp::TCP_Endpoint* endpoint, uint32_t cur_base,
                                 uint32_t last, uint32_t wraps, bool* underflow)
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

static void update_history(analyzer::tcp::TCP_Flags flags, analyzer::tcp::TCP_Endpoint* endpoint,
                           uint64_t rel_seq, int len)
	{
	int bits_set = (flags.SYN() ? 1 : 0) + (flags.FIN() ? 1 : 0) + (flags.RST() ? 1 : 0);
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

			if ( endpoint->CheckHistory(HIST_SYN_PKT, code) && rel_seq != endpoint->hist_last_SYN )
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
			if ( endpoint->CheckHistory(HIST_RST_PKT, 'R') && rel_seq != endpoint->hist_last_RST )
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

static void update_window(analyzer::tcp::TCP_Endpoint* endpoint, unsigned int window,
                          uint32_t base_seq, uint32_t ack_seq, analyzer::tcp::TCP_Flags flags)
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
	     endpoint->peer->state != analyzer::tcp::TCP_ENDPOINT_CLOSED &&
	     endpoint->state != analyzer::tcp::TCP_ENDPOINT_RESET )
		endpoint->ZeroWindow();

	// Don't analyze window values off of SYNs, they're sometimes
	// immediately rescinded.  Also don't do so for FINs or RSTs,
	// or if the connection has already been partially closed, since
	// such recisions occur frequently in practice, probably as the
	// receiver loses buffer memory due to its process going away.

	if ( ! flags.SYN() && ! flags.FIN() && ! flags.RST() &&
	     endpoint->state != analyzer::tcp::TCP_ENDPOINT_CLOSED &&
	     endpoint->state != analyzer::tcp::TCP_ENDPOINT_RESET )
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

static zeek::RecordValPtr build_syn_packet_val(bool is_orig, const zeek::IP_Hdr* ip,
                                               const struct tcphdr* tcp)
	{
	int winscale = -1;
	int MSS = 0;
	int SACK = 0;
	std::optional<uint64_t> TSval;
	std::optional<uint64_t> TSecr;

	// Parse TCP options.
	u_char* options = (u_char*)tcp + sizeof(struct tcphdr);
	u_char* opt_end = (u_char*)tcp + tcp->th_off * 4;

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

		switch ( opt )
			{
			case TCPOPT_SACK_PERMITTED:
				SACK = 1;
				break;

			case TCPOPT_MAXSEG:
				if ( opt_len < 4 )
					break; // bad length

				MSS = (options[2] << 8) | options[3];
				break;

			case 3: // TCPOPT_WSCALE
				if ( opt_len < 3 )
					break; // bad length

				winscale = options[2];
				break;

			case 8: // TCPOPT_TIMESTAMP
				if ( opt_len < 10 )
					break; // bad length

				TSval =
					(((((static_cast<uint64_t>(options[2]) << 8) | options[3]) << 8) | options[4])
				     << 8) |
					options[5];
				TSecr =
					(((((static_cast<uint64_t>(options[6]) << 8) | options[7]) << 8) | options[8])
				     << 8) |
					options[9];
				break;

			default: // just skip over
				break;
			}

		options += opt_len;
		}

	static auto SYN_packet = zeek::id::find_type<zeek::RecordType>("SYN_packet");
	auto v = zeek::make_intrusive<zeek::RecordVal>(SYN_packet);

	v->Assign(0, is_orig);
	v->Assign(1, static_cast<bool>(ip->DF()));
	v->Assign(2, ip->TTL());
	v->Assign(3, ip->TotalLen());
	v->Assign(4, ntohs(tcp->th_win));
	v->Assign(5, winscale);
	v->Assign(6, MSS);
	v->Assign(7, static_cast<bool>(SACK));

	if ( TSval )
		v->Assign(8, *TSval);

	if ( TSecr )
		v->Assign(9, *TSecr);

	return v;
	}

static void init_window(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                        analyzer::tcp::TCP_Flags flags, zeek_int_t scale, uint32_t base_seq,
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

static void init_peer(analyzer::tcp::TCP_Endpoint* peer, analyzer::tcp::TCP_Endpoint* endpoint,
                      analyzer::tcp::TCP_Flags flags, uint32_t ack_seq)
	{
	if ( ! flags.SYN() && ! flags.FIN() && ! flags.RST() )
		{
		if ( endpoint->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT ||
		     endpoint->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT ||
		     endpoint->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
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

static void update_ack_seq(analyzer::tcp::TCP_Endpoint* endpoint, uint32_t ack_seq)
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
static int32_t update_last_seq(analyzer::tcp::TCP_Endpoint* endpoint, uint32_t last_seq,
                               analyzer::tcp::TCP_Flags flags, int len)
	{
	int32_t delta_last = seq_delta(last_seq, endpoint->LastSeq());

	if ( (flags.SYN() || flags.RST()) &&
	     (delta_last > TOO_LARGE_SEQ_DELTA || delta_last < -TOO_LARGE_SEQ_DELTA) )
		// ### perhaps trust RST seq #'s if initial and not too
		// outlandish, but not if they're coming after the other
		// side has sent a FIN - trust the FIN ack instead
		;

	else if ( flags.FIN() && endpoint->LastSeq() == endpoint->StartSeq() + 1 )
		// Update last_seq based on the FIN even if delta_last < 0.
		// This is to accommodate > 2 GB connections for which
		// we've only seen the SYN and the FIN (hence the check
		// for last_seq == start_seq + 1).
		endpoint->UpdateLastSeq(last_seq);

	else if ( endpoint->state == analyzer::tcp::TCP_ENDPOINT_RESET )
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

void TCPSessionAdapter::Process(bool is_orig, const struct tcphdr* tp, int len,
                                const std::shared_ptr<IP_Hdr>& ip, const u_char* data,
                                int remaining)
	{
	analyzer::tcp::TCP_Flags flags(tp);
	uint32_t base_seq = ntohl(tp->th_seq);
	uint32_t ack_seq = ntohl(tp->th_ack);
	uint32_t tcp_hdr_len = data - (const u_char*)tp;

	analyzer::tcp::TCP_Endpoint* endpoint = is_orig ? orig : resp;
	analyzer::tcp::TCP_Endpoint* peer = endpoint->peer;

	SetPartialStatus(flags, endpoint->IsOrig());

	int seg_len = get_segment_len(len, flags);
	uint32_t seq_one_past_segment = base_seq + seg_len;

	init_endpoint(endpoint, flags, base_seq, seq_one_past_segment, run_state::current_timestamp);

	bool seq_underflow = false;
	uint64_t rel_seq = get_relative_seq(endpoint, base_seq, endpoint->LastSeq(),
	                                    endpoint->SeqWraps(), &seq_underflow);

	if ( seq_underflow && ! flags.RST() )
		// Can't tell if if this is a retransmit/out-of-order or something
		// before the sequence Zeek initialized the endpoint at or the TCP is
		// just broken and sending garbage sequences.  In either case, some
		// standard analysis doesn't apply (e.g. reassembly).
		Weird("TCP_seq_underflow_or_misorder");

	update_history(flags, endpoint, rel_seq, len);
	update_window(endpoint, ntohs(tp->th_win), base_seq, ack_seq, flags);

	if ( ! orig->did_close || ! resp->did_close )
		Conn()->SetLastTime(run_state::current_timestamp);

	if ( flags.SYN() )
		{
		SynWeirds(flags, endpoint, len);
		RecordValPtr SYN_vals = build_syn_packet_val(is_orig, ip.get(), tp);
		init_window(endpoint, peer, flags, SYN_vals->GetFieldAs<IntVal>(5), base_seq, ack_seq);

		if ( connection_SYN_packet )
			EnqueueConnEvent(connection_SYN_packet, ConnVal(), SYN_vals);
		}

	if ( flags.FIN() )
		{
		++endpoint->FIN_cnt;

		if ( endpoint->FIN_cnt >= detail::tcp_storm_thresh &&
		     run_state::current_timestamp <
		         endpoint->last_time + detail::tcp_storm_interarrival_thresh )
			Weird("FIN_storm");

		endpoint->FIN_seq = rel_seq + seg_len;
		}

	if ( flags.RST() )
		{
		++endpoint->RST_cnt;

		if ( endpoint->RST_cnt >= detail::tcp_storm_thresh &&
		     run_state::current_timestamp <
		         endpoint->last_time + detail::tcp_storm_interarrival_thresh )
			Weird("RST_storm");

		// This now happens often enough that it's
		// not in the least interesting.
		// if ( len > 0 )
		//	Weird("RST_with_data");

		PacketWithRST();
		}

	uint64_t rel_ack = 0;

	if ( flags.ACK() )
		{
		if ( is_orig && ! seen_first_ACK &&
		     (endpoint->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED ||
		      endpoint->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT) )
			{
			seen_first_ACK = 1;
			Event(connection_first_ACK);
			}

		if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{
			rel_ack = 1;
			init_peer(peer, endpoint, flags, ack_seq);
			}
		else
			{
			bool ack_underflow = false;
			rel_ack = get_relative_seq(peer, ack_seq, peer->AckSeq(), peer->AckWraps(),
			                           &ack_underflow);

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
	endpoint->last_time = run_state::current_timestamp;

	bool do_close;
	bool gen_event;
	UpdateStateMachine(run_state::current_timestamp, endpoint, peer, base_seq, ack_seq, len,
	                   delta_last, is_orig, flags, do_close, gen_event);

	if ( flags.ACK() )
		// We wait on doing this until we've updated the state
		// machine so that if the ack reveals a content gap,
		// we can tell whether it came at the very end of the
		// connection (in a FIN or RST).  Those gaps aren't
		// reliable - especially those for RSTs - and we refrain
		// from flagging them in the connection history.
		peer->AckReceived(rel_ack);

	if ( tcp_packet )
		GeneratePacketEvent(rel_seq, rel_ack, data, len, remaining, is_orig, flags);

	if ( (tcp_option || tcp_options) && tcp_hdr_len > sizeof(*tp) )
		ParseTCPOptions(tp, is_orig);

	// PIA/signature matching state needs to be initialized before
	// processing/reassembling any TCP data, since that processing may
	// itself try to perform signature matching.  Also note that a SYN
	// packet may technically carry data (see RFC793 Section 3.4 and also
	// TCP Fast Open).
	CheckPIA_FirstPacket(is_orig, ip.get());

	if ( DEBUG_tcp_data_sent )
		{
		DEBUG_MSG("%.6f before DataSent: len=%d remaining=%d skip=%d\n", run_state::network_time,
		          len, remaining, Skipping());
		}

	rel_data_seq = flags.SYN() ? rel_seq + 1 : rel_seq;

	bool need_contents = false;
	if ( len > 0 && (remaining >= len || ! packet_children.empty()) && ! flags.RST() &&
	     ! Skipping() && ! seq_underflow )
		need_contents = endpoint->DataSent(run_state::current_timestamp, rel_data_seq, len,
		                                   remaining, data, ip.get(), tp);

	endpoint->CheckEOF();

	if ( do_close )
		{
		// We need to postpone doing this until after we process
		// DataSent, so we don't generate a connection_finished event
		// until after data perhaps included with the FIN is processed.
		ConnectionClosed(endpoint, peer, gen_event);
		}

	CheckRecording(need_contents, flags);
	}

analyzer::Analyzer* TCPSessionAdapter::FindChild(analyzer::ID arg_id)
	{
	analyzer::Analyzer* child = packet_analysis::IP::SessionAdapter::FindChild(arg_id);

	if ( child )
		return child;

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		{
		analyzer::Analyzer* child = (*i)->FindChild(arg_id);
		if ( child )
			return child;
		}

	return nullptr;
	}

analyzer::Analyzer* TCPSessionAdapter::FindChild(zeek::Tag arg_tag)
	{
	analyzer::Analyzer* child = packet_analysis::IP::SessionAdapter::FindChild(arg_tag);

	if ( child )
		return child;

	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
		{
		analyzer::Analyzer* child = (*i)->FindChild(arg_tag);
		if ( child )
			return child;
		}

	return nullptr;
	}

bool TCPSessionAdapter::RemoveChildAnalyzer(analyzer::ID id)
	{
	auto rval = packet_analysis::IP::SessionAdapter::RemoveChildAnalyzer(id);

	if ( rval )
		return rval;

	return RemoveChild(packet_children, id);
	}

void TCPSessionAdapter::EnableReassembly()
	{
	SetReassembler(new analyzer::tcp::TCP_Reassembler(
					   this, this, analyzer::tcp::TCP_Reassembler::Forward, orig),
	               new analyzer::tcp::TCP_Reassembler(
					   this, this, analyzer::tcp::TCP_Reassembler::Forward, resp));
	}

void TCPSessionAdapter::SetReassembler(analyzer::tcp::TCP_Reassembler* rorig,
                                       analyzer::tcp::TCP_Reassembler* rresp)
	{
	orig->AddReassembler(rorig);
	rorig->SetDstAnalyzer(this);
	resp->AddReassembler(rresp);
	rresp->SetDstAnalyzer(this);

	if ( new_connection_contents && reassembling == 0 )
		Event(new_connection_contents);

	reassembling = 1;
	}

void TCPSessionAdapter::SetPartialStatus(analyzer::tcp::TCP_Flags flags, bool is_orig)
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

void TCPSessionAdapter::UpdateInactiveState(double t, analyzer::tcp::TCP_Endpoint* endpoint,
                                            analyzer::tcp::TCP_Endpoint* peer, uint32_t base_seq,
                                            uint32_t ack_seq, int len, bool is_orig,
                                            analyzer::tcp::TCP_Flags flags, bool& do_close,
                                            bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( is_orig )
			{
			if ( flags.ACK() )
				{
				Weird("connection_originator_SYN_ack");
				endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT);
				}
			else
				endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_SYN_SENT);

			if ( zeek::detail::tcp_attempt_delay )
				ADD_ANALYZER_TIMER(&TCPSessionAdapter::AttemptTimer, t + detail::tcp_attempt_delay,
				                   true, detail::TIMER_TCP_ATTEMPT);
			}
		else
			{
			if ( flags.ACK() )
				{
				if ( peer->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
				     peer->state != analyzer::tcp::TCP_ENDPOINT_PARTIAL &&
				     ! seq_between(ack_seq, peer->StartSeq(), peer->LastSeq()) )
					Weird("bad_SYN_ack");
				}

			else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT &&
			          base_seq == endpoint->StartSeq() )
				{
				// This is a SYN/SYN-ACK reversal,
				// per the discussion in IsReuse.
				// Flip the endpoints and establish
				// the connection.
				is_partial = 0;
				Conn()->FlipRoles();
				peer->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
				}

			else
				Weird("simultaneous_open");

			if ( peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
				peer->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
			else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
				{
				// If we were to ignore SYNs and
				// only instantiate state on SYN
				// acks, then we'd do:
				//    peer->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
				// here.
				Weird("unsolicited_SYN_response");
				}

			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);

			if ( peer->state != analyzer::tcp::TCP_ENDPOINT_PARTIAL )
				{
				Event(connection_established);
				Conn()->EnableStatusUpdateTimer();
				}
			}
		}

	if ( flags.FIN() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);
		do_close = gen_event = true;
		if ( peer->state != analyzer::tcp::TCP_ENDPOINT_PARTIAL && ! flags.SYN() )
			Weird("spontaneous_FIN");
		}

	if ( flags.RST() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);

		bool is_reject = false;

		if ( is_orig )
			{
			// If our peer is established then we saw
			// a SYN-ack but not SYN - so a reverse
			// scan, and we should treat this as a
			// reject.
			if ( peer->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
				is_reject = true;
			}

		else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT ||
		          peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT )
			// We're rejecting an initial SYN.
			is_reject = true;

		do_close = true;
		gen_event = ! is_reject;

		if ( is_reject )
			Event(connection_rejected);

		else if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			Weird("spontaneous_RST");
		}

	if ( endpoint->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
		{ // No control flags to change the state.
		if ( ! is_orig && len == 0 && orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
			// Some eccentric TCP's will ack an initial
			// SYN prior to sending a SYN reply (hello,
			// ftp.microsoft.com).  For those, don't
			// consider the ack as forming a partial
			// connection.
			;

		else if ( flags.ACK() && peer->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
			{
			// No SYN packet from originator but SYN/ACK from
			// responder, and now a pure ACK. Probably means we
			// just missed that initial SYN. Let's not treat it
			// as partial and instead establish the connection.
			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_ESTABLISHED);
			is_partial = 0;
			}

		else
			{
			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_PARTIAL);
			Conn()->EnableStatusUpdateTimer();

			if ( peer->state == analyzer::tcp::TCP_ENDPOINT_PARTIAL )
				// We've seen both sides of a partial
				// connection, report it.
				Event(partial_connection);
			}
		}
	}

void TCPSessionAdapter::UpdateSYN_SentState(analyzer::tcp::TCP_Endpoint* endpoint,
                                            analyzer::tcp::TCP_Endpoint* peer, int len,
                                            bool is_orig, analyzer::tcp::TCP_Flags flags,
                                            bool& do_close, bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( is_orig )
			{
			if ( flags.ACK() && ! flags.FIN() && ! flags.RST() &&
			     endpoint->state != analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT )
				Weird("repeated_SYN_with_ack");
			}
		else
			{
			if ( ! flags.ACK() && endpoint->state != analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
				Weird("repeated_SYN_reply_wo_ack");
			}
		}

	if ( flags.FIN() )
		{
		if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
		     peer->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
			Weird("inappropriate_FIN");

		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);
		do_close = gen_event = true;
		}

	if ( flags.RST() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);
		ConnectionReset();
		do_close = true;
		}

	else if ( len > 0 )
		Weird("data_before_established");
	}

void TCPSessionAdapter::UpdateEstablishedState(analyzer::tcp::TCP_Endpoint* endpoint,
                                               analyzer::tcp::TCP_Endpoint* peer,
                                               analyzer::tcp::TCP_Flags flags, bool& do_close,
                                               bool& gen_event)
	{
	if ( flags.SYN() )
		{
		if ( endpoint->state == analyzer::tcp::TCP_ENDPOINT_PARTIAL &&
		     peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE && ! flags.ACK() )
			{
			Weird("SYN_after_partial");
			endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_SYN_SENT);
			}
		}

	if ( flags.FIN() && ! flags.RST() ) // ###
		{ // should check sequence/ack numbers here ###
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);

		if ( peer->state == analyzer::tcp::TCP_ENDPOINT_RESET &&
		     peer->prev_state == analyzer::tcp::TCP_ENDPOINT_CLOSED )
			// The peer sent a FIN followed by a RST.
			// Turn it back into CLOSED state, because
			// this was actually normal termination.
			peer->SetState(analyzer::tcp::TCP_ENDPOINT_CLOSED);

		do_close = gen_event = true;
		}

	if ( flags.RST() )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);
		do_close = true;

		if ( peer->state != analyzer::tcp::TCP_ENDPOINT_RESET ||
		     peer->prev_state != analyzer::tcp::TCP_ENDPOINT_ESTABLISHED )
			ConnectionReset();
		}
	}

void TCPSessionAdapter::UpdateClosedState(double t, analyzer::tcp::TCP_Endpoint* endpoint,
                                          int32_t delta_last, analyzer::tcp::TCP_Flags flags,
                                          bool& do_close)
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
	if ( flags.RST() && endpoint->peer->state != analyzer::tcp::TCP_ENDPOINT_CLOSED )
		{
		endpoint->SetState(analyzer::tcp::TCP_ENDPOINT_RESET);

		if ( ! endpoint->did_close )
			// RST after FIN.
			do_close = true;

		if ( connection_reset )
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::ResetTimer, t + zeek::detail::tcp_reset_delay,
			                   true, zeek::detail::TIMER_TCP_RESET);
		}
	}

void TCPSessionAdapter::UpdateResetState(int len, analyzer::tcp::TCP_Flags flags)
	{
	if ( flags.SYN() )
		Weird("SYN_after_reset");

	if ( flags.FIN() )
		Weird("FIN_after_reset");

	if ( len > 0 && ! flags.RST() )
		Weird("data_after_reset");
	}

void TCPSessionAdapter::UpdateStateMachine(double t, analyzer::tcp::TCP_Endpoint* endpoint,
                                           analyzer::tcp::TCP_Endpoint* peer, uint32_t base_seq,
                                           uint32_t ack_seq, int len, int32_t delta_last,
                                           bool is_orig, analyzer::tcp::TCP_Flags flags,
                                           bool& do_close, bool& gen_event)
	{
	do_close = false; // whether to report the connection as closed
	gen_event = false; // if so, whether to generate an event

	switch ( endpoint->state )
		{

		case analyzer::tcp::TCP_ENDPOINT_INACTIVE:
			UpdateInactiveState(t, endpoint, peer, base_seq, ack_seq, len, is_orig, flags, do_close,
			                    gen_event);
			break;

		case analyzer::tcp::TCP_ENDPOINT_SYN_SENT:
		case analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT:
			UpdateSYN_SentState(endpoint, peer, len, is_orig, flags, do_close, gen_event);
			break;

		case analyzer::tcp::TCP_ENDPOINT_ESTABLISHED:
		case analyzer::tcp::TCP_ENDPOINT_PARTIAL:
			UpdateEstablishedState(endpoint, peer, flags, do_close, gen_event);
			break;

		case analyzer::tcp::TCP_ENDPOINT_CLOSED:
			UpdateClosedState(t, endpoint, delta_last, flags, do_close);
			break;

		case analyzer::tcp::TCP_ENDPOINT_RESET:
			UpdateResetState(len, flags);
			break;
		}
	}

void TCPSessionAdapter::GeneratePacketEvent(uint64_t rel_seq, uint64_t rel_ack, const u_char* data,
                                            int len, int caplen, bool is_orig,
                                            analyzer::tcp::TCP_Flags flags)
	{
	EnqueueConnEvent(tcp_packet, ConnVal(), val_mgr->Bool(is_orig),
	                 make_intrusive<StringVal>(flags.AsString()), val_mgr->Count(rel_seq),
	                 val_mgr->Count(flags.ACK() ? rel_ack : 0), val_mgr->Count(len),
	                 // We need the min() here because Ethernet padding can lead to
	                 // caplen > len.
	                 make_intrusive<StringVal>(std::min(caplen, len), (const char*)data));
	}

bool TCPSessionAdapter::DeliverData(double t, const u_char* data, int len, int caplen,
                                    const IP_Hdr* ip, const struct tcphdr* tp,
                                    analyzer::tcp::TCP_Endpoint* endpoint, uint64_t rel_data_seq,
                                    bool is_orig, analyzer::tcp::TCP_Flags flags)
	{
	return endpoint->DataSent(t, rel_data_seq, len, caplen, data, ip, tp);
	}

void TCPSessionAdapter::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq,
                                      const IP_Hdr* ip, int caplen)
	{
	// Handle child_packet analyzers.  Note: This happens *after* the
	// packet has been processed and the TCP state updated.
	analyzer::analyzer_list::iterator next;

	for ( auto i = packet_children.begin(); i != packet_children.end(); /* nop */ )
		{
		auto child = *i;

		if ( child->IsFinished() || child->Removing() )
			{
			if ( child->Removing() )
				child->Done();

			DBG_LOG(DBG_ANALYZER, "%s deleted child %s", fmt_analyzer(this).c_str(),
			        fmt_analyzer(child).c_str());
			i = packet_children.erase(i);
			delete child;
			}
		else
			{
			child->NextPacket(len, data, is_orig, seq, ip, caplen);
			++i;
			}
		}

	if ( ! reassembling )
		ForwardPacket(len, data, is_orig, seq, ip, caplen);
	}

void TCPSessionAdapter::DeliverStream(int len, const u_char* data, bool orig)
	{
	Analyzer::DeliverStream(len, data, orig);
	}

void TCPSessionAdapter::Undelivered(uint64_t seq, int len, bool is_orig)
	{
	Analyzer::Undelivered(seq, len, orig);
	}

void TCPSessionAdapter::FlipRoles()
	{
	Analyzer::FlipRoles();

	TCPAnalyzer::GetStats().FlipState(orig->state, resp->state);
	analyzer::tcp::TCP_Endpoint* tmp_ep = resp;
	resp = orig;
	orig = tmp_ep;
	orig->is_orig = ! orig->is_orig;
	resp->is_orig = ! resp->is_orig;
	}

void TCPSessionAdapter::UpdateConnVal(RecordVal* conn_val)
	{
	auto orig_endp_val = conn_val->GetFieldAs<RecordVal>("orig");
	auto resp_endp_val = conn_val->GetFieldAs<RecordVal>("resp");

	orig_endp_val->Assign(0, orig->Size());
	orig_endp_val->Assign(1, orig->state);
	resp_endp_val->Assign(0, resp->Size());
	resp_endp_val->Assign(1, resp->state);

	// Call children's UpdateConnVal
	Analyzer::UpdateConnVal(conn_val);

	// Have to do packet_children ourselves.
	LOOP_OVER_GIVEN_CHILDREN(i, packet_children)
	(*i)->UpdateConnVal(conn_val);
	}

void TCPSessionAdapter::AttemptTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( (orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT ||
	      orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT) &&
	     resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
		{
		Event(connection_attempt);
		is_active = 0;

		// All done with this connection.
		session_mgr->Remove(Conn());
		}
	}

void TCPSessionAdapter::PartialCloseTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( orig->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
	     resp->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
	     (! orig->did_close || ! resp->did_close) )
		{
		if ( orig->state == analyzer::tcp::TCP_ENDPOINT_RESET ||
		     resp->state == analyzer::tcp::TCP_ENDPOINT_RESET )
			// Presumably the RST is what caused the partial
			// close.  Don't report it.
			return;

		Event(connection_partial_close);
		session_mgr->Remove(Conn());
		}
	}

void TCPSessionAdapter::ExpireTimer(double t)
	{
	if ( ! is_active )
		return;

	if ( Conn()->LastTime() + zeek::detail::tcp_connection_linger < t )
		{
		if ( orig->did_close || resp->did_close )
			{
			// No activity for tcp_connection_linger seconds, and
			// at least one side has closed.  See whether
			// connection has likely terminated.
			if ( (orig->did_close && resp->did_close) ||
			     (orig->state == analyzer::tcp::TCP_ENDPOINT_RESET ||
			      resp->state == analyzer::tcp::TCP_ENDPOINT_RESET) ||
			     (orig->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
			      resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE) )
				{
				// Either both closed, or one RST,
				// or half-closed.

				// The Timer has Ref()'d us and won't Unref()
				// us until we return, so it's safe to have
				// the session remove and Unref() us here.
				Event(connection_timeout);
				is_active = 0;
				session_mgr->Remove(Conn());
				return;
				}
			}

		if ( resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{
			if ( orig->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
				{
				// Nothing ever happened on this connection.
				// This can occur when we see a trashed
				// packet - it's discarded by NextPacket
				// before setting up an attempt timer,
				// so we need to clean it up here.
				Event(connection_timeout);
				session_mgr->Remove(Conn());
				return;
				}
			}
		}

	// Connection still active, so reschedule timer.
	// ### if PQ_Element's were Obj's, could just Ref the timer
	// and adjust its value here, instead of creating a new timer.
	ADD_ANALYZER_TIMER(&TCPSessionAdapter::ExpireTimer, t + zeek::detail::tcp_session_timer, false,
	                   zeek::detail::TIMER_TCP_EXPIRE);
	}

void TCPSessionAdapter::ResetTimer(double /* t */)
	{
	if ( ! is_active )
		return;

	if ( ! BothClosed() )
		ConnectionReset();

	session_mgr->Remove(Conn());
	}

void TCPSessionAdapter::DeleteTimer(double /* t */)
	{
	session_mgr->Remove(Conn());
	}

void TCPSessionAdapter::ConnDeleteTimer(double t)
	{
	Conn()->DeleteTimer(t);
	}

void TCPSessionAdapter::SetContentsFile(unsigned int direction, FilePtr f)
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

FilePtr TCPSessionAdapter::GetContentsFile(unsigned int direction) const
	{
	switch ( direction )
		{
		case CONTENTS_NONE:
			return nullptr;

		case CONTENTS_ORIG:
			return orig->GetContentsFile();

		case CONTENTS_RESP:
			return resp->GetContentsFile();

		case CONTENTS_BOTH:
			if ( orig->GetContentsFile() != resp->GetContentsFile() )
				// This is an "error".
				return nullptr;
			else
				return orig->GetContentsFile();

		default:
			break;
		}

	reporter->Error("bad direction %u in TCPSessionAdapter::GetContentsFile", direction);
	return nullptr;
	}

void TCPSessionAdapter::ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
                                         analyzer::tcp::TCP_Endpoint* peer, bool gen_event)
	{
	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
	// Using this type of cast here is nasty (will crash if
	// we inadvertantly have a child analyzer that's not a
	// TCP_ApplicationAnalyzer), but we have to ...
	static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->ConnectionClosed(endpoint, peer,
	                                                                           gen_event);

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
		return; // nothing new to report

	endpoint->did_close = true;

	int close_complete = endpoint->state == analyzer::tcp::TCP_ENDPOINT_RESET || peer->did_close ||
	                     peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE;

	if ( DEBUG_tcp_connection_close )
		{
		DEBUG_MSG("%.6f close_complete=%d tcp_close_delay=%f\n", run_state::network_time,
		          close_complete, detail::tcp_close_delay);
		}

	if ( close_complete )
		{
		if ( endpoint->prev_state != analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
		     peer->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{
			if ( deferred_gen_event )
				{
				gen_event = true;
				deferred_gen_event = 0; // clear flag
				}

			// We have something interesting to report.
			if ( gen_event )
				{
				if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
					ConnectionFinished(true);
				else
					ConnectionFinished(false);
				}
			}

		CancelTimers();

		// Note, even if tcp_close_delay is zero, we can't
		// simply do:
		//
		//	session_mgr->Remove(this);
		//
		// here, because that would cause the object to be
		// deleted out from under us.
		if ( zeek::detail::tcp_close_delay != 0.0 )
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::ConnDeleteTimer,
			                   Conn()->LastTime() + zeek::detail::tcp_close_delay, false,
			                   zeek::detail::TIMER_CONN_DELETE);
		else
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::DeleteTimer, Conn()->LastTime(), false,
			                   zeek::detail::TIMER_TCP_DELETE);
		}

	else
		{ // We haven't yet seen a full close.
		if ( endpoint->prev_state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			{ // First time we've seen anything from this side.
			if ( connection_partial_close )
				ADD_ANALYZER_TIMER(&TCPSessionAdapter::PartialCloseTimer,
				                   Conn()->LastTime() + zeek::detail::tcp_partial_close_delay,
				                   false, zeek::detail::TIMER_TCP_PARTIAL_CLOSE);
			}

		else
			{
			// Create a timer to look for the other side closing,
			// too.
			ADD_ANALYZER_TIMER(&TCPSessionAdapter::ExpireTimer,
			                   Conn()->LastTime() + zeek::detail::tcp_session_timer, false,
			                   zeek::detail::TIMER_TCP_EXPIRE);
			}
		}
	}

void TCPSessionAdapter::ConnectionFinished(bool half_finished)
	{
	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
	// Again, nasty - see TCPSessionAdapter::ConnectionClosed.
	static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->ConnectionFinished(half_finished);

	if ( half_finished )
		Event(connection_half_finished);
	else
		Event(connection_finished);

	is_active = 0;
	}

void TCPSessionAdapter::ConnectionReset()
	{
	Event(connection_reset);

	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
	static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->ConnectionReset();

	is_active = 0;
	}

bool TCPSessionAdapter::HadGap(bool is_orig) const
	{
	analyzer::tcp::TCP_Endpoint* endp = is_orig ? orig : resp;
	return endp && endp->HadGap();
	}

void TCPSessionAdapter::AddChildPacketAnalyzer(analyzer::Analyzer* a)
	{
	DBG_LOG(DBG_ANALYZER, "%s added packet child %s", this->GetAnalyzerName(),
	        a->GetAnalyzerName());

	packet_children.push_back(a);
	a->SetParent(this);
	}

bool TCPSessionAdapter::DataPending(analyzer::tcp::TCP_Endpoint* closing_endp)
	{
	if ( Skipping() )
		return false;

	return closing_endp->DataPending();
	}

void TCPSessionAdapter::EndpointEOF(analyzer::tcp::TCP_Reassembler* endp)
	{
	if ( connection_EOF )
		EnqueueConnEvent(connection_EOF, ConnVal(), val_mgr->Bool(endp->IsOrig()));

	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
	static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->EndpointEOF(endp->IsOrig());

	if ( close_deferred )
		{
		if ( DataPending(endp->Endpoint()) )
			{
			if ( BothClosed() )
				Weird("pending_data_when_closed");

			// Defer further, until the other endpoint
			// EOF's, too.
			}

		ConnectionClosed(endp->Endpoint(), endp->Endpoint()->peer, deferred_gen_event);
		close_deferred = 0;
		}
	}

void TCPSessionAdapter::PacketWithRST()
	{
	const analyzer::analyzer_list& children(GetChildren());
	LOOP_OVER_CONST_CHILDREN(i)
	static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(*i)->PacketWithRST();
	}

void TCPSessionAdapter::CheckPIA_FirstPacket(bool is_orig, const IP_Hdr* ip)
	{
	if ( is_orig && ! (first_packet_seen & ORIG) )
		{
		if ( auto* pia = static_cast<analyzer::pia::PIA_TCP*>(Conn()->GetPrimaryPIA()) )
			pia->FirstPacket(is_orig, ip);
		first_packet_seen |= ORIG;
		}

	if ( ! is_orig && ! (first_packet_seen & RESP) )
		{
		if ( auto* pia = static_cast<analyzer::pia::PIA_TCP*>(Conn()->GetPrimaryPIA()) )
			pia->FirstPacket(is_orig, ip);
		first_packet_seen |= RESP;
		}
	}

bool TCPSessionAdapter::IsReuse(double t, const u_char* pkt)
	{
	const struct tcphdr* tp = (const struct tcphdr*)pkt;

	if ( unsigned(tp->th_off) < sizeof(struct tcphdr) / 4 )
		// Bogus header, don't interpret further.
		return false;

	analyzer::tcp::TCP_Endpoint* conn_orig = orig;

	// Reuse only occurs on initial SYN's, except for half connections
	// it can occur on SYN-acks.
	if ( ! (tp->th_flags & TH_SYN) )
		return false;

	if ( (tp->th_flags & TH_ACK) )
		{
		if ( orig->state != analyzer::tcp::TCP_ENDPOINT_INACTIVE )
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
		     conn_orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_ACK_SENT &&
		     resp->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE && base_seq == resp->StartSeq() )
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

		if ( conn_orig->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT )
			Weird("SYN_seq_jump");
		else
			Weird("active_connection_reuse");
		}

	else if ( (orig->IsActive() || resp->IsActive()) &&
	          orig->state != analyzer::tcp::TCP_ENDPOINT_RESET &&
	          resp->state != analyzer::tcp::TCP_ENDPOINT_RESET )
		Weird("active_connection_reuse");

	else if ( t - Conn()->LastTime() < zeek::detail::tcp_connection_linger &&
	          orig->state != analyzer::tcp::TCP_ENDPOINT_RESET &&
	          resp->state != analyzer::tcp::TCP_ENDPOINT_RESET )
		Weird("premature_connection_reuse");

	return true;
	}

void TCPSessionAdapter::AddExtraAnalyzers(Connection* conn)
	{
	static zeek::Tag analyzer_connsize = analyzer_mgr->GetComponentTag("CONNSIZE");
	static zeek::Tag analyzer_tcpstats = analyzer_mgr->GetComponentTag("TCPSTATS");

	// We have to decide whether to reassamble the stream.
	// We turn it on right away if we already have an app-layer
	// analyzer, reassemble_first_packets is true, or the user
	// asks us to do so.  In all other cases, reassembly may
	// be turned on later by the TCP PIA.

	bool reass = (! GetChildren().empty()) || zeek::detail::dpd_reassemble_first_packets ||
	             zeek::detail::tcp_content_deliver_all_orig ||
	             zeek::detail::tcp_content_deliver_all_resp;

	if ( tcp_contents && ! reass )
		{
		static auto tcp_content_delivery_ports_orig = id::find_val<TableVal>(
			"tcp_content_delivery_ports_orig");
		static auto tcp_content_delivery_ports_resp = id::find_val<TableVal>(
			"tcp_content_delivery_ports_resp");
		const auto& dport = val_mgr->Port(ntohs(Conn()->RespPort()), TRANSPORT_TCP);

		if ( ! reass )
			reass = (bool)tcp_content_delivery_ports_orig->FindOrDefault(dport);

		if ( ! reass )
			reass = (bool)tcp_content_delivery_ports_resp->FindOrDefault(dport);
		}

	if ( reass )
		EnableReassembly();

	if ( analyzer_mgr->IsEnabled(analyzer_tcpstats) )
		// Add TCPStats analyzer. This needs to see packets so
		// we cannot add it as a normal child.
		AddChildPacketAnalyzer(new analyzer::tcp::TCPStats_Analyzer(conn));

	if ( analyzer_mgr->IsEnabled(analyzer_connsize) )
		// Add ConnSize analyzer. Needs to see packets, not stream.
		AddChildPacketAnalyzer(new analyzer::conn_size::ConnSize_Analyzer(conn));
	}

void TCPSessionAdapter::SynWeirds(analyzer::tcp::TCP_Flags flags,
                                  analyzer::tcp::TCP_Endpoint* endpoint, int data_len) const
	{
	if ( flags.RST() )
		endpoint->Conn()->Weird("TCP_christmas", "", GetAnalyzerName());

	if ( flags.URG() )
		endpoint->Conn()->Weird("baroque_SYN", "", GetAnalyzerName());

	if ( data_len > 0 )
		// Not technically wrong according to RFC 793, but the other side
		// would be forced to buffer data until the handshake succeeds, and
		// that could be bad in some cases, e.g. SYN floods.
		// T/TCP definitely complicates this.
		endpoint->Conn()->Weird("SYN_with_data", "", GetAnalyzerName());
	}

int TCPSessionAdapter::ParseTCPOptions(const struct tcphdr* tcp, bool is_orig)
	{
	// Parse TCP options.
	const u_char* options = (const u_char*)tcp + sizeof(struct tcphdr);
	const u_char* opt_end = (const u_char*)tcp + tcp->th_off * 4;
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
			break; // trashed length field

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
			EnqueueConnEvent(tcp_option, ConnVal(), val_mgr->Bool(is_orig), val_mgr->Count(kind),
			                 val_mgr->Count(length));
			}

	if ( tcp_options )
		{
		auto option_list = make_intrusive<VectorVal>(BifType::Vector::TCP::OptionList);

		auto add_option_data = [](const RecordValPtr& rv, const u_char* odata, int olen)
		{
			if ( olen <= 2 )
				return;

			auto data_len = olen - 2;
			auto data = reinterpret_cast<const char*>(odata + 2);
			rv->Assign(2, make_intrusive<StringVal>(data_len, data));
		};

		for ( const auto& o : opts )
			{
			auto kind = o[0];
			auto length = kind < 2 ? 1 : o[1];
			auto option_record = make_intrusive<RecordVal>(BifType::Record::TCP::Option);
			option_list->Assign(option_list->Size(), option_record);
			option_record->Assign(0, kind);
			option_record->Assign(1, length);

			switch ( kind )
				{
				case 2:
					// MSS
					if ( length == 4 )
						{
						auto mss = ntohs(*reinterpret_cast<const uint16_t*>(o + 2));
						option_record->Assign(3, mss);
						}
					else
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_mss_invalid_len", util::fmt("%d", length));
						}
					break;

				case 3:
					// window scale
					if ( length == 3 )
						{
						auto scale = o[2];
						option_record->Assign(4, scale);
						}
					else
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_window_scale_invalid_len", util::fmt("%d", length));
						}
					break;

				case 4:
					// sack permitted (implicit boolean)
					if ( length != 2 )
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_sack_invalid_len", util::fmt("%d", length));
						}
					break;

				case 5:
					// SACK blocks (1-4 pairs of 32-bit begin+end pointers)
					if ( length == 10 || length == 18 || length == 26 || length == 34 )
						{
						auto p = reinterpret_cast<const uint32_t*>(o + 2);
						auto num_pointers = (length - 2) / 4;
						auto vt = id::index_vec;
						auto sack = make_intrusive<VectorVal>(std::move(vt));

						for ( auto i = 0; i < num_pointers; ++i )
							sack->Assign(sack->Size(), val_mgr->Count(ntohl(p[i])));

						option_record->Assign(5, sack);
						}
					else
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_sack_blocks_invalid_len", util::fmt("%d", length));
						}
					break;

				case 8:
					// timestamps
					if ( length == 10 )
						{
						auto send = ntohl(*reinterpret_cast<const uint32_t*>(o + 2));
						auto echo = ntohl(*reinterpret_cast<const uint32_t*>(o + 6));
						option_record->Assign(6, send);
						option_record->Assign(7, echo);
						}
					else
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_timestamps_invalid_len", util::fmt("%d", length));
						}
					break;

				case 27:
					// TCP Quick Start Response
					if ( length == 8 )
						{
						auto rate = o[2];
						auto ttl_diff = o[3];
						auto qs_nonce = ntohl(*reinterpret_cast<const uint32_t*>(o + 4));
						option_record->Assign(8, rate);
						option_record->Assign(9, ttl_diff);
						option_record->Assign(10, qs_nonce);
						}
					else
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_qsresponse_invalid_len", util::fmt("%d", length));
						}
					break;

				case 28:
					// TCP User Timeout option UTO
					if ( length != 4 )
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_uto_invalid_len", util::fmt("%d", length));
						}
					break;

				case 29:
					// TCP Auth Option AO
					if ( length < 4 )
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_ao_invalid_len", util::fmt("%d", length));
						}
					break;

				case 34:
					// TCP Fast open TFO
					if ( (length != 2) && (length < 6 || length > 18) )
						{
						add_option_data(option_record, o, length);
						Weird("tcp_option_tfo_invalid_len", util::fmt("%d", length));
						}
					break;

				default:
					add_option_data(option_record, o, length);
					break;
				}
			}

		EnqueueConnEvent(tcp_options, ConnVal(), val_mgr->Bool(is_orig), std::move(option_list));
		}

	if ( options < opt_end )
		return -1;

	return 0;
	}

void TCPSessionAdapter::CheckRecording(bool need_contents, analyzer::tcp::TCP_Flags flags)
	{
	bool record_current_content = need_contents || Conn()->RecordContents();
	bool record_current_packet = Conn()->RecordPackets() || flags.SYN() || flags.FIN() ||
	                             flags.RST();

	Conn()->SetRecordCurrentContent(record_current_content);
	Conn()->SetRecordCurrentPacket(record_current_packet);
	}
