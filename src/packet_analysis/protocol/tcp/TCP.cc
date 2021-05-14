// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/analyzer/protocol/tcp/types.bif.h"

using namespace zeek;
using namespace zeek::packet_analysis::TCP;
using namespace zeek::packet_analysis::IP;

constexpr int32_t TOO_LARGE_SEQ_DELTA = 1048576;

TCPAnalyzer::TCPAnalyzer() : IPBasedAnalyzer("TCP", TRANSPORT_TCP, TCP_PORT_MASK, false)
	{
	// TODO: remove once the other plugins are done
	new_plugin = true;
	}

TCPAnalyzer::~TCPAnalyzer()
	{
	}

void TCPAnalyzer::Initialize()
	{
	ignored_nets = zeek::id::find_val<TableVal>("ignore_checksums_nets");
	}

SessionAdapter* TCPAnalyzer::MakeSessionAdapter(Connection* conn)
	{
	auto* root = new TCPSessionAdapter(conn);
	root->SetParent(this);

	conn->EnableStatusUpdateTimer();
	conn->SetInactivityTimeout(zeek::detail::udp_inactivity_timeout);

	return root;
	}

zeek::analyzer::pia::PIA* TCPAnalyzer::MakePIA(Connection* conn)
	{
	return new analyzer::pia::PIA_TCP(conn);
	}

bool TCPAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
                                 ConnTuple& tuple)
	{
	uint32_t min_hdr_len = sizeof(struct tcphdr);
	if ( ! CheckHeaderTrunc(min_hdr_len, len, packet) )
		return false;

	tuple.src_addr = packet->ip_hdr->SrcAddr();
	tuple.dst_addr = packet->ip_hdr->DstAddr();

	data = packet->ip_hdr->Payload();

	const struct tcphdr* tp = (const struct tcphdr *) data;
	tuple.src_port = tp->th_sport;
	tuple.dst_port = tp->th_dport;
	tuple.is_one_way = false;
	tuple.proto = TRANSPORT_TCP;

	return true;
	}

bool TCPAnalyzer::WantConnection(uint16_t src_port, uint16_t dst_port,
                                 const u_char* data, bool& flip_roles) const
	{
	flip_roles = false;
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint8_t tcp_flags = tp->th_flags;

	if ( ! (tcp_flags & TH_SYN) || (tcp_flags & TH_ACK) )
		{
		// The new connection is starting either without a SYN,
		// or with a SYN ack. This means it's a partial connection.
		if ( ! zeek::detail::partial_connection_ok )
			return false;

		if ( tcp_flags & TH_SYN && ! zeek::detail::tcp_SYN_ack_ok )
			return false;

		// Try to guess true responder by the port numbers.
		// (We might also think that for SYN acks we could
		// safely flip the roles, but that doesn't work
		// for stealth scans.)
		if ( IsLikelyServerPort(src_port) )
			{ // connection is a candidate for flipping
			if ( IsLikelyServerPort(dst_port) )
				// Hmmm, both source and destination
				// are plausible.  Heuristic: flip only
				// if (1) this isn't a SYN ACK (to avoid
				// confusing stealth scans) and
				// (2) dest port > src port (to favor
				// more plausible servers).
				flip_roles = ! (tcp_flags & TH_SYN) && src_port < dst_port;
			else
				// Source is plausible, destination isn't.
				flip_roles = true;
			}
		}

	return true;
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
	switch ( endpoint->state ) {
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

static uint64_t get_relative_seq(const analyzer::tcp::TCP_Endpoint* endpoint,
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

static void update_history(analyzer::tcp::TCP_Flags flags, analyzer::tcp::TCP_Endpoint* endpoint,
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
	auto v = zeek::make_intrusive<zeek::RecordVal>(SYN_packet);

	v->Assign(0, is_orig);
	v->Assign(1, static_cast<bool>(ip->DF()));
	v->Assign(2, ip->TTL());
	v->Assign(3, ip->TotalLen());
	v->Assign(4, ntohs(tcp->th_win));
	v->Assign(5, winscale);
	v->Assign(6, MSS);
	v->Assign(7, static_cast<bool>(SACK));

	return v;
	}

static void init_window(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                        analyzer::tcp::TCP_Flags flags, bro_int_t scale, uint32_t base_seq,
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

void TCPAnalyzer::DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt)
	{
	const u_char* data = pkt->ip_hdr->Payload();
	int len = pkt->ip_hdr->PayloadLen();
	auto* adapter = static_cast<TCPSessionAdapter*>(c->GetSessionAdapter());

	const struct tcphdr* tp = ExtractTCP_Header(data, len, remaining, adapter);
	if ( ! tp )
		return;

	// We need the min() here because Ethernet frame padding can lead to
	// remaining > len.
	if ( packet_contents )
		adapter->PacketContents(data, std::min(len, remaining));

	analyzer::tcp::TCP_Endpoint* endpoint = is_orig ? adapter->orig : adapter->resp;
	analyzer::tcp::TCP_Endpoint* peer = endpoint->peer;
	const std::unique_ptr<IP_Hdr>& ip = pkt->ip_hdr;

	if ( ! ValidateChecksum(ip.get(), tp, endpoint, len, remaining, adapter) )
		return;

	uint32_t tcp_hdr_len = data - (const u_char*) tp;
	analyzer::tcp::TCP_Flags flags(tp);
	adapter->SetPartialStatus(flags, endpoint->IsOrig());

	uint32_t base_seq = ntohl(tp->th_seq);
	uint32_t ack_seq = ntohl(tp->th_ack);

	int seg_len = get_segment_len(len, flags);
	uint32_t seq_one_past_segment = base_seq + seg_len;

	init_endpoint(endpoint, flags, base_seq, seq_one_past_segment,
	              run_state::current_timestamp);

	bool seq_underflow = false;
	uint64_t rel_seq = get_relative_seq(endpoint, base_seq, endpoint->LastSeq(),
	                                    endpoint->SeqWraps(), &seq_underflow);

	if ( seq_underflow && ! flags.RST() )
		// Can't tell if if this is a retransmit/out-of-order or something
		// before the sequence Bro initialized the endpoint at or the TCP is
		// just broken and sending garbage sequences.  In either case, some
		// standard analysis doesn't apply (e.g. reassembly).
		adapter->Weird("TCP_seq_underflow_or_misorder");

	update_history(flags, endpoint, rel_seq, len);
	update_window(endpoint, ntohs(tp->th_win), base_seq, ack_seq, flags);

	if ( ! adapter->orig->did_close || ! adapter->resp->did_close )
		c->SetLastTime(run_state::current_timestamp);

	if ( flags.SYN() )
		{
		SynWeirds(flags, endpoint, len);
		RecordValPtr SYN_vals = build_syn_packet_val(is_orig, ip.get(), tp);
		init_window(endpoint, peer, flags, SYN_vals->GetFieldAs<IntVal>(5),
		            base_seq, ack_seq);

		if ( connection_SYN_packet )
			adapter->EnqueueConnEvent(connection_SYN_packet, adapter->ConnVal(), SYN_vals);
		}

	if ( flags.FIN() )
		{
		++endpoint->FIN_cnt;

		if ( endpoint->FIN_cnt >= detail::tcp_storm_thresh && run_state::current_timestamp <
		     endpoint->last_time + detail::tcp_storm_interarrival_thresh )
			adapter->Weird("FIN_storm");

		endpoint->FIN_seq = rel_seq + seg_len;
		}

	if ( flags.RST() )
		{
		++endpoint->RST_cnt;

		if ( endpoint->RST_cnt >= detail::tcp_storm_thresh && run_state::current_timestamp <
		     endpoint->last_time + detail::tcp_storm_interarrival_thresh )
			adapter->Weird("RST_storm");

		// This now happens often enough that it's
		// not in the least interesting.
		//if ( len > 0 )
		//	adapter->Weird("RST_with_data");

		adapter->PacketWithRST();
		}

	uint64_t rel_ack = 0;

	if ( flags.ACK() )
		{
		if ( is_orig && ! adapter->seen_first_ACK &&
		     (endpoint->state == analyzer::tcp::TCP_ENDPOINT_ESTABLISHED ||
		      endpoint->state == analyzer::tcp::TCP_ENDPOINT_SYN_SENT) )
			{
			adapter->seen_first_ACK = 1;
			adapter->Event(connection_first_ACK);
			}

		if ( peer->state == analyzer::tcp::TCP_ENDPOINT_INACTIVE )
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
				adapter->Weird("TCP_ack_underflow_or_misorder");
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
	adapter->UpdateStateMachine(run_state::current_timestamp, endpoint, peer, base_seq, ack_seq,
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
		adapter->GeneratePacketEvent(rel_seq, rel_ack, data, len, remaining, is_orig, flags);

	if ( (tcp_option || tcp_options) && tcp_hdr_len > sizeof(*tp) )
		ParseTCPOptions(adapter, tp, is_orig);

	// PIA/signature matching state needs to be initialized before
	// processing/reassembling any TCP data, since that processing may
	// itself try to perform signature matching.  Also note that a SYN
	// packet may technically carry data (see RFC793 Section 3.4 and also
	// TCP Fast Open).
	adapter->CheckPIA_FirstPacket(is_orig, ip.get());

	if ( DEBUG_tcp_data_sent )
		{
		DEBUG_MSG("%.6f before DataSent: len=%d remaining=%d skip=%d\n",
		          run_state::network_time, len, remaining, adapter->Skipping());
		}

	uint64_t rel_data_seq = flags.SYN() ? rel_seq + 1 : rel_seq;

	int need_contents = 0;
	if ( len > 0 && (remaining >= len || adapter->HasPacketChildren()) &&
	     ! flags.RST() && ! adapter->Skipping() && ! seq_underflow )
		need_contents = endpoint->DataSent(run_state::current_timestamp, rel_data_seq,
		                                   len, remaining, data, ip.get(), tp);

	endpoint->CheckEOF();

	if ( do_close )
		{
		// We need to postpone doing this until after we process
		// DataSent, so we don't generate a connection_finished event
		// until after data perhaps included with the FIN is processed.
		adapter->ConnectionClosed(endpoint, peer, gen_event);
		}

	CheckRecording(c, need_contents, flags);

	// Send the packet back into the packet analysis framework.
	ForwardPacket(len, data, pkt);

	// Call DeliverPacket on the adapter directly here. Normally we'd call ForwardPacket
	// but this adapter does some other things in its DeliverPacket with the packet children
	// analyzers.
	adapter->DeliverPacket(len, data, is_orig, rel_data_seq, ip.get(), remaining);
	}

const struct tcphdr* TCPAnalyzer::ExtractTCP_Header(const u_char*& data, int& len, int& remaining,
                                                    TCPSessionAdapter* adapter)
	{
	const struct tcphdr* tp = (const struct tcphdr*) data;
	uint32_t tcp_hdr_len = tp->th_off * 4;

	if ( tcp_hdr_len < sizeof(struct tcphdr) )
		{
		adapter->Weird("bad_TCP_header_len");
		return nullptr;
		}

	if ( tcp_hdr_len > uint32_t(len) ||
	     tcp_hdr_len > uint32_t(remaining) )
		{
		// This can happen even with the above test, due to TCP options.
		adapter->Weird("truncated_header");
		return nullptr;
		}

	len -= tcp_hdr_len;	// remove TCP header
	remaining -= tcp_hdr_len;
	data += tcp_hdr_len;

	return tp;
	}

void TCPAnalyzer::SynWeirds(analyzer::tcp::TCP_Flags flags, analyzer::tcp::TCP_Endpoint* endpoint,
                            int data_len) const
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

int TCPAnalyzer::ParseTCPOptions(TCPSessionAdapter* adapter, const struct tcphdr* tcp,
                                 bool is_orig) const
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
			adapter->EnqueueConnEvent(tcp_option,
			                          adapter->ConnVal(),
			                          val_mgr->Bool(is_orig),
			                          val_mgr->Count(kind),
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

			switch ( kind ) {
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
					adapter->Weird("tcp_option_mss_invalid_len", util::fmt("%d", length));
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
					adapter->Weird("tcp_option_window_scale_invalid_len", util::fmt("%d", length));
					}
				break;

			case 4:
				// sack permitted (implicit boolean)
				if ( length != 2 )
					{
					add_option_data(option_record, o, length);
					adapter->Weird("tcp_option_sack_invalid_len", util::fmt("%d", length));
					}
				break;

			case 5:
				// SACK blocks (1-4 pairs of 32-bit begin+end pointers)
				if ( length == 10 || length == 18 ||
				     length == 26 || length == 34 )
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
					adapter->Weird("tcp_option_sack_blocks_invalid_len", util::fmt("%d", length));
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
					adapter->Weird("tcp_option_timestamps_invalid_len", util::fmt("%d", length));
					}
				break;

			default:
				add_option_data(option_record, o, length);
				break;
			}
			}

		adapter->EnqueueConnEvent(tcp_options,
		                          adapter->ConnVal(),
		                          val_mgr->Bool(is_orig),
		                          std::move(option_list));
		}

	if ( options < opt_end )
		return -1;

	return 0;
	}

void TCPAnalyzer::CheckRecording(Connection* c, bool need_contents, analyzer::tcp::TCP_Flags flags)
	{
	bool record_current_content = need_contents || c->RecordContents();
	bool record_current_packet =
		c->RecordPackets() ||
		flags.SYN() || flags.FIN() || flags.RST();

	c->SetRecordCurrentContent(record_current_content);
	c->SetRecordCurrentPacket(record_current_packet);
	}

bool TCPAnalyzer::ValidateChecksum(const IP_Hdr* ip, const struct tcphdr* tp,
                                   analyzer::tcp::TCP_Endpoint* endpoint, int len, int caplen,
                                   TCPSessionAdapter* adapter)
	{
	if ( ! run_state::current_pkt->l3_checksummed &&
	     ! detail::ignore_checksums &&
	     ! ignored_nets->Contains(ip->IPHeaderSrcAddr()) &&
	     caplen >= len && ! endpoint->ValidChecksum(tp, len, ip->IP4_Hdr()) )
		{
		adapter->Weird("bad_TCP_checksum");
		endpoint->ChecksumError();
		return false;
		}
	else
		return true;
	}
