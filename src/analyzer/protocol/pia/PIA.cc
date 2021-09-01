#include "zeek/analyzer/protocol/pia/PIA.h"

#include "zeek/RuleMatcher.h"
#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/IP.h"
#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::pia {

PIA::PIA(analyzer::Analyzer* arg_as_analyzer)
	: state(INIT), as_analyzer(arg_as_analyzer), conn(), current_packet()
	{
	}

PIA::~PIA()
	{
	ClearBuffer(&pkt_buffer);
	}

void PIA::ClearBuffer(Buffer* buffer)
	{
	DataBlock* next = nullptr;
	for ( DataBlock* b = buffer->head; b; b = next )
		{
		next = b->next;
		delete b->ip;
		delete [] b->data;
		delete b;
		}

	buffer->head = buffer->tail = nullptr;
	buffer->size = 0;
	}

void PIA::AddToBuffer(Buffer* buffer, uint64_t seq, int len, const u_char* data,
                      bool is_orig, const IP_Hdr* ip)
	{
	u_char* tmp = nullptr;

	if ( data )
		{
		tmp = new u_char[len];
		memcpy(tmp, data, len);
		}

	DataBlock* b = new DataBlock;
	b->ip = ip ? ip->Copy() : nullptr;
	b->data = tmp;
	b->is_orig = is_orig;
	b->len = len;
	b->seq = seq;
	b->next = nullptr;

	if ( buffer->tail )
		{
		buffer->tail->next = b;
		buffer->tail = b;
		}
	else
		buffer->head = buffer->tail = b;

	if ( data )
		buffer->size += len;
	}

void PIA::AddToBuffer(Buffer* buffer, int len, const u_char* data, bool is_orig,
                      const IP_Hdr* ip)
	{
	AddToBuffer(buffer, -1, len, data, is_orig, ip);
	}

void PIA::ReplayPacketBuffer(analyzer::Analyzer* analyzer)
	{
	DBG_LOG(DBG_ANALYZER, "PIA replaying %d total packet bytes", pkt_buffer.size);

	for ( DataBlock* b = pkt_buffer.head; b; b = b->next )
		analyzer->DeliverPacket(b->len, b->data, b->is_orig, -1, b->ip, 0);
	}

void PIA::PIA_Done()
	{
	FinishEndpointMatcher();
	}

void PIA::PIA_DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq,
                            const IP_Hdr* ip, int caplen, bool clear_state)
	{
	if ( pkt_buffer.state == SKIPPING )
		return;

	current_packet.data = data;
	current_packet.len = len;
	current_packet.seq = seq;
	current_packet.is_orig = is_orig;

	State new_state = pkt_buffer.state;

	if ( pkt_buffer.state == INIT )
		new_state = BUFFERING;

	if ( (pkt_buffer.state == BUFFERING || new_state == BUFFERING) &&
	     len > 0 )
		{
		AddToBuffer(&pkt_buffer, seq, len, data, is_orig, ip);
		if ( pkt_buffer.size > zeek::detail::dpd_buffer_size )
			new_state = zeek::detail::dpd_match_only_beginning ?
						SKIPPING : MATCHING_ONLY;
		}

	// FIXME: I'm not sure why it does not work with eol=true...
	DoMatch(data, len, is_orig, true, false, false, ip);

	if ( clear_state )
		zeek::detail::RuleMatcherState::ClearMatchState(is_orig);

	pkt_buffer.state = new_state;

	current_packet.data = nullptr;
	}

void PIA::Match(zeek::detail::Rule::PatternType type, const u_char* data, int len,
                bool is_orig, bool bol, bool eol, bool clear_state)
	{
	if ( ! MatcherInitialized(is_orig) )
		InitEndpointMatcher(AsAnalyzer(), nullptr, 0, is_orig, this);

	zeek::detail::RuleMatcherState::Match(type, data, len, is_orig, bol, eol, clear_state);
	}

void PIA::DoMatch(const u_char* data, int len, bool is_orig, bool bol, bool eol,
                  bool clear_state, const IP_Hdr* ip)
	{
	if ( ! zeek::detail::rule_matcher )
		return;

	if ( ! zeek::detail::rule_matcher->HasNonFileMagicRule() )
		return;

	if ( ! MatcherInitialized(is_orig) )
		InitEndpointMatcher(AsAnalyzer(), ip, len, is_orig, this);

	zeek::detail::RuleMatcherState::Match(zeek::detail::Rule::PAYLOAD, data, len, is_orig,
	                                      bol, eol, clear_state);
	}

void PIA_UDP::ActivateAnalyzer(analyzer::Tag tag, const zeek::detail::Rule* rule)
	{
	if ( pkt_buffer.state == MATCHING_ONLY )
		{
		DBG_LOG(DBG_ANALYZER, "analyzer found but buffer already exceeded");
		// FIXME: This is where to check whether an analyzer
		// supports partial connections once we get such.

		if ( protocol_late_match )
			{
			// Queue late match event
			if ( ! tag )
				tag = GetAnalyzerTag();

			const auto& tval = tag.AsVal();
			event_mgr.Enqueue(protocol_late_match, ConnVal(), tval);
			}

		pkt_buffer.state = zeek::detail::dpd_late_match_stop ? SKIPPING : MATCHING_ONLY;
		return;
		}

	if ( Parent()->HasChildAnalyzer(tag) )
		return;

	analyzer::Analyzer* a = Parent()->AddChildAnalyzer(tag);

	if ( ! a )
		return;

	a->SetSignature(rule);
	ReplayPacketBuffer(a);
	}

void PIA_UDP::DeactivateAnalyzer(analyzer::Tag tag)
	{
	reporter->InternalError("PIA_UDP::Deact not implemented yet");
	}

//// TCP PIA

PIA_TCP::~PIA_TCP()
	{
	ClearBuffer(&stream_buffer);
	}

void PIA_TCP::Init()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Init();

	if ( Parent()->IsAnalyzer("TCP") )
		{
		auto* tcp = static_cast<packet_analysis::TCP::TCPSessionAdapter*>(Parent());
		SetTCP(tcp);
		tcp->SetPIA(this);
		}
	}

void PIA_TCP::FirstPacket(bool is_orig, const IP_Hdr* ip)
	{
	static char dummy_packet[sizeof(struct ip) + sizeof(struct tcphdr)];
	static struct ip* ip4 = nullptr;
	static struct tcphdr* tcp4 = nullptr;
	static IP_Hdr* ip4_hdr = nullptr;

	DBG_LOG(DBG_ANALYZER, "PIA_TCP[%d] FirstPacket(%s)", GetID(), (is_orig ? "T" : "F"));

	if ( ! ip )
		{
		// Create a dummy packet.  Not very elegant, but everything
		// else would be *really* ugly ...
		if ( ! ip4_hdr )
			{
			ip4 = (struct ip*) dummy_packet;
			tcp4 = (struct tcphdr*)
				(dummy_packet + sizeof(struct ip));
			ip4->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
			ip4->ip_hl = sizeof(struct ip) >> 2;
			ip4->ip_p = IPPROTO_TCP;

			// Cast to const so that it doesn't delete it.
			ip4_hdr = new IP_Hdr(ip4, false);
			}

		// Locals used to avoid potentil alignment problems
		// with some archs/compilers when grabbing the address
		// of the struct member directly in the following.
		in_addr tmp_src;
		in_addr tmp_dst;

		if ( is_orig )
			{
			Conn()->OrigAddr().CopyIPv4(&tmp_src);
			Conn()->RespAddr().CopyIPv4(&tmp_dst);
			tcp4->th_sport = htons(Conn()->OrigPort());
			tcp4->th_dport = htons(Conn()->RespPort());
			}
		else
			{
			Conn()->RespAddr().CopyIPv4(&tmp_src);
			Conn()->OrigAddr().CopyIPv4(&tmp_dst);
			tcp4->th_sport = htons(Conn()->RespPort());
			tcp4->th_dport = htons(Conn()->OrigPort());
			}

		ip4->ip_src = tmp_src;
		ip4->ip_dst = tmp_dst;
		ip = ip4_hdr;
		}

	if ( ! MatcherInitialized(is_orig) )
		DoMatch((const u_char*)"", 0, is_orig, true, false, false, ip);
	}

void PIA_TCP::DeliverStream(int len, const u_char* data, bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

	if ( stream_buffer.state == SKIPPING )
		return;

	stream_mode = true;

	State new_state = stream_buffer.state;

	if ( stream_buffer.state == INIT )
		{
		// FIXME: clear payload-matching state here...
		new_state = BUFFERING;
		}

	if ( stream_buffer.state == BUFFERING || new_state == BUFFERING )
		{
		AddToBuffer(&stream_buffer, len, data, is_orig);
		if ( stream_buffer.size > zeek::detail::dpd_buffer_size )
			new_state = zeek::detail::dpd_match_only_beginning ?
						SKIPPING : MATCHING_ONLY;
		}

	DoMatch(data, len, is_orig, false, false, false, nullptr);

	stream_buffer.state = new_state;
	}

void PIA_TCP::Undelivered(uint64_t seq, int len, bool is_orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, is_orig);

	if ( stream_buffer.state == BUFFERING )
		// We use data=nil to mark an undelivered.
		AddToBuffer(&stream_buffer, seq, len, nullptr, is_orig);

	// No check for buffer overrun here. I think that's ok.
	}

void PIA_TCP::ActivateAnalyzer(analyzer::Tag tag, const zeek::detail::Rule* rule)
	{
	if ( stream_buffer.state == MATCHING_ONLY )
		{
		DBG_LOG(DBG_ANALYZER, "analyzer found but buffer already exceeded");
		// FIXME: This is where to check whether an analyzer supports
		// partial connections once we get such.

		if ( protocol_late_match )
			{
			// Queue late match event
			if ( ! tag )
				tag = GetAnalyzerTag();

			const auto& tval = tag.AsVal();
			event_mgr.Enqueue(protocol_late_match, ConnVal(), tval);
			}

		stream_buffer.state = zeek::detail::dpd_late_match_stop ? SKIPPING : MATCHING_ONLY;
		return;
		}

	analyzer::Analyzer* a = Parent()->AddChildAnalyzer(tag);

	if ( ! a )
		return;

	a->SetSignature(rule);

	// We have two cases here:
	//
	// (a) We have already got stream input.
	//     => Great, somebody's already reassembling and we can just
	//		replay our stream buffer to the new analyzer.
	if ( stream_mode )
		{
		ReplayStreamBuffer(a);
		return;
		}

	// (b) We have only got packet input so far (or none at all).
	//     => We have to switch from packet-mode to stream-mode.
	//
	// Here's what we do:
	//
	//   (1) We create new tcp::TCP_Reassemblers and feed them the buffered
	//       packets.
	//
	//   (2) The reassembler will give us their results via the
	//       stream-interface and we buffer it as usual.
	//
	//   (3) We replay the now-filled stream-buffer to the analyzer.
	//
	//   (4) We hand the two reassemblers to the TCP Analyzer (our parent),
	//       turning reassembly now on for all subsequent data.

	DBG_LOG(DBG_ANALYZER, "PIA_TCP switching from packet-mode to stream-mode");
	stream_mode = true;

	// FIXME: The reassembler will query the endpoint for state. Not sure
	// if this is works in all cases...

	if ( ! Parent()->IsAnalyzer("TCP") )
		{
		// Our parent is not the TCP analyzer, which can only mean
		// we have been inserted somewhere further down in the
		// analyzer tree.  In this case, we will never have seen
		// any input at this point (because we don't get packets).
		assert(!pkt_buffer.head);
		assert(!stream_buffer.head);
		return;
		}

	auto* tcp = static_cast<packet_analysis::TCP::TCPSessionAdapter*>(Parent());

	auto* reass_orig = new tcp::TCP_Reassembler(this, tcp, tcp::TCP_Reassembler::Direct,
	                                            tcp->Orig());

	auto* reass_resp = new tcp::TCP_Reassembler(this, tcp, tcp::TCP_Reassembler::Direct,
	                                            tcp->Resp());

	uint64_t orig_seq = 0;
	uint64_t resp_seq = 0;

	for ( DataBlock* b = pkt_buffer.head; b; b = b->next )
		{
		// We don't have the TCP flags here during replay. We could
		// funnel them through, but it's non-trivial and doesn't seem
		// worth the effort.

		if ( b->is_orig )
			reass_orig->DataSent(run_state::network_time, orig_seq = b->seq,
			                     b->len, b->data, tcp::TCP_Flags(), true);
		else
			reass_resp->DataSent(run_state::network_time, resp_seq = b->seq,
			                     b->len, b->data, tcp::TCP_Flags(), true);
		}

	// We also need to pass the current packet on.
	DataBlock* current = CurrentPacket();
	if ( current->data )
		{
		if ( current->is_orig )
			reass_orig->DataSent(run_state::network_time,
					orig_seq = current->seq,
					current->len, current->data, analyzer::tcp::TCP_Flags(), true);
		else
			reass_resp->DataSent(run_state::network_time,
					resp_seq = current->seq,
					current->len, current->data, analyzer::tcp::TCP_Flags(), true);
		}

	ClearBuffer(&pkt_buffer);

	ReplayStreamBuffer(a);
	reass_orig->AckReceived(orig_seq);
	reass_resp->AckReceived(resp_seq);

	reass_orig->SetType(tcp::TCP_Reassembler::Forward);
	reass_resp->SetType(tcp::TCP_Reassembler::Forward);

	tcp->SetReassembler(reass_orig, reass_resp);
	}

void PIA_TCP::DeactivateAnalyzer(analyzer::Tag tag)
	{
	reporter->InternalError("PIA_TCP::Deact not implemented yet");
	}

void PIA_TCP::ReplayStreamBuffer(analyzer::Analyzer* analyzer)
	{
	DBG_LOG(DBG_ANALYZER, "PIA_TCP replaying %d total stream bytes", stream_buffer.size);

	for ( DataBlock* b = stream_buffer.head; b; b = b->next )
		{
		if ( b->data )
			analyzer->NextStream(b->len, b->data, b->is_orig);
		else
			analyzer->NextUndelivered(b->seq, b->len, b->is_orig);
		}
	}

} // namespace zeek::analyzer::pia
