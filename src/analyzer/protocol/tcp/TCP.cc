// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include <vector>

#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"
#include "zeek/analyzer/protocol/pia/PIA.h"

#include "zeek/IP.h"
#include "zeek/RunState.h"
#include "zeek/NetVar.h"
#include "zeek/File.h"
#include "zeek/Event.h"
#include "zeek/Reporter.h"
#include "zeek/session/Manager.h"
#include "zeek/DebugLogger.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"
#include "zeek/analyzer/protocol/tcp/types.bif.h"

namespace zeek::analyzer::tcp {

packet_analysis::TCP::TCPSessionAdapter* TCP_ApplicationAnalyzer::TCP()
	{
	return tcp ?
		tcp :
		static_cast<packet_analysis::TCP::TCPSessionAdapter*>(Conn()->FindAnalyzer("TCP"));
	}

void TCP_ApplicationAnalyzer::Init()
	{
	Analyzer::Init();

	if ( Parent()->IsAnalyzer("TCP") )
		SetTCP(static_cast<packet_analysis::TCP::TCPSessionAdapter*>(Parent()));
	}

void TCP_ApplicationAnalyzer::ProtocolViolation(const char* reason,
						const char* data, int len)
	{
	auto* tcp = TCP();

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
	        util::fmt_bytes((const char*) data, std::min(40, len)), len > 40 ? "..." : "");
	}

void TCP_ApplicationAnalyzer::SetEnv(bool /* is_orig */, char* name, char* val)
	{
	delete [] name;
	delete [] val;
	}

void TCP_ApplicationAnalyzer::EndpointEOF(bool is_orig)
	{
	analyzer::SupportAnalyzer* sa = is_orig ? orig_supporters : resp_supporters;
	for ( ; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->EndpointEOF(is_orig);
	}

void TCP_ApplicationAnalyzer::ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, bool gen_event)
	{
	analyzer::SupportAnalyzer* sa =
		endpoint->IsOrig() ? orig_supporters : resp_supporters;

	for ( ; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)
			->ConnectionClosed(endpoint, peer, gen_event);
	}

void TCP_ApplicationAnalyzer::ConnectionFinished(bool half_finished)
	{
	for ( analyzer::SupportAnalyzer* sa = orig_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)
			->ConnectionFinished(half_finished);

	for ( analyzer::SupportAnalyzer* sa = resp_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)
			->ConnectionFinished(half_finished);
	}

void TCP_ApplicationAnalyzer::ConnectionReset()
	{
	for ( analyzer::SupportAnalyzer* sa = orig_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->ConnectionReset();

	for ( analyzer::SupportAnalyzer* sa = resp_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->ConnectionReset();
	}

void TCP_ApplicationAnalyzer::PacketWithRST()
	{
	for ( analyzer::SupportAnalyzer* sa = orig_supporters; sa; sa = sa->Sibling() )
		static_cast<TCP_SupportAnalyzer*>(sa)->PacketWithRST();

	for ( analyzer::SupportAnalyzer* sa = resp_supporters; sa; sa = sa->Sibling() )
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
		if ( ! BifConst::ignore_keep_alive_rexmit || len > 1 || data_in_flight > 0 )
			{
			++num_rxmit;
			num_rxmit_bytes += len;
			}

		DEBUG_MSG("%.6f rexmit %" PRIu64" + %d <= %" PRIu64" data_in_flight = %d\n",
		          run_state::network_time, seq, len, max_top_seq, data_in_flight);

		if ( tcp_rexmit )
			endp->TCP()->EnqueueConnEvent(tcp_rexmit,
				endp->TCP()->ConnVal(),
				val_mgr->Bool(endp->IsOrig()),
				val_mgr->Count(seq),
				val_mgr->Count(len),
				val_mgr->Count(data_in_flight),
				val_mgr->Count(endp->peer->window)
			);
		}
	else
		max_top_seq = top_seq;

	return false;
	}

RecordVal* TCPStats_Endpoint::BuildStats()
	{
	static auto endpoint_stats = id::find_type<RecordType>("endpoint_stats");
	auto* stats = new RecordVal(endpoint_stats);

	stats->Assign(0, num_pkts);
	stats->Assign(1, num_rxmit);
	stats->Assign(2, num_rxmit_bytes);
	stats->Assign(3, num_in_order);
	stats->Assign(4, num_OO);
	stats->Assign(5, num_repl);
	stats->Assign(6, endian_type);

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
			IntrusivePtr{AdoptRef{}, orig_stats->BuildStats()},
			IntrusivePtr{AdoptRef{}, resp_stats->BuildStats()}
		);
	}

void TCPStats_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	if ( is_orig )
		orig_stats->DataSent(run_state::network_time, seq, len, caplen, data, ip, nullptr);
	else
		resp_stats->DataSent(run_state::network_time, seq, len, caplen, data, ip, nullptr);
	}

} // namespace zeek::analyzer::tcp
