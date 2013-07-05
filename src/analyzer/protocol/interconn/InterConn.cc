// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "InterConn.h"
#include "Event.h"
#include "Net.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "events.bif.h"

using namespace analyzer::interconn;

InterConnEndpoint::InterConnEndpoint(tcp::TCP_Endpoint* e)
	{
	endp = e;
	max_top_seq = 0;
	num_pkts = num_keystrokes_two_in_a_row = num_normal_interarrivals =
		num_8k0_pkts = num_8k4_pkts = num_bytes = num_7bit_ascii =
			num_lines = num_normal_lines = 0;
	is_partial = keystroke_just_seen = 0;
	last_keystroke_time = 0.0;
	}

#define NORMAL_LINE_LENGTH 80

int InterConnEndpoint::DataSent(double t, int seq, int len, int caplen,
		const u_char* data, const IP_Hdr* /* ip */,
		const struct tcphdr* /* tp */)
	{
	if ( caplen < len )
		len = caplen;

	if ( len <= 0 )
		return 0;

	if ( endp->state == tcp::TCP_ENDPOINT_PARTIAL )
		is_partial = 1;

	int ack = endp->AckSeq() - endp->StartSeq();
	int top_seq = seq + len;

	if ( top_seq <= ack || top_seq <= max_top_seq )
		// There is no new data in this packet
		return 0;

	if ( seq < max_top_seq )
		{ // Only consider new data
		int amount_seen = max_top_seq - seq;
		seq += amount_seen;
		data += amount_seen;
		len -= amount_seen;
		}

	if ( max_top_seq && seq > max_top_seq )
		// We've got a pkt above a hole
		num_pkts += EstimateGapPacketNum(seq - max_top_seq);

	++num_pkts;
	max_top_seq = top_seq;

	// Count the bytes.
	num_bytes += len;

	int last_char = 0;
	int offset = 0;	// where we consider the latest line to have begun

	for ( int i = 0; i < len; ++i )
		{
		unsigned int c = data[i];

		if ( c == '\n' && last_char == '\r' )
			{
			// Compress CRLF to just one line termination.
			last_char = c;
			continue;
			}

		if ( c == '\n' || c == '\r' )
			{
			++num_lines;
			if ( i - offset <= NORMAL_LINE_LENGTH )
				++num_normal_lines;
			offset = i;
			}

		else if ( c != 0 && c < 128 )
			++num_7bit_ascii;

		last_char = c;
		}

	if ( IsPotentialKeystrokePacket(len) )
		{
		if ( keystroke_just_seen )
			{
			++num_keystrokes_two_in_a_row;

			if ( IsNormalKeystrokeInterarrival(t - last_keystroke_time) )
				++num_normal_interarrivals;
			}
		else
			keystroke_just_seen = 1;

		// Look for packets matching the SSH signature of
		// being either 0 or 4 modulo 8.
		switch ( len & 7 ) {
		case 0:
			if ( len >= 16 )
				++num_8k0_pkts;
			break;

		case 4:
			++num_8k4_pkts;
			break;
		}

		last_keystroke_time = t;
		}
	else
		keystroke_just_seen = 0;

	return 1;
	}

RecordVal* InterConnEndpoint::BuildStats()
	{
	RecordVal* stats = new RecordVal(interconn_endp_stats);

	stats->Assign(0, new Val(num_pkts, TYPE_COUNT));
	stats->Assign(1, new Val(num_keystrokes_two_in_a_row, TYPE_COUNT));
	stats->Assign(2, new Val(num_normal_interarrivals, TYPE_COUNT));
	stats->Assign(3, new Val(num_8k0_pkts, TYPE_COUNT));
	stats->Assign(4, new Val(num_8k4_pkts, TYPE_COUNT));
	stats->Assign(5, new Val(is_partial, TYPE_BOOL));
	stats->Assign(6, new Val(num_bytes, TYPE_COUNT));
	stats->Assign(7, new Val(num_7bit_ascii, TYPE_COUNT));
	stats->Assign(8, new Val(num_lines, TYPE_COUNT));
	stats->Assign(9, new Val(num_normal_lines, TYPE_COUNT));

	return stats;
	}

int InterConnEndpoint::EstimateGapPacketNum(int gap) const
	{
	return (gap + interconn_default_pkt_size - 1) / interconn_default_pkt_size;
	}

int InterConnEndpoint::IsPotentialKeystrokePacket(int len) const
	{
	return len <= interconn_max_keystroke_pkt_size;
	}

int InterConnEndpoint::IsNormalKeystrokeInterarrival(double t) const
	{
	return interconn_min_interarrival <= t && t <= interconn_max_interarrival;
	}

InterConn_Analyzer::InterConn_Analyzer(Connection* c)
: tcp::TCP_ApplicationAnalyzer("INTERCONN", c)
	{
	orig_endp = resp_endp = 0;
	orig_stream_pos = resp_stream_pos = 1;

	timeout = backdoor_stat_period;
	backoff = backdoor_stat_backoff;

	c->GetTimerMgr()->Add(new InterConnTimer(network_time + timeout, this));
	}

InterConn_Analyzer::~InterConn_Analyzer()
	{
	Unref(orig_endp);
	Unref(resp_endp);
	}

void InterConn_Analyzer::Init()
	{
	tcp::TCP_ApplicationAnalyzer::Init();

	assert(TCP());
	orig_endp = new InterConnEndpoint(TCP()->Orig());
	resp_endp = new InterConnEndpoint(TCP()->Resp());
	}

void InterConn_Analyzer::DeliverPacket(int len, const u_char* data,
			bool is_orig, int seq, const IP_Hdr* ip, int caplen)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, is_orig,
						seq, ip, caplen);

	if ( is_orig )
		orig_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	else
		resp_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	}

void InterConn_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

	if ( is_orig )
		{
		orig_endp->DataSent(network_time, orig_stream_pos, len, len, data, 0, 0);
		orig_stream_pos += len;
		}

	else
		{
		resp_endp->DataSent(network_time, resp_stream_pos, len, len, data, 0, 0);
		resp_stream_pos += len;
		}
	}

void InterConn_Analyzer::Done()
	{
	if ( ! IsFinished() )
		{
		if ( ! Conn()->Skipping() )
			StatEvent();

		RemoveEvent();
		}

	tcp::TCP_ApplicationAnalyzer::Done();
	}

void InterConn_Analyzer::StatTimer(double t, int is_expire)
	{
	if ( IsFinished() || Conn()->Skipping() )
		return;

	StatEvent();

	if ( ! is_expire )
		{
		timeout *= backoff;
		timer_mgr->Add(new InterConnTimer(t + timeout, this));
		}
	}

void InterConn_Analyzer::StatEvent()
	{
	val_list* vl = new val_list;
	vl->append(Conn()->BuildConnVal());
	vl->append(orig_endp->BuildStats());
	vl->append(resp_endp->BuildStats());

	Conn()->ConnectionEvent(interconn_stats, this, vl);
	}

void InterConn_Analyzer::RemoveEvent()
	{
	val_list* vl = new val_list;
	vl->append(Conn()->BuildConnVal());

	Conn()->ConnectionEvent(interconn_remove_conn, this, vl);
	}

InterConnTimer::InterConnTimer(double t, InterConn_Analyzer* a)
: Timer(t, TIMER_INTERCONN)
	{
	analyzer = a;
	// Make sure connection does not expire.
	Ref(a->Conn());
	}

InterConnTimer::~InterConnTimer()
	{
	Unref(analyzer->Conn());
	}

void InterConnTimer::Dispatch(double t, int is_expire)
	{
	analyzer->StatTimer(t, is_expire);
	}
