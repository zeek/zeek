// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"

#include <errno.h>

#include "zeek/RunState.h"
#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"
#include "zeek/Reporter.h"
#include "zeek/session/SessionManager.h"
#include "zeek/Event.h"
#include "zeek/File.h"
#include "zeek/Val.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"

namespace zeek::analyzer::tcp {

TCP_Endpoint::TCP_Endpoint(TCP_Analyzer* arg_analyzer, bool arg_is_orig)
	{
	contents_processor = nullptr;
	prev_state = state = TCP_ENDPOINT_INACTIVE;
	peer = nullptr;
	start_time = last_time = 0.0;
	start_seq = last_seq = ack_seq = 0;
	seq_wraps = ack_wraps = 0;
	window = 0;
	window_scale = 0;
	window_seq = window_ack_seq = 0;
	contents_start_seq = 0;
	FIN_seq = 0;
	SYN_cnt = FIN_cnt = RST_cnt = 0;
	did_close = false;
	tcp_analyzer = arg_analyzer;
	is_orig = arg_is_orig;

	gap_cnt = chk_cnt = rxmt_cnt = win0_cnt = 0;
	gap_thresh = chk_thresh = rxmt_thresh = win0_thresh = 1;

	hist_last_SYN = hist_last_FIN = hist_last_RST = 0;

	src_addr = is_orig ? Conn()->RespAddr() : Conn()->OrigAddr();
	dst_addr = is_orig ? Conn()->OrigAddr() : Conn()->RespAddr();
	}

TCP_Endpoint::~TCP_Endpoint()
	{
	delete contents_processor;
	}

Connection* TCP_Endpoint::Conn() const
	{
	return tcp_analyzer->Conn();
	}

void TCP_Endpoint::Done()
	{
	if ( contents_processor )
		contents_processor->Done();
	}

void TCP_Endpoint::SetPeer(TCP_Endpoint* p)
	{
	peer = p;
	if ( IsOrig() )
		// Only one Endpoint adds the initial state to the counter.
		session_mgr->tcp_stats.StateEntered(state, peer->state);
	}

bool TCP_Endpoint::HadGap() const
	{
	return contents_processor && contents_processor->HadGap();
	}

void TCP_Endpoint::AddReassembler(TCP_Reassembler* arg_contents_processor)
	{
	if ( contents_processor != arg_contents_processor )
		delete contents_processor;
	contents_processor = arg_contents_processor;

	if ( contents_file )
		contents_processor->SetContentsFile(contents_file);
	}

bool TCP_Endpoint::DataPending() const
	{
	if ( contents_processor )
		return contents_processor->DataPending();
	else
		return false;
	}

bool TCP_Endpoint::HasUndeliveredData() const
	{
	if ( contents_processor )
		return contents_processor->HasUndeliveredData();
	else
		return false;
	}

void TCP_Endpoint::CheckEOF()
	{
	if ( contents_processor )
		contents_processor->CheckEOF();
	}

void TCP_Endpoint::SizeBufferedData(uint64_t& waiting_on_hole,
                                    uint64_t& waiting_on_ack)
	{
	if ( contents_processor )
		contents_processor->SizeBufferedData(waiting_on_hole, waiting_on_ack);
	else
		waiting_on_hole = waiting_on_ack = 0;
	}

bool TCP_Endpoint::ValidChecksum(const struct tcphdr* tp, int len, bool ipv4) const
	{
	int tcp_len = tp->th_off * 4 + len;

	auto sum = detail::ip_in_cksum(ipv4, src_addr, dst_addr, IPPROTO_TCP,
	                               reinterpret_cast<const uint8_t*>(tp), tcp_len);

	return sum == 0xffff;
	}

static inline bool is_handshake(EndpointState state)
	{
	return state == TCP_ENDPOINT_INACTIVE ||
		state == TCP_ENDPOINT_SYN_SENT ||
		state == TCP_ENDPOINT_SYN_ACK_SENT;
	}

void TCP_Endpoint::SetState(EndpointState new_state)
	{
	if ( new_state != state )
		{
		// Activate inactivity timer if this transition finishes the
		// handshake.
		if ( ! is_handshake(new_state) )
			if ( is_handshake(state) && is_handshake(peer->state) )
				Conn()->SetInactivityTimeout(zeek::detail::tcp_inactivity_timeout);

		prev_state = state;
		state = new_state;
		if ( IsOrig() )
			session_mgr->tcp_stats.ChangeState(prev_state, state,
			                                   peer->state, peer->state);
		else
			session_mgr->tcp_stats.ChangeState(peer->state, peer->state,
			                                   prev_state, state);
		}
	}

uint64_t TCP_Endpoint::Size() const
	{
	if ( prev_state == TCP_ENDPOINT_SYN_SENT && state == TCP_ENDPOINT_RESET &&
	     peer->state == TCP_ENDPOINT_INACTIVE && ! NoDataAcked() )
		// This looks like a half-open connection was discovered and aborted.
		// Sequence numbers could be misleading if used in context of data size
		// and there was never a chance for this endpoint to send data anyway.
		return 0;

	uint64_t size;
	uint64_t last_seq_64 = ToFullSeqSpace(LastSeq(), SeqWraps());
	uint64_t ack_seq_64 = ToFullSeqSpace(AckSeq(), AckWraps());

	// Going straight to relative sequence numbers and comparing those might
	// make more sense, but there's some cases (e.g. due to RSTs) where
	// last_seq might not be initialized to a trustworthy value such that
	// rel_seq > rel_ack, but last_seq_64 < start_seq, which is obviously wrong.
	if ( last_seq_64 > ack_seq_64 )
		size = last_seq_64 - StartSeqI64();
	else
		size = ack_seq_64 - StartSeqI64();

	// Don't include SYN octet in sequence space.  For partial connections
	// (no SYN seen), we're still careful to adjust start_seq as though
	// there was an initial SYN octet, because if we don't then the
	// packet reassembly code gets confused.
	if ( size != 0 )
		--size;

	if ( FIN_cnt > 0 && size != 0 )
		--size;	// don't include FIN octet.

	return size;
	}

bool TCP_Endpoint::DataSent(double t, uint64_t seq, int len, int caplen,
                            const u_char* data,
                            const IP_Hdr* ip, const struct tcphdr* tp)
	{
	bool status = false;

	if ( contents_processor )
		{
		if ( caplen >= len )
			status = contents_processor->DataSent(t, seq, len, data, TCP_Flags(tp));
		else
			TCP()->Weird("truncated_tcp_payload");
		}

	if ( caplen <= 0 )
		return status;

	if ( contents_file && ! contents_processor &&
	     seq + len > contents_start_seq )
		{
		int64_t under_seq = contents_start_seq - seq;
		if ( under_seq > 0 )
			{
			seq += under_seq;
			data += under_seq;
			len -= under_seq;
			}

		// DEBUG_MSG("%d: seek %d, data=%02x len=%d\n", IsOrig(), seq - contents_start_seq, *data, len);
		FILE* f = contents_file->Seek(seq - contents_start_seq);

		if ( fwrite(data, 1, len, f) < unsigned(len) )
			{
			char buf[256];
			util::zeek_strerror_r(errno, buf, sizeof(buf));
			reporter->Error("TCP contents write failed: %s", buf);

			if ( contents_file_write_failure )
				tcp_analyzer->EnqueueConnEvent(contents_file_write_failure,
					Conn()->GetVal(),
					val_mgr->Bool(IsOrig()),
					make_intrusive<StringVal>(buf)
				);
			}
		}

	return status;
	}

void TCP_Endpoint::AckReceived(uint64_t seq)
	{
	if ( contents_processor )
		contents_processor->AckReceived(seq);
	}

void TCP_Endpoint::SetContentsFile(FilePtr f)
	{
	contents_file = std::move(f);
	contents_start_seq = ToRelativeSeqSpace(last_seq, seq_wraps);

	if ( contents_start_seq == 0 )
		contents_start_seq = 1;	// skip SYN

	if ( contents_processor )
		contents_processor->SetContentsFile(contents_file);
	}

bool TCP_Endpoint::CheckHistory(uint32_t mask, char code)
	{
	if ( ! IsOrig() )
		{
		mask <<= 16;
		code = tolower(code);
		}

	return Conn()->CheckHistory(mask, code);
	}

void TCP_Endpoint::AddHistory(char code)
	{
	if ( ! IsOrig() )
		code = tolower(code);

	Conn()->AddHistory(code);
	}

void TCP_Endpoint::ChecksumError()
	{
	uint32_t t = chk_thresh;
	if ( Conn()->ScaledHistoryEntry(IsOrig() ? 'C' : 'c',
	                                chk_cnt, chk_thresh) )
		Conn()->HistoryThresholdEvent(tcp_multiple_checksum_errors,
		                              IsOrig(), t);
	}

void TCP_Endpoint::DidRxmit()
	{
	uint32_t t = rxmt_thresh;
	if ( Conn()->ScaledHistoryEntry(IsOrig() ? 'T' : 't',
	                                rxmt_cnt, rxmt_thresh) )
		Conn()->HistoryThresholdEvent(tcp_multiple_retransmissions,
		                              IsOrig(), t);
	}

void TCP_Endpoint::ZeroWindow()
	{
	uint32_t t = win0_thresh;
	if ( Conn()->ScaledHistoryEntry(IsOrig() ? 'W' : 'w',
	                                win0_cnt, win0_thresh) )
		Conn()->HistoryThresholdEvent(tcp_multiple_zero_windows,
		                              IsOrig(), t);
	}

void TCP_Endpoint::Gap(uint64_t seq, uint64_t len)
	{
	uint32_t t = gap_thresh;
	if ( Conn()->ScaledHistoryEntry(IsOrig() ? 'G' : 'g',
					gap_cnt, gap_thresh) )
		Conn()->HistoryThresholdEvent(tcp_multiple_gap, IsOrig(), t);
	}

} // namespace zeek::analyzer::tcp
