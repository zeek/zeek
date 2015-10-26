// See the file "COPYING" in the main distribution directory for copyright.

#include "Net.h"
#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "TCP_Reassembler.h"
#include "Sessions.h"
#include "Event.h"
#include "File.h"
#include "Val.h"

#include "events.bif.h"

using namespace analyzer::tcp;

TCP_Endpoint::TCP_Endpoint(TCP_Analyzer* arg_analyzer, int arg_is_orig)
	{
	contents_processor = 0;
	prev_state = state = TCP_ENDPOINT_INACTIVE;
	peer = 0;
	start_time = last_time = 0.0;
	start_seq = last_seq = ack_seq = 0;
	seq_wraps = ack_wraps = 0;
	window = 0;
	window_scale = 0;
	window_seq = window_ack_seq = 0;
	contents_start_seq = 0;
	FIN_seq = 0;
	SYN_cnt = FIN_cnt = RST_cnt = 0;
	did_close = 0;
	contents_file = 0;
	tcp_analyzer = arg_analyzer;
	is_orig = arg_is_orig;

	hist_last_SYN = hist_last_FIN = hist_last_RST = 0;

	src_addr = is_orig ? Conn()->RespAddr() : Conn()->OrigAddr();
	dst_addr = is_orig ? Conn()->OrigAddr() : Conn()->RespAddr();

	checksum_base = ones_complement_checksum(src_addr, 0);
	checksum_base = ones_complement_checksum(dst_addr, checksum_base);
	// Note, for IPv6, strictly speaking this field is 32 bits
	// rather than 16 bits.  But because the upper bits are all zero,
	// we get the same checksum either way.  The same applies to
	// later when we add in the data length in ValidChecksum().
	checksum_base += htons(IPPROTO_TCP);
	}

TCP_Endpoint::~TCP_Endpoint()
	{
	delete contents_processor;
	Unref(contents_file);
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
		sessions->tcp_stats.StateEntered(state, peer->state);
	}

int TCP_Endpoint::HadGap() const
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

int TCP_Endpoint::DataPending() const
	{
	if ( contents_processor )
		return contents_processor->DataPending();
	else
		return 0;
	}

int TCP_Endpoint::HasUndeliveredData() const
	{
	if ( contents_processor )
		return contents_processor->HasUndeliveredData();
	else
		return 0;
	}

void TCP_Endpoint::CheckEOF()
	{
	if ( contents_processor )
		contents_processor->CheckEOF();
	}

void TCP_Endpoint::SizeBufferedData(uint64& waiting_on_hole,
                                    uint64& waiting_on_ack)
	{
	if ( contents_processor )
		contents_processor->SizeBufferedData(waiting_on_hole, waiting_on_ack);
	else
		waiting_on_hole = waiting_on_ack = 0;
	}

int TCP_Endpoint::ValidChecksum(const struct tcphdr* tp, int len) const
	{
	uint32 sum = checksum_base;
	int tcp_len = tp->th_off * 4 + len;

	if ( len % 2 == 1 )
		// Add in pad byte.
		sum += htons(((const u_char*) tp)[tcp_len - 1] << 8);

	sum += htons((unsigned short) tcp_len);	// fill out pseudo header
	sum = ones_complement_checksum((void*) tp, tcp_len, sum);

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
				Conn()->SetInactivityTimeout(tcp_inactivity_timeout);

		prev_state = state;
		state = new_state;
		if ( IsOrig() )
			sessions->tcp_stats.ChangeState(prev_state, state,
						peer->state, peer->state);
		else
			sessions->tcp_stats.ChangeState(peer->state, peer->state,
						prev_state, state);
		}
	}

uint64 TCP_Endpoint::Size() const
	{
	if ( prev_state == TCP_ENDPOINT_SYN_SENT && state == TCP_ENDPOINT_RESET &&
	     peer->state == TCP_ENDPOINT_INACTIVE && ! NoDataAcked() )
		// This looks like a half-open connection was discovered and aborted.
		// Sequence numbers could be misleading if used in context of data size
		// and there was never a chance for this endpoint to send data anyway.
		return 0;

	uint64 size;
	uint64 last_seq_64 = ToFullSeqSpace(LastSeq(), SeqWraps());
	uint64 ack_seq_64 = ToFullSeqSpace(AckSeq(), AckWraps());

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

int TCP_Endpoint::DataSent(double t, uint64 seq, int len, int caplen,
				const u_char* data,
				const IP_Hdr* ip, const struct tcphdr* tp)
	{
	int status = 0;

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
		int64 under_seq = contents_start_seq - seq;
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
			strerror_r(errno, buf, sizeof(buf));
			reporter->Error("TCP contents write failed: %s", buf);

			if ( contents_file_write_failure )
				{
				val_list* vl = new val_list();
				vl->append(Conn()->BuildConnVal());
				vl->append(new Val(IsOrig(), TYPE_BOOL));
				vl->append(new StringVal(buf));
				tcp_analyzer->ConnectionEvent(contents_file_write_failure, vl);
				}
			}
		}

	return status;
	}

void TCP_Endpoint::AckReceived(uint64 seq)
	{
	if ( contents_processor )
		contents_processor->AckReceived(seq);
	}

void TCP_Endpoint::SetContentsFile(BroFile* f)
	{
	Ref(f);
	contents_file = f;
	contents_start_seq = ToRelativeSeqSpace(last_seq, seq_wraps);

	if ( contents_start_seq == 0 )
		contents_start_seq = 1;	// skip SYN

	if ( contents_processor )
		contents_processor->SetContentsFile(contents_file);
	}

int TCP_Endpoint::CheckHistory(uint32 mask, char code)
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

