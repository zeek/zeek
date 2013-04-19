// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_TCP_TCP_ENDPOINT_H
#define ANALYZER_PROTOCOL_TCP_TCP_ENDPOINT_H

#include "IPAddr.h"

class Connection;
class IP_Hdr;

namespace analyzer { namespace tcp {

class TCP_Analyzer;
class TCP_Reassembler;

typedef enum {
	TCP_ENDPOINT_INACTIVE,	// no SYN (or other packets) seen for this side
	TCP_ENDPOINT_SYN_SENT,	// SYN seen, but no ack
	TCP_ENDPOINT_SYN_ACK_SENT,	// SYN ack seen, no initial SYN
	TCP_ENDPOINT_PARTIAL,	// data seen, but no SYN
	TCP_ENDPOINT_ESTABLISHED,	// SYN ack seen (implicit for SYN
					// sent by responder)
	TCP_ENDPOINT_CLOSED,	// FIN seen
	TCP_ENDPOINT_RESET	// RST seen
} EndpointState;

// One endpoint of a TCP connection.
class TCP_Endpoint {
public:
	TCP_Endpoint(TCP_Analyzer* analyzer, int is_orig);
	~TCP_Endpoint();

	void Done();

	TCP_Analyzer* TCP()	{ return tcp_analyzer; }

	void SetPeer(TCP_Endpoint* p);

	EndpointState State() const 	{ return state; }
	void SetState(EndpointState new_state);
	bro_int_t Size() const;
	int IsActive() const
		{ return state != TCP_ENDPOINT_INACTIVE && ! did_close; }

	double StartTime() const	{ return start_time; }
	double LastTime() const		{ return last_time; }

	uint32 StartSeq() const		{ return start_seq; }
	uint32 LastSeq() const		{ return last_seq; }
	uint32 AckSeq() const		{ return ack_seq; }

	void InitStartSeq(uint32 seq) 	{ start_seq = seq; }
	void InitLastSeq(uint32 seq) 	{ last_seq = seq; }
	void InitAckSeq(uint32 seq) 	{ ack_seq = seq; }

	void UpdateLastSeq(uint32 seq)
		{
		if ( seq < last_seq )
			++last_seq_high;
		last_seq = seq;
		}

	void UpdateAckSeq(uint32 seq)
		{
		if ( seq < ack_seq )
			++ack_seq_high;
		ack_seq = seq;
		}

	// True if none of this endpoint's data has been acknowledged.
	// We allow for possibly one octet being ack'd in the case of
	// an initial SYN exchange.
	int NoDataAcked() const
		{ return ack_seq == start_seq || ack_seq == start_seq + 1; }

	Connection* Conn() const;

	int HasContents() const		{ return contents_processor != 0; }
	int HadGap() const;

	inline int IsOrig() const		{ return is_orig; }

	int HasDoneSomething() const	{ return last_time != 0.0; }

	void AddReassembler(TCP_Reassembler* contents_processor);

	int DataPending() const;
	int HasUndeliveredData() const;
	void CheckEOF();

	// Returns the volume of data buffered in the reassembler.
	// First parameter returns data that is above a hole, and thus is
	// waiting on the hole being filled.  Second parameter returns
	// data that has been processed but is awaiting an ACK to free
	// it up.
	//
	// If we're not processing contents, then naturally each of
	// these is empty.
	void SizeBufferedData(int& waiting_on_hole, int& waiting_on_ack);

	int ValidChecksum(const struct tcphdr* tp, int len) const;

	// Returns true if the data was used (and hence should be recorded
	// in the save file), false otherwise.
	int DataSent(double t, int seq, int len, int caplen, const u_char* data,
			const IP_Hdr* ip, const struct tcphdr* tp);

	void AckReceived(int seq);

	void SetContentsFile(BroFile* f);
	BroFile* GetContentsFile() const	{ return contents_file; }

	// Codes used for tracking history.  For responders, we shift these
	// over by 16 bits in order to fit both originator and responder
	// into a Connection's hist_seen field.
#define HIST_SYN_PKT 0x1
#define HIST_FIN_PKT 0x2
#define HIST_RST_PKT 0x4
#define HIST_FIN_RST_PKT 0x8
#define HIST_DATA_PKT 0x10
#define HIST_ACK_PKT 0x20
#define HIST_MULTI_FLAG_PKT 0x40
#define HIST_CORRUPT_PKT 0x80
	int CheckHistory(uint32 mask, char code);
	void AddHistory(char code);

	//### combine into a set of flags:
	EndpointState state, prev_state;
	TCP_Endpoint* peer;
	TCP_Reassembler* contents_processor;
	TCP_Analyzer* tcp_analyzer;
	BroFile* contents_file;
	uint32 checksum_base;

	double start_time, last_time;
	IPAddr src_addr; // the other endpoint
	IPAddr dst_addr; // this endpoint
	uint32 window; // current congestion window (*scaled*, not pre-scaling)
	int window_scale;  // from the TCP option
	uint32 window_ack_seq; // at which ack_seq number did we record 'window'
	uint32 window_seq; // at which sending sequence number did we record 'window'
	int contents_start_seq;	// relative seq # where contents file starts
	int FIN_seq;		// relative seq # to start_seq
	int SYN_cnt, FIN_cnt, RST_cnt;
	int did_close;		// whether we've reported it closing
	int is_orig;

	// Sequence numbers associated with last control packets.
	// Used to determine whether ones seen again are interesting,
	// for tracking history.
	uint32 hist_last_SYN, hist_last_FIN, hist_last_RST;

protected:
	uint32 start_seq, last_seq, ack_seq;	// in host order
	uint32 last_seq_high, ack_seq_high;
};

#define ENDIAN_UNKNOWN 0
#define ENDIAN_LITTLE 1
#define ENDIAN_BIG 2
#define ENDIAN_CONFUSED 3

} } // namespace analyzer::* 

#endif
