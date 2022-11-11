// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/File.h"
#include "zeek/IPAddr.h"

namespace zeek
	{

class Connection;
class IP_Hdr;

namespace packet_analysis::TCP
	{
class TCPSessionAdapter;
	}

namespace analyzer::tcp
	{

class TCP_Reassembler;

enum EndpointState
	{
	TCP_ENDPOINT_INACTIVE, // no SYN (or other packets) seen for this side
	TCP_ENDPOINT_SYN_SENT, // SYN seen, but no ack
	TCP_ENDPOINT_SYN_ACK_SENT, // SYN ack seen, no initial SYN
	TCP_ENDPOINT_PARTIAL, // data seen, but no SYN
	TCP_ENDPOINT_ESTABLISHED, // SYN ack seen (implicit for SYN
	                          // sent by responder)
	TCP_ENDPOINT_CLOSED, // FIN seen
	TCP_ENDPOINT_RESET // RST seen
	};

// One endpoint of a TCP connection.
class TCP_Endpoint
	{
public:
	TCP_Endpoint(packet_analysis::TCP::TCPSessionAdapter* analyzer, bool is_orig);
	~TCP_Endpoint();

	void Done();

	packet_analysis::TCP::TCPSessionAdapter* TCP() { return tcp_analyzer; }

	void SetPeer(TCP_Endpoint* p);

	EndpointState State() const { return state; }
	void SetState(EndpointState new_state);
	uint64_t Size() const;
	bool IsActive() const { return state != TCP_ENDPOINT_INACTIVE && ! did_close; }

	double StartTime() const { return start_time; }
	double LastTime() const { return last_time; }

	/**
	 * @return The starting TCP sequence number for this endpoint.
	 */
	uint32_t StartSeq() const { return static_cast<uint32_t>(start_seq); }

	/**
	 * @return The starting TCP sequence number for this endpoint, in terms
	 *         of a signed sequence space, which may account for initial
	 *         sequence space wraparounds (underflow/overflow).
	 */
	int64_t StartSeqI64() const { return start_seq; }

	/**
	 * @return The sequence number after the last TCP sequence number seen
	 *         from this endpoint.
	 */
	uint32_t LastSeq() const { return last_seq; }

	/**
	 * @return The last TCP acknowledgement number seen from this endpoint.
	 */
	uint32_t AckSeq() const { return ack_seq; }

	/**
	 * @return The number of times the TCP sequence has wrapped around
	 *         for this endpoint (i.e. overflowed a uint32_t).
	 */
	uint32_t SeqWraps() const { return seq_wraps; }

	/**
	 * @return The number of times the TCP acknowledgement sequence has
	 *         wrapped around for this endpoint (i.e. overflowed a uint32_t).
	 */
	uint32_t AckWraps() const { return ack_wraps; }

	/**
	 * @param wraps Number of times a 32-bit sequence space has wrapped.
	 * @return A 64-bit sequence space number it would take to overflow
	 *         a 32-bit sequence space \a wraps number of times.
	 */
	static uint64_t ToFullSeqSpace(uint32_t wraps) { return (uint64_t(wraps) << 32); }

	/**
	 * @param tcp_seq_num A 32-bit TCP sequence space number.
	 * @param wraparounds Number of times a 32-bit sequence space has wrapped.
	 * @return \a tcp_seq_num expanded out into a 64-bit sequence space,
	 *         accounting for the number of times the 32-bit space overflowed.
	 */
	static uint64_t ToFullSeqSpace(uint32_t tcp_seq_num, uint32_t wraparounds)
		{
		return ToFullSeqSpace(wraparounds) + tcp_seq_num;
		}

	/**
	 * @param tcp_seq_num A 32-bit TCP sequence space number.
	 * @param wraparounds Number of times a 32-bit sequence space has wrapped.
	 * @return \a tcp_seq_num expanded out into a 64-bit sequence space,
	 *         accounting for the number of times the 32-bit space overflowed
	 *         and relative to the starting sequence number for this endpoint.
	 */
	uint64_t ToRelativeSeqSpace(uint32_t tcp_seq_num, uint32_t wraparounds) const
		{
		return ToFullSeqSpace(tcp_seq_num, wraparounds) - StartSeqI64();
		}

	void InitStartSeq(int64_t seq) { start_seq = seq; }
	void InitLastSeq(uint32_t seq) { last_seq = seq; }
	void InitAckSeq(uint32_t seq) { ack_seq = seq; }

	void UpdateLastSeq(uint32_t seq)
		{
		if ( seq < last_seq )
			++seq_wraps;

		last_seq = seq;
		}

	void UpdateAckSeq(uint32_t seq)
		{
		if ( seq < ack_seq )
			++ack_wraps;

		ack_seq = seq;
		}

	// True if none of this endpoint's data has been acknowledged.
	// We allow for possibly one octet being ack'd in the case of
	// an initial SYN exchange.
	bool NoDataAcked() const
		{
		uint64_t ack = ToFullSeqSpace(ack_seq, ack_wraps);
		uint64_t start = static_cast<uint64_t>(StartSeqI64());
		return ack == start || ack == start + 1;
		}

	Connection* Conn() const;

	bool HasContents() const { return contents_processor != nullptr; }
	bool HadGap() const;

	inline bool IsOrig() const { return is_orig; }

	bool HasDoneSomething() const { return last_time != 0.0; }

	void AddReassembler(TCP_Reassembler* contents_processor);

	bool DataPending() const;
	bool HasUndeliveredData() const;
	void CheckEOF();

	// Returns the volume of data buffered in the reassembler.
	// First parameter returns data that is above a hole, and thus is
	// waiting on the hole being filled.  Second parameter returns
	// data that has been processed but is awaiting an ACK to free
	// it up.
	//
	// If we're not processing contents, then naturally each of
	// these is empty.
	//
	// WARNING: this is an O(n) operation and potentially very slow.
	void SizeBufferedData(uint64_t& waiting_on_hole, uint64_t& waiting_on_ack);

	bool ValidChecksum(const struct tcphdr* tp, int len, bool ipv4) const;

	// Called to inform endpoint that it has generated a checksum error.
	void ChecksumError();

	// Called to inform endpoint that it has generated a retransmission.
	void DidRxmit();

	// Called to inform endpoint that it has offered a zero window.
	void ZeroWindow();

	// Called to inform endpoint that a gap occurred.
	void Gap(uint64_t seq, uint64_t len);

	// Returns true if the data was used (and hence should be recorded
	// in the save file), false otherwise.
	bool DataSent(double t, uint64_t seq, int len, int caplen, const u_char* data, const IP_Hdr* ip,
	              const struct tcphdr* tp);

	void AckReceived(uint64_t seq);

	void SetContentsFile(FilePtr f);
	const FilePtr& GetContentsFile() const { return contents_file; }

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
#define HIST_RXMIT 0x100
#define HIST_WIN0 0x200
	bool CheckHistory(uint32_t mask, char code);
	void AddHistory(char code);

	//### combine into a set of flags:
	EndpointState state, prev_state;
	TCP_Endpoint* peer;
	TCP_Reassembler* contents_processor;
	packet_analysis::TCP::TCPSessionAdapter* tcp_analyzer;
	FilePtr contents_file;

	double start_time, last_time;
	IPAddr src_addr; // the other endpoint
	IPAddr dst_addr; // this endpoint
	uint32_t window; // current advertised window (*scaled*, not pre-scaling)
	int window_scale; // from the TCP option
	uint32_t window_ack_seq; // at which ack_seq number did we record 'window'
	uint32_t window_seq; // at which sending sequence number did we record 'window'
	uint64_t contents_start_seq; // relative seq # where contents file starts
	uint64_t FIN_seq; // relative seq # to start_seq
	int SYN_cnt, FIN_cnt, RST_cnt;
	bool did_close; // whether we've reported it closing
	bool is_orig;

	// Relative sequence numbers associated with last control packets.
	// Used to determine whether ones seen again are interesting,
	// for tracking history.
	uint64_t hist_last_SYN, hist_last_FIN, hist_last_RST;

protected:
	int64_t start_seq; // Initial TCP sequence number in host order.
	                   // Signed 64-bit to detect initial sequence wrapping.
	                   // Use StartSeq() accessor if need it in terms of
	                   // an absolute TCP sequence number.
	uint32_t last_seq, ack_seq; // in host order
	uint32_t seq_wraps, ack_wraps; // Number of times 32-bit TCP sequence space
	                               // has wrapped around (overflowed).

	// Performance history accounting.
	uint32_t chk_cnt, chk_thresh;
	uint32_t rxmt_cnt, rxmt_thresh;
	uint32_t win0_cnt, win0_thresh;
	uint32_t gap_cnt, gap_thresh;
	};

#define ENDIAN_UNKNOWN 0
#define ENDIAN_LITTLE 1
#define ENDIAN_BIG 2
#define ENDIAN_CONFUSED 3

	} // namespace analyzer::tcp
	} // namespace zeek
