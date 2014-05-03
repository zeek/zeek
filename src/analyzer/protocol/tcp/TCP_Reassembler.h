#ifndef ANALYZER_PROTOCOL_TCP_TCP_REASSEMBLER_H
#define ANALYZER_PROTOCOL_TCP_TCP_REASSEMBLER_H

#include "Reassem.h"
#include "TCP_Endpoint.h"

// The skip_to_seq feature does not work correctly with connections >2GB due
// to use of 32 bit signed ints (see comments in TCP_Reassembler.cc) Since
// it's not used by any analyzer or policy script we disable it. Could be
// added back in once we start using 64bit integers.
//
// #define ENABLE_SEQ_TO_SKIP

class BroFile;
class Connection;

namespace analyzer { namespace tcp {

class TCP_Analyzer;

const int STOP_ON_GAP = 1;
const int PUNT_ON_PARTIAL = 1;

class TCP_Reassembler : public Reassembler {
public:
	enum Type {
		Direct,		// deliver to destination analyzer itself
		Forward,	// forward to destination analyzer's children
	};

	TCP_Reassembler(Analyzer* arg_dst_analyzer, TCP_Analyzer* arg_tcp_analyzer,
	                Type arg_type, TCP_Endpoint* arg_endp);

	virtual ~TCP_Reassembler();

	void Done();

	void SetDstAnalyzer(Analyzer* analyzer)	{ dst_analyzer = analyzer; }
	void SetType(Type arg_type)	{ type = arg_type; }

	TCP_Analyzer* GetTCPAnalyzer()	{ return tcp_analyzer; }

	// Returns the volume of data buffered in the reassembler.
	// First parameter returns data that is above a hole, and thus is
	// waiting on the hole being filled.  Second parameter returns
	// data that has been processed but is awaiting an ACK to free
	// it up.
	//
	// If we're not processing contents, then naturally each of
	// these is empty.
	void SizeBufferedData(int& waiting_on_hole, int& waiting_on_ack) const;

	// How much data is pending delivery since it's not yet reassembled.
	// Includes the data due to holes (so this value is a bit different
	// from waiting_on_hole above; and is computed in a different fashion).
	int NumUndeliveredBytes() const
		{
		if ( last_block )
			return last_block->upper - last_reassem_seq;
		else
			return 0;
		}

	void SetContentsFile(BroFile* f);
	BroFile* GetContentsFile() const	{ return record_contents_file; }

	void MatchUndelivered(int up_to_seq = -1);

#ifdef ENABLE_SEQ_TO_SKIP
	// Skip up to seq, as if there's a content gap.
	// Can be used to skip HTTP data for performance considerations.
	void SkipToSeq(int seq);
} } // namespace analyzer::* 

#endif

	int DataSent(double t, int seq, int len, const u_char* data,
			bool replaying=true);
	void AckReceived(int seq);

	// Checks if we have delivered all contents that we can possibly
	// deliver for this endpoint.  Calls TCP_Analyzer::EndpointEOF()
	// when so.
	void CheckEOF();

	int HasUndeliveredData() const	{ return HasBlocks(); }
	int HadGap() const	{ return had_gap; }
	int DataPending() const;
	int DataSeq() const		{ return LastReassemSeq(); }

	void DeliverBlock(int seq, int len, const u_char* data);
	virtual void Deliver(int seq, int len, const u_char* data);

	TCP_Endpoint* Endpoint()		{ return endp; }
	const TCP_Endpoint* Endpoint() const	{ return endp; }

	int IsOrig() const	{ return endp->IsOrig(); }
#ifdef ENABLE_SEQ_TO_SKIP
	bool IsSkippedContents(int seq, int length) const
		{ return seq + length <= seq_to_skip; }
} } // namespace analyzer::* 

#endif

private:
	TCP_Reassembler()	{ }

	DECLARE_SERIAL(TCP_Reassembler);

	void Undelivered(int up_to_seq);

	void RecordToSeq(int start_seq, int stop_seq, BroFile* f);
	void RecordBlock(DataBlock* b, BroFile* f);
	void RecordGap(int start_seq, int upper_seq, BroFile* f);

	void BlockInserted(DataBlock* b);
	void Overlap(const u_char* b1, const u_char* b2, int n);

	TCP_Endpoint* endp;

	unsigned int deliver_tcp_contents:1;
	unsigned int had_gap:1;
	unsigned int did_EOF:1;
	unsigned int skip_deliveries:1;

#ifdef ENABLE_SEQ_TO_SKIP
	int seq_to_skip;
#endif
	bool in_delivery;

	BroFile* record_contents_file;	// file on which to reassemble contents

	Analyzer* dst_analyzer;
	TCP_Analyzer* tcp_analyzer;

	Type type;
};

} } // namespace analyzer::* 

#endif
