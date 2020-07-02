#pragma once

#include "Reassem.h"
#include "TCP_Endpoint.h"
#include "TCP_Flags.h"
#include "File.h"

class Connection;

ZEEK_FORWARD_DECLARE_NAMESPACED(Analyzer, zeek, analyzer);

namespace analyzer::tcp {

class TCP_Analyzer;

class TCP_Reassembler final : public Reassembler {
public:
	enum Type {
		Direct,		// deliver to destination analyzer itself
		Forward,	// forward to destination analyzer's children
	};

	TCP_Reassembler(zeek::analyzer::Analyzer* arg_dst_analyzer,
	                TCP_Analyzer* arg_tcp_analyzer,
	                Type arg_type, TCP_Endpoint* arg_endp);

	void Done();

	void SetDstAnalyzer(zeek::analyzer::Analyzer* analyzer)	{ dst_analyzer = analyzer; }
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
	//
	// WARNING: this is an O(n) operation and potentially very slow.
	void SizeBufferedData(uint64_t& waiting_on_hole, uint64_t& waiting_on_ack) const;

	// How much data is pending delivery since it's not yet reassembled.
	// Includes the data due to holes (so this value is a bit different
	// from waiting_on_hole above; and is computed in a different fashion).
	uint64_t NumUndeliveredBytes() const;

	void SetContentsFile(BroFilePtr f);
	const BroFilePtr& GetContentsFile() const	{ return record_contents_file; }

	void MatchUndelivered(uint64_t up_to_seq, bool use_last_upper);

	// Skip up to seq, as if there's a content gap.
	// Can be used to skip HTTP data for performance considerations.
	void SkipToSeq(uint64_t seq);

	bool DataSent(double t, uint64_t seq, int len, const u_char* data,
		     analyzer::tcp::TCP_Flags flags, bool replaying=true);
	void AckReceived(uint64_t seq);

	// Checks if we have delivered all contents that we can possibly
	// deliver for this endpoint.  Calls TCP_Analyzer::EndpointEOF()
	// when so.
	void CheckEOF();

	bool HasUndeliveredData() const	{ return HasBlocks(); }
	bool HadGap() const	{ return had_gap; }
	bool DataPending() const;
	uint64_t DataSeq() const		{ return LastReassemSeq(); }

	void DeliverBlock(uint64_t seq, int len, const u_char* data);
	virtual void Deliver(uint64_t seq, int len, const u_char* data);

	TCP_Endpoint* Endpoint()		{ return endp; }
	const TCP_Endpoint* Endpoint() const	{ return endp; }

	bool IsOrig() const	{ return endp->IsOrig(); }

	bool IsSkippedContents(uint64_t seq, int length) const
		{ return seq + length <= seq_to_skip; }

private:
	TCP_Reassembler()	{ }

	void Undelivered(uint64_t up_to_seq) override;
	void Gap(uint64_t seq, uint64_t len);

	void RecordToSeq(uint64_t start_seq, uint64_t stop_seq, const BroFilePtr& f);
	void RecordBlock(const DataBlock& b, const BroFilePtr& f);
	void RecordGap(uint64_t start_seq, uint64_t upper_seq, const BroFilePtr& f);

	void BlockInserted(DataBlockMap::const_iterator it) override;
	void Overlap(const u_char* b1, const u_char* b2, uint64_t n) override;

	TCP_Endpoint* endp;

	bool deliver_tcp_contents;
	bool had_gap;
	bool did_EOF;
	bool skip_deliveries;

	uint64_t seq_to_skip;

	bool in_delivery;
	analyzer::tcp::TCP_Flags flags;

	BroFilePtr record_contents_file;	// file on which to reassemble contents

	zeek::analyzer::Analyzer* dst_analyzer;
	TCP_Analyzer* tcp_analyzer;

	Type type;
};

} // namespace analyzer::tcp
