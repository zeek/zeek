// Support-analyzer to split a reassembled stream into lines.

#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::tcp
	{

#define CR_as_EOL 1
#define LF_as_EOL 2

// Slightly smaller than 16MB so that the buffer is not unnecessarily resized to 32M.
constexpr auto DEFAULT_MAX_LINE_LENGTH = 16 * 1024 * 1024 - 100;

class ContentLine_Analyzer : public TCP_SupportAnalyzer
	{
public:
	ContentLine_Analyzer(Connection* conn, bool orig,
	                     int max_line_length = DEFAULT_MAX_LINE_LENGTH);
	~ContentLine_Analyzer() override;

	void SuppressWeirds(bool enable) { suppress_weirds = enable; }

	// If enabled, flag (first) line with embedded NUL. Default off.
	void SetIsNULSensitive(bool enable) { flag_NULs = enable; }

	// If enabled, skip data above a hole. Default off.
	void SetSkipPartial(bool enable) { skip_partial = enable; }

	// If true, single CR / LF are considered as EOL. Default on for both.
	void SetCRLFAsEOL(int crlf = (CR_as_EOL | LF_as_EOL)) { CR_LF_as_EOL = crlf; }

	int CRLFAsEOL() { return CR_LF_as_EOL; }

	bool HasPartialLine() const;

	bool SkipDeliveries() const { return skip_deliveries; }

	void SetSkipDeliveries(bool should_skip) { skip_deliveries = should_skip; }

	// We actually have two delivery modes: line delivery and plain
	// delivery for data portions which are not line-separated.
	// SetPlainDelivery() keeps the ContentLine_Analyzer in plain delivery
	// mode for next <length> bytes.  Plain-delivery data is also passed
	// via DeliverStream() and can differentiated by calling
	// IsPlainDelivery().
	void SetPlainDelivery(int64_t length);
	void SetDeliverySize(int64_t length);
	int64_t GetPlainDeliveryLength() const { return plain_delivery_length; }
	bool IsPlainDelivery() { return is_plain; }

	// Skip <length> bytes after this line.
	// Can be used to skip HTTP data for performance considerations.
	void SkipBytesAfterThisLine(int64_t length);
	void SkipBytes(int64_t length);

	bool IsSkippedContents(uint64_t seq, int64_t length) { return seq + length <= seq_to_skip; }

protected:
	ContentLine_Analyzer(const char* name, Connection* conn, bool orig,
	                     int max_line_length = DEFAULT_MAX_LINE_LENGTH);

	void DeliverStream(int len, const u_char* data, bool is_orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	class State;
	void InitState();
	void InitBuffer(int size);
	virtual void DoDeliver(int len, const u_char* data);
	int DoDeliverOnce(int len, const u_char* data);
	void CheckNUL();

	// Returns the sequence number delivered so far.
	uint64_t SeqDelivered() const { return seq_delivered_in_lines; }

	u_char* buf; // where we build up the body of the request
	int offset; // where we are in buf
	int buf_len; // how big buf is, total
	unsigned int last_char; // last (non-option) character scanned
	int max_line_length; // how large of a line to accumulate before emitting and raising a weird

	uint64_t seq; // last seq number
	uint64_t seq_to_skip;

	// Seq delivered up to through NewLine() -- it is adjusted
	// *before* NewLine() is called.
	uint64_t seq_delivered_in_lines;

	// Number of bytes to be skipped after this line. See
	// comments in SkipBytesAfterThisLine().
	int64_t skip_pending;

	// Remaining bytes to deliver plain.
	int64_t plain_delivery_length;
	// Remaining bytes to deliver
	int64_t delivery_length;
	bool is_plain;

	// Don't deliver further data.
	bool skip_deliveries;

	bool suppress_weirds;

	// If true, flag (first) line with embedded NUL.
	bool flag_NULs;

	// Whether single CR / LF are considered as EOL.
	uint8_t CR_LF_as_EOL : 2;

	// Whether to skip partial conns.
	bool skip_partial;
	};

	} // namespace zeek::analyzer::tcp
