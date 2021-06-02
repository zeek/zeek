#include "zeek/analyzer/protocol/tcp/ContentLine.h"

#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/Reporter.h"

#include "zeek/analyzer/protocol/tcp/events.bif.h"

namespace zeek::analyzer::tcp {

ContentLine_Analyzer::ContentLine_Analyzer(Connection* conn, bool orig, int max_line_length)
: TCP_SupportAnalyzer("CONTENTLINE", conn, orig), max_line_length(max_line_length)
	{
	InitState();
	}

ContentLine_Analyzer::ContentLine_Analyzer(const char* name, Connection* conn, bool orig, int max_line_length)
: TCP_SupportAnalyzer(name, conn, orig), max_line_length(max_line_length)
	{
	InitState();
	}

void ContentLine_Analyzer::InitState()
	{
	flag_NULs = false;
	CR_LF_as_EOL = (CR_as_EOL | LF_as_EOL);
	skip_deliveries = false;
	skip_partial = false;
	buf = nullptr;
	seq_delivered_in_lines = 0;
	skip_pending = 0;
	seq = 0;
	seq_to_skip = 0;
	plain_delivery_length = 0;
	is_plain = false;
	suppress_weirds = false;

	InitBuffer(0);
	}

void ContentLine_Analyzer::InitBuffer(int size)
	{
	if ( buf && buf_len >= size )
		// Don't shrink the buffer, because it's not clear in that
		// case how to deal with characters in it that no longer fit.
		return;

	if ( size < 128 )
		size = 128;

	u_char* b = new u_char[size];

	if ( buf )
		{
		if ( offset > 0 )
			memcpy(b, buf, offset);
		delete [] buf;
		}
	else
		{
		offset = 0;
		last_char = 0;
		}

	buf = b;
	buf_len = size;
	}

ContentLine_Analyzer::~ContentLine_Analyzer()
	{
	delete [] buf;
	}

bool ContentLine_Analyzer::HasPartialLine() const
	{
	return buf && offset > 0;
	}

void ContentLine_Analyzer::DeliverStream(int len, const u_char* data,
						bool is_orig)
	{
	TCP_SupportAnalyzer::DeliverStream(len, data, is_orig);

	if ( len <= 0 || SkipDeliveries() )
		return;

	if ( skip_partial )
		{
		auto* tcp = static_cast<TCP_ApplicationAnalyzer*>(Parent())->TCP();

		if ( tcp && tcp->IsPartial() )
			return;
		}

	DoDeliver(len, data);

	seq += len;
	}

void ContentLine_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	ForwardUndelivered(seq, len, orig);
	}

void ContentLine_Analyzer::EndpointEOF(bool is_orig)
	{
	if ( offset > 0 )
		DeliverStream(1, (const u_char*) "\n", is_orig);
	}

void ContentLine_Analyzer::SetPlainDelivery(int64_t length)
	{
	if ( length < 0 )
		{
		reporter->AnalyzerError(
			this, "negative length for plain delivery");
		return;
		}

	plain_delivery_length = length;
	}

void ContentLine_Analyzer::DoDeliver(int len, const u_char* data)
	{
	seq_delivered_in_lines = seq;

	while ( len > 0 && ! SkipDeliveries() )
		{
		if ( (CR_LF_as_EOL & CR_as_EOL) &&
		     last_char == '\r' && *data == '\n' )
			{
			// CR is already considered as EOL.
			// Compress CRLF to just one line termination.
			//
			// Note, we test this prior to checking for
			// "plain delivery" because (1) we might have
			// made the decision to switch to plain delivery
			// based on a line terminated with '\r' for
			// which a '\n' then arrived, and (2) we are
			// careful when executing plain delivery to
			// clear last_char once we do so.
			last_char = *data;
			--len; ++data; ++seq;
			++seq_delivered_in_lines;
			}

		if ( plain_delivery_length > 0 )
			{
			int deliver_plain = std::min(plain_delivery_length, (int64_t)len);

			last_char = 0; // clear last_char
			plain_delivery_length -= deliver_plain;
			is_plain = true;

			ForwardStream(deliver_plain, data, IsOrig());

			is_plain = false;

			data += deliver_plain;
			len -= deliver_plain;
			if ( len == 0 )
				return;
			}

		if ( skip_pending > 0 )
			SkipBytes(skip_pending);

		// Note that the skipping must take place *after*
		// the CR/LF check above, so that the '\n' of the
		// previous line is skipped first.
		if ( seq < seq_to_skip )
			{
			// Skip rest of the data and return
			int64_t skip_len = seq_to_skip - seq;
			if ( skip_len > len )
				skip_len = len;

			ForwardUndelivered(seq, skip_len, IsOrig());

			len -= skip_len; data += skip_len; seq += skip_len;
			seq_delivered_in_lines += skip_len;
			}

		if ( len <= 0 )
			break;

		int n = DoDeliverOnce(len, data);
		len -= n;
		data += n;
		seq += n;
		}
	}

int ContentLine_Analyzer::DoDeliverOnce(int len, const u_char* data)
	{
	const u_char* data_start = data;

	if ( len <= 0 )
		return 0;

	for ( ; len > 0; --len, ++data )
		{
		if ( offset >= buf_len )
			InitBuffer(buf_len * 2);

		int c = data[0];

#define EMIT_LINE \
	{ \
	buf[offset] = '\0'; \
	int seq_len = data + 1 - data_start; \
	seq_delivered_in_lines = seq + seq_len; \
	last_char = c; \
	ForwardStream(offset, buf, IsOrig()); \
	offset = 0; \
	return seq_len; \
	}

		if ( offset >= max_line_length )
			{
			Weird("contentline_size_exceeded");
			EMIT_LINE
			}

		switch ( c ) {
		case '\r':
			// Look ahead for '\n'.
			if ( len > 1 && data[1] == '\n' )
				{
				--len; ++data;
				last_char = c;
				c = data[0];
				EMIT_LINE
				}

			else if ( CR_LF_as_EOL & CR_as_EOL )
				EMIT_LINE

			else
				buf[offset++] = c;
			break;

		case '\n':
			if ( last_char == '\r' )
				{
				// Weird corner-case:
				// this can happen if we see a \r at the end of a packet where crlf is
				// set to CR_as_EOL | LF_as_EOL, with the packet causing crlf to be set to
				// 0 and the next packet beginning with a \n. In this case we just swallow
				// the character and re-set last_char.
				if ( offset == 0 )
					{
					last_char = c;
					break;
					}
				--offset; // remove '\r'
				EMIT_LINE
				}

			else if ( CR_LF_as_EOL & LF_as_EOL )
				EMIT_LINE

			else
				{
				if ( ! suppress_weirds && Conn()->FlagEvent(SINGULAR_LF) )
					Weird("line_terminated_with_single_LF");
				buf[offset++] = c;
				}
			break;

		case '\0':
			if ( flag_NULs )
				CheckNUL();
			else
				buf[offset++] = c;
			break;

		default:
			buf[offset++] = c;
			break;
		}

		if ( last_char == '\r' )
			if ( ! suppress_weirds && Conn()->FlagEvent(SINGULAR_CR) )
				Weird("line_terminated_with_single_CR");

		last_char = c;
		}

	return data - data_start;
	}

void ContentLine_Analyzer::CheckNUL()
	{
	// If this is the first byte seen on this connection,
	// and if the connection's state is PARTIAL, then we've
	// intercepted a keep-alive, and shouldn't complain
	// about it.  Note that for PARTIAL connections, the
	// starting sequence number is adjusted as though there
	// had been an initial SYN, so we check for whether
	// the connection has at most two bytes so far.

	auto* tcp = static_cast<TCP_ApplicationAnalyzer*>(Parent())->TCP();

	if ( tcp )
		{
		TCP_Endpoint* endp = IsOrig() ? tcp->Orig() : tcp->Resp();
		if ( endp->state == TCP_ENDPOINT_PARTIAL &&
		     endp->LastSeq() - endp->StartSeq() <= 2 )
			; // Ignore it.
		else
			{
			if ( ! suppress_weirds && Conn()->FlagEvent(NUL_IN_LINE) )
				Weird("NUL_in_line");
			flag_NULs = false;
			}
		}
	}

void ContentLine_Analyzer::SkipBytesAfterThisLine(int64_t length)
	{
	// This is a little complicated because Bro has to handle
	// both CR and CRLF as a line break. When a line is delivered,
	// it's possible that only a CR is seen, and we may not know
	// if an LF is following until we see the next packet.  If an
	// LF follows, we should start skipping bytes *after* the LF.
	// So we keep the skip as 'pending' until we see the next
	// character in DoDeliver().

	if ( last_char == '\r' )
		skip_pending = length;
	else
		SkipBytes(length);
	}

void ContentLine_Analyzer::SkipBytes(int64_t length)
	{
	skip_pending = 0;
	seq_to_skip = SeqDelivered() + length;
	}

} // namespace zeek::analyzer::tcp
