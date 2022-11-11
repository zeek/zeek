// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/ncp/NCP.h"

#include "zeek/zeek-config.h"

#include <cstdlib>
#include <map>
#include <string>

#include "zeek/analyzer/protocol/ncp/consts.bif.h"
#include "zeek/analyzer/protocol/ncp/events.bif.h"

using namespace std;

#define xbyte(b, n) (((const u_char*)(b))[n])
#define extract_uint16(little_endian, bytes)                                                       \
	((little_endian) ? uint16(xbyte(bytes, 0)) | ((uint16(xbyte(bytes, 1))) << 8)                  \
	                 : uint16(xbyte(bytes, 1)) | ((uint16(xbyte(bytes, 0))) << 8))

namespace zeek::analyzer::ncp
	{
namespace detail
	{

NCP_Session::NCP_Session(analyzer::Analyzer* a) : analyzer(a)
	{
	req_frame_type = 0;
	req_func = 0;
	}

void NCP_Session::Deliver(bool is_orig, int len, const u_char* data)
	{
	try
		{
		binpac::NCP::ncp_over_tcpip_frame frame(is_orig);
		frame.Parse(data, data + len);

		DeliverFrame(frame.ncp());
		}
	catch ( const binpac::Exception& e )
		{
		analyzer->AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
		}
	}

void NCP_Session::DeliverFrame(const binpac::NCP::ncp_frame* frame)
	{
	if ( frame->is_orig() )
		{
		req_frame_type = frame->frame_type();
		req_func = frame->request()->function();
		if ( req_func == 0x57 ) // enhanced FILE_DIR services
			{
			req_func = (req_func << 8) | frame->request()->subfunction();
			}
		}

	EventHandlerPtr f = frame->is_orig() ? ncp_request : ncp_reply;
	if ( f )
		{
		if ( frame->is_orig() )
			analyzer->EnqueueConnEvent(f, analyzer->ConnVal(), val_mgr->Count(frame->frame_type()),
			                           val_mgr->Count(frame->body_length()),
			                           val_mgr->Count(req_func));
		else
			analyzer->EnqueueConnEvent(f, analyzer->ConnVal(), val_mgr->Count(frame->frame_type()),
			                           val_mgr->Count(frame->body_length()),
			                           val_mgr->Count(req_frame_type), val_mgr->Count(req_func),
			                           val_mgr->Count(frame->reply()->completion_code()));
		}
	}

FrameBuffer::FrameBuffer(size_t header_length)
	{
	hdr_len = header_length;
	msg_buf = nullptr;
	buf_len = 0;
	Reset();
	}

FrameBuffer::~FrameBuffer()
	{
	delete[] msg_buf;
	}

void FrameBuffer::Reset()
	{
	// Allocate space for header.
	if ( ! msg_buf )
		{
		buf_len = hdr_len;
		msg_buf = new u_char[buf_len];
		}

	buf_n = 0;
	msg_len = 0;
	}

int FrameBuffer::Deliver(int& len, const u_char*& data)
	{
	ASSERT(buf_len >= hdr_len);

	if ( len == 0 )
		return -1;

	if ( buf_n < hdr_len )
		{
		while ( buf_n < hdr_len && len > 0 )
			{
			ASSERT(buf_n < buf_len);
			msg_buf[buf_n] = *data;
			++buf_n;
			++data;
			--len;
			}

		if ( buf_n < hdr_len )
			return -1;

		compute_msg_length();

		if ( msg_len > buf_len )
			{
			if ( msg_len > BifConst::NCP::max_frame_size )
				return 1;

			buf_len = msg_len;
			u_char* new_buf = new u_char[buf_len];
			memcpy(new_buf, msg_buf, buf_n);
			delete[] msg_buf;
			msg_buf = new_buf;
			}
		}

	while ( buf_n < msg_len && len > 0 )
		{
		msg_buf[buf_n] = *data;
		++buf_n;
		++data;
		--len;
		}

	if ( buf_n < msg_len )
		return -1;

	if ( buf_n == msg_len )
		return 0;

	return 1;
	}

void NCP_FrameBuffer::compute_msg_length()
	{
	const u_char* data = Data();
	msg_len = 0;
	for ( int i = 0; i < 4; ++i )
		msg_len = (msg_len << 8) | data[4 + i];
	}

	} // namespace detail

Contents_NCP_Analyzer::Contents_NCP_Analyzer(Connection* conn, bool orig,
                                             detail::NCP_Session* arg_session)
	: analyzer::tcp::TCP_SupportAnalyzer("CONTENTS_NCP", conn, orig)
	{
	session = arg_session;
	resync = true;
	resync_set = false;
	}

Contents_NCP_Analyzer::~Contents_NCP_Analyzer() { }

void Contents_NCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	auto tcp = static_cast<NCP_Analyzer*>(Parent())->TCP();

	if ( ! resync_set )
		{
		resync_set = true;

		if ( tcp )
			resync = (IsOrig() ? tcp->OrigState() : tcp->RespState()) !=
			         analyzer::tcp::TCP_ENDPOINT_ESTABLISHED;
		else
			resync = false;
		}

	if ( tcp && tcp->HadGap(orig) )
		return;

	if ( buffer.empty() && resync )
		{
		// Assume NCP frames align with packet boundary.
		if ( (IsOrig() && len < 22) || (! IsOrig() && len < 16) )
			{ // ignore small fragments
			return;
			}

		int frame_type_index = IsOrig() ? 16 : 8;
		int frame_type = ((int)data[frame_type_index]) << 8 | data[frame_type_index + 1];

		if ( frame_type != 0x1111 && frame_type != 0x2222 && frame_type != 0x3333 &&
		     frame_type != 0x5555 && frame_type != 0x7777 && frame_type != 0x9999 )
			// Skip this packet
			return;

		resync = false;
		}

	for ( ;; )
		{
		auto result = buffer.Deliver(len, data);

		if ( result < 0 )
			break;

		if ( result == 0 )
			{
			session->Deliver(IsOrig(), buffer.Len(), buffer.Data());
			buffer.Reset();
			}
		else
			{
			// The rest of the data available in this delivery will
			// be discarded and will need to resync to a new frame header.
			Weird("ncp_large_frame");
			buffer.Reset();
			resync = true;
			break;
			}
		}
	}

void Contents_NCP_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	analyzer::tcp::TCP_SupportAnalyzer::Undelivered(seq, len, orig);

	buffer.Reset();
	resync = true;
	}

NCP_Analyzer::NCP_Analyzer(Connection* conn) : analyzer::tcp::TCP_ApplicationAnalyzer("NCP", conn)
	{
	session = new detail::NCP_Session(this);
	o_ncp = new Contents_NCP_Analyzer(conn, true, session);
	AddSupportAnalyzer(o_ncp);
	r_ncp = new Contents_NCP_Analyzer(conn, false, session);
	AddSupportAnalyzer(r_ncp);
	}

NCP_Analyzer::~NCP_Analyzer()
	{
	delete session;
	}

	} // namespace zeek::analyzer::ncp
