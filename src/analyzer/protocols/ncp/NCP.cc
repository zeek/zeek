// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>
#include <string>
#include <map>

#include "NCP.h"

#include "events.bif.h"

using namespace std;
using namespace analyzer::ncp;

#include "NCP.h"
#include "Sessions.h"

#define xbyte(b, n) (((const u_char*) (b))[n])
#define extract_uint16(little_endian, bytes) \
	((little_endian) ? \
	 uint16(xbyte(bytes, 0)) | ((uint16(xbyte(bytes, 1))) << 8) : \
	 uint16(xbyte(bytes, 1)) | ((uint16(xbyte(bytes, 0))) << 8))

NCP_Session::NCP_Session(analyzer::Analyzer* a)
: analyzer(a)
	{
	req_frame_type = 0;
	req_func = 0;
	}

void NCP_Session::Deliver(int is_orig, int len, const u_char* data)
	{
	try
		{
		binpac::NCP::ncp_over_tcpip_frame frame(is_orig);
		frame.Parse(data, data + len);

		DeliverFrame(frame.ncp());
		}
	catch ( const binpac::Exception& e )
		{
		analyzer->Weird(e.msg().c_str());
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
			req_func = (req_func << 8) |
					frame->request()->subfunction();
			}
		}

	EventHandlerPtr f = frame->is_orig() ? ncp_request : ncp_reply;
	if ( f )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(frame->frame_type(), TYPE_COUNT));
		vl->append(new Val(frame->body_length(), TYPE_COUNT));

		if ( frame->is_orig() )
			vl->append(new Val(req_func, TYPE_COUNT));
		else
			{
			vl->append(new Val(req_frame_type, TYPE_COUNT));
			vl->append(new Val(req_func, TYPE_COUNT));
			vl->append(new Val(frame->reply()->completion_code(),
						TYPE_COUNT));
			}

		analyzer->ConnectionEvent(f, vl);
		}
	}

FrameBuffer::FrameBuffer(int header_length)
	{
	hdr_len = header_length;
	msg_buf = 0;
	buf_len = 0;
	Reset();
	}

FrameBuffer::~FrameBuffer()
	{
	delete [] msg_buf;
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

// Returns true if we have a complete frame
bool FrameBuffer::Deliver(int &len, const u_char* &data)
	{
	ASSERT(buf_len >= hdr_len);

	if ( len == 0 )
		return false;

	if ( buf_n < hdr_len )
		{
		while ( buf_n < hdr_len && len > 0 )
			{
			ASSERT(buf_n < buf_len);
			msg_buf[buf_n] = *data;
			++buf_n; ++data; --len;
			}

		if ( buf_n < hdr_len )
			return false;

		compute_msg_length();

		if ( msg_len > buf_len )
			{
			buf_len = msg_len * 2;
			u_char* new_buf = new u_char[buf_len];
			memcpy(new_buf, msg_buf, buf_n);
			delete [] msg_buf;
			msg_buf = new_buf;
			}
		}

	while ( buf_n < msg_len && len > 0 )
		{
		msg_buf[buf_n] = *data;
		++buf_n; ++data; --len;
		}

	return buf_n >= msg_len;
	}

void NCP_FrameBuffer::compute_msg_length()
	{
	const u_char* data = Data();
	msg_len = 0;
	for ( int i = 0; i < 4; ++i )
		msg_len = (msg_len << 8) | data[4+i];
	}

Contents_NCP_Analyzer::Contents_NCP_Analyzer(Connection* conn, bool orig, NCP_Session* arg_session)
: tcp::TCP_SupportAnalyzer("CONTENTS_NCP", conn, orig)
	{
	session = arg_session;
	resync = true;

	tcp::TCP_Analyzer* tcp = static_cast<tcp::TCP_ApplicationAnalyzer*>(Parent())->TCP();
	if ( tcp )
		resync = (orig ? tcp->OrigState() : tcp->RespState()) !=
						tcp::TCP_ENDPOINT_ESTABLISHED;
	}

Contents_NCP_Analyzer::~Contents_NCP_Analyzer()
	{
	}

void Contents_NCP_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	tcp::TCP_Analyzer* tcp = static_cast<tcp::TCP_ApplicationAnalyzer*>(Parent())->TCP();

	if ( tcp && tcp->HadGap(orig) )
		return;

	DEBUG_MSG("NCP deliver: len = %d resync = %d buffer.empty = %d\n",
		len, resync, buffer.empty());

	if ( buffer.empty() && resync )
		{
		// Assume NCP frames align with packet boundary.
		if ( (IsOrig() && len < 22) || (! IsOrig() && len < 16) )
			{ // ignore small fragmeents
			DEBUG_MSG("NCP discard small pieces: %d\n", len);
			return;
			}

		int frame_type_index = IsOrig() ? 16 : 8;
		int frame_type = ((int) data[frame_type_index]) << 8 |
					data[frame_type_index + 1];

		if ( frame_type != 0x1111 && frame_type != 0x2222 &&
		     frame_type != 0x3333 && frame_type != 0x5555 &&
		     frame_type != 0x7777 && frame_type != 0x9999 )
			// Skip this packet
			return;

		resync = false;
		}

	while ( buffer.Deliver(len, data) )
		{
		session->Deliver(IsOrig(), buffer.Len(), buffer.Data());
		buffer.Reset();
		}
	}

void Contents_NCP_Analyzer::Undelivered(int seq, int len, bool orig)
	{
	tcp::TCP_SupportAnalyzer::Undelivered(seq, len, orig);

	buffer.Reset();
	resync = true;
	}

NCP_Analyzer::NCP_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("NCP", conn)
	{
	session = new NCP_Session(this);
	o_ncp = new Contents_NCP_Analyzer(conn, true, session);
	r_ncp = new Contents_NCP_Analyzer(conn, false, session);
	}

NCP_Analyzer::~NCP_Analyzer()
	{
	delete session;
	delete o_ncp;
	delete r_ncp;
	}

