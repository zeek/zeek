// $Id: RPC.cc 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>

#include "NetVar.h"
#include "XDR.h"
#include "RPC.h"
#include "Sessions.h"

namespace { // local namespace
	const bool DEBUG_rpc_resync = false;
}

#define MAX_RPC_LEN 65536

// The following correspond to the different RPC status values defined
// in bro.init.
// #define BRO_RPC_TIMEOUT 6
// #define BRO_RPC_AUTH_ERROR 7
// #define BRO_RPC_UNKNOWN_ERROR 8

RPC_CallInfo::RPC_CallInfo(uint32 arg_xid, const u_char*& buf, int& n)
	{
	xid = arg_xid;

	start_time = network_time;
	call_n = n;
	call_buf = new u_char[call_n];
	memcpy((void*) call_buf, (const void*) buf, call_n);

	rpc_version = extract_XDR_uint32(buf, n);
	prog = extract_XDR_uint32(buf, n);
	vers = extract_XDR_uint32(buf, n);
	proc = extract_XDR_uint32(buf, n);
	cred_flavor = skip_XDR_opaque_auth(buf, n);
	verf_flavor = skip_XDR_opaque_auth(buf, n);

	header_len = call_n - n;

	valid_call = false;

	v = 0;
	}

RPC_CallInfo::~RPC_CallInfo()
	{
	delete [] call_buf;
	Unref(v);
	}

int RPC_CallInfo::CompareRexmit(const u_char* buf, int n) const
	{
	if ( n != call_n )
		return 0;

	return memcmp((const void*) call_buf, (const void*) buf, call_n) == 0;
	}


void rpc_callinfo_delete_func(void* v)
	{
	delete (RPC_CallInfo*) v;
	}

RPC_Interpreter::RPC_Interpreter(Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	calls.SetDeleteFunc(rpc_callinfo_delete_func);
	}

RPC_Interpreter::~RPC_Interpreter()
	{
	}

int RPC_Interpreter::DeliverRPC(const u_char* buf, int n, int is_orig)
	{
	uint32 xid = extract_XDR_uint32(buf, n);
	uint32 msg_type = extract_XDR_uint32(buf, n);

	if ( ! buf )
		return 0;

	HashKey h(&xid, 1);
	RPC_CallInfo* call = calls.Lookup(&h);

	if ( msg_type == RPC_CALL )
		{
		if ( ! is_orig )
			Weird("responder_RPC_call");

		if ( call )
			{
			if ( ! call->CompareRexmit(buf, n) )
				Weird("RPC_rexmit_inconsistency");

			if ( call->HeaderLen() > n )
				{
				Weird("RPC_underflow");
				return 0;
				}

			n -= call->HeaderLen();
			buf += call->HeaderLen();
			}

		else
			{
			call = new RPC_CallInfo(xid, buf, n);
			if ( ! buf )
				{
				delete call;
				return 0;
				}

			calls.Insert(&h, call);
			}

		if ( RPC_BuildCall(call, buf, n) )
			call->SetValidCall();
		else
			{
			Weird("bad_RPC");
			return 0;
			}
		}

	else if ( msg_type == RPC_REPLY )
		{
		if ( is_orig )
			Weird("originator_RPC_reply");

		uint32 reply_stat = extract_XDR_uint32(buf, n);
		if ( ! buf )
			return 0;

		uint32 status = BroEnum::RPC_UNKNOWN_ERROR;

		if ( reply_stat == RPC_MSG_ACCEPTED )
			{
			(void) skip_XDR_opaque_auth(buf, n);
			uint32 accept_stat = extract_XDR_uint32(buf, n);

			// The first members of BroEnum::RPC_* correspond
			// to accept_stat.
			if ( accept_stat <= RPC_SYSTEM_ERR )
				status = accept_stat;

			if ( ! buf )
				return 0;

			if ( accept_stat == RPC_PROG_MISMATCH )
				{
				(void) extract_XDR_uint32(buf, n);
				(void) extract_XDR_uint32(buf, n);

				if ( ! buf )
					return 0;
				}
			}

		else if ( reply_stat == RPC_MSG_DENIED )
			{
			uint32 reject_stat = extract_XDR_uint32(buf, n);
			if ( ! buf )
				return 0;

			if ( reject_stat == RPC_MISMATCH )
				{
				// Note that RPC_MISMATCH == 0 == RPC_SUCCESS.
				status = BroEnum::RPC_VERS_MISMATCH;

				(void) extract_XDR_uint32(buf, n);
				(void) extract_XDR_uint32(buf, n);

				if ( ! buf )
					return 0;
				}

			else if ( reject_stat == RPC_AUTH_ERROR )
				{
				status = BroEnum::RPC_AUTH_ERROR;

				(void) extract_XDR_uint32(buf, n);
				if ( ! buf )
					return 0;
				}

			else
				{
				status = BroEnum::RPC_UNKNOWN_ERROR;
				Weird("bad_RPC");
				}
			}

		else
			Weird("bad_RPC");

		if ( call )
			{
			int success = status == RPC_SUCCESS;

			if ( ! call->IsValidCall() )
				{
				if ( success )
					Weird("successful_RPC_reply_to_invalid_request");
				// We can't process this further, even if
				// it was successful, because the call
				// info won't be fully set up.
				}

			else
				{
				EventHandlerPtr event;
				Val* reply;
				if ( ! RPC_BuildReply(call, success, buf,
							n, event, reply) )
					Weird("bad_RPC");
				else
					{
					Event(event, call->TakeRequestVal(),
						status, reply);
					}
				}

			RPC_Event(call, status, n);

			delete calls.RemoveEntry(&h);
			}
		else
			{
			Weird("unpaired_RPC_response");
			n = 0;
			}
		}

	else
		Weird("bad_RPC");

	if ( n > 0 )
		{
		// If it's just padded with zeroes, don't complain.
		for ( ; n > 0; --n, ++buf )
			if ( *buf != 0 )
				break;

		if ( n > 0 )
			Weird("excess_RPC");
		}

	else if ( n < 0 )
		internal_error("RPC underflow");

	return 1;
	}

void RPC_Interpreter::Timeout()
	{
	IterCookie* cookie = calls.InitForIteration();
	RPC_CallInfo* c;

	while ( (c = calls.NextEntry(cookie)) )
		{
		RPC_Event(c, BroEnum::RPC_TIMEOUT, 0);
		if ( c->IsValidCall() )
			{
			const u_char* buf;
			int n = 0;
			EventHandlerPtr event;
			Val* reply;
			if ( ! RPC_BuildReply(c, 0, buf, n, event, reply) )
				Weird("bad_RPC");
			else
				{
				Event(event, c->TakeRequestVal(),
					BroEnum::RPC_TIMEOUT, reply);
				}
			}
		}
	}

void RPC_Interpreter::RPC_Event(RPC_CallInfo* c, int status, int reply_len)
	{
	if ( rpc_call )
		{
		val_list* vl = new val_list;
		vl->append(analyzer->BuildConnVal());
		vl->append(new Val(c->Program(), TYPE_COUNT));
		vl->append(new Val(c->Version(), TYPE_COUNT));
		vl->append(new Val(c->Proc(), TYPE_COUNT));
		vl->append(new Val(status, TYPE_COUNT));
		vl->append(new Val(c->StartTime(), TYPE_TIME));
		vl->append(new Val(c->CallLen(), TYPE_COUNT));
		vl->append(new Val(reply_len, TYPE_COUNT));
		analyzer->ConnectionEvent(rpc_call, vl);
		}
	}

void RPC_Interpreter::Weird(const char* msg)
	{
	analyzer->Weird(msg);
	}


Contents_RPC::Contents_RPC(Connection* conn, bool orig,
				RPC_Interpreter* arg_interp)
: TCP_SupportAnalyzer(AnalyzerTag::Contents_RPC, conn, orig)
	{
	interp = arg_interp;
	resync = false;
	msg_buf = 0;
	InitBuffer();
	}

void Contents_RPC::Init()
	{
	TCP_SupportAnalyzer::Init();

	TCP_Analyzer* tcp =
		static_cast<TCP_ApplicationAnalyzer*>(Parent())->TCP();
	assert(tcp);

	resync = (IsOrig() ? tcp->OrigState() : tcp->RespState()) !=
						TCP_ENDPOINT_ESTABLISHED;
	}

void Contents_RPC::InitBuffer()
	{
	buf_len = 4;

	// For record marker:
	delete [] msg_buf;
	msg_buf = new u_char[buf_len];

	buf_n = 0;
	last_frag = 0;
	state = RPC_RECORD_MARKER;
	}

Contents_RPC::~Contents_RPC()
	{
	delete [] msg_buf;
	}

void Contents_RPC::Undelivered(int seq, int len, bool orig)
	{
	TCP_SupportAnalyzer::Undelivered(seq, len, orig);

	// Re-sync after content gaps.
	InitBuffer();
	resync = true;
	}

void Contents_RPC::DeliverStream(int len, const u_char* data, bool orig)
	{
	TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	if ( state == RPC_COMPLETE )
		InitBuffer();

	// This is an attempt to re-synchronize the stream with RPC
	// frames after a content gap.  We try to look for the beginning
	// of an RPC frame, assuming (1) RPC frames begin at packet
	// boundaries (though they may span over multiple packets) and
	// (2) the first piece is longer than 12 bytes. (If we see a
	// piece shorter than 12 bytes, it is likely that it's the
	// remaining piece of a previous RPC frame, so the code here
	// skips that piece.)  It then checks if the frame type and length
	// make any sense, and if so, it assumes that is beginning of
	// a frame.
	if ( resync && state == RPC_RECORD_MARKER && buf_n == 0 )
		{
		// Assuming RPC frames align with packet boundaries ...
		if ( len < 12 )
			{
			// Ignore small fragmeents.
			if ( len != 1 && DEBUG_rpc_resync )
				{
				// One-byte fragments are likely caused by
				// TCP keep-alive retransmissions.
				DEBUG_MSG("%.6f RPC resync: "
				          "discard small pieces: %d\n",
			                  network_time, len);
				Conn()->Weird(
					fmt("RPC resync: discard %d bytes\n",
						len));
				}
			return;
			}

		const u_char* xdata = data;
		int xlen = len;
		uint32 frame_len = extract_XDR_uint32(xdata, xlen);
		uint32 xid = extract_XDR_uint32(xdata, xlen);
		uint32 frame_type = extract_XDR_uint32(xdata, xlen);

		if ( (IsOrig() && frame_type != 0) ||
		     (! IsOrig() && frame_type != 1) ||
		     frame_len < 16 )
			{
			// Skip this packet.
			if ( DEBUG_rpc_resync )
				{
				DEBUG_MSG("RPC resync: skipping %d bytes\n",
				          len);
				}
			return;
			}

		resync = false;
		}

	int n;
	for ( n = 0; buf_n < buf_len && n < len; ++n )
		msg_buf[buf_n++] = data[n];

	if ( buf_n < buf_len )
		// Haven't filled up the message buffer yet, no more to do.
		return;

	switch ( state ) {
	case RPC_RECORD_MARKER:
		{ // Have the whole record marker.
		int prev_frag_len = buf_len - 4;
		const u_char* buf = &msg_buf[prev_frag_len];
		int n = 4;

		uint32 marker = extract_XDR_uint32(buf, n);
		if ( ! buf )
			internal_error("inconsistent RPC record marker extraction");

		if ( prev_frag_len > 0 && last_frag )
			internal_error("last_frag set but more fragments");

		last_frag = (marker & 0x80000000) != 0;

		marker &= 0x7fffffff;

		if ( prev_frag_len > 0 )
			// We're adding another fragment.
			marker += prev_frag_len;

		// Fragment length is now given by marker.  Sanity-check.
		if ( marker > MAX_RPC_LEN )
			{
			Conn()->Weird("excessive_RPC_len");
			marker = MAX_RPC_LEN;
			}

		// The new size is either the full record size (if this
		// is the last fragment), or that plus 4 more bytes for
		// the next fragment header.
		int new_size = last_frag ? marker : marker + 4;

		u_char* tmp = new u_char[new_size];
		int msg_len = (unsigned int) buf_len < marker ? buf_len : marker;
		for ( int i = 0; i < msg_len; ++i )
			tmp[i] = msg_buf[i];

		delete [] msg_buf;
		msg_buf = tmp;

		buf_len = marker;	// we only want to fill to here
		buf_n = prev_frag_len;	// overwrite this fragment's header

		state = RPC_MESSAGE_BUFFER;
		}
		break;

	case RPC_MESSAGE_BUFFER:
		{ // Have the whole fragment.
		if ( ! last_frag )
			{
			// We earlier made sure to leave an extra 4 bytes
			// at the end of the buffer - use them now for
			// the new fragment header.
			buf_len += 4;
			state = RPC_RECORD_MARKER;
			break;
			}

		if ( ! interp->DeliverRPC(msg_buf, buf_n, IsOrig()) )
			Conn()->Weird("partial_RPC");

		state = RPC_COMPLETE;
		delete [] msg_buf;
		msg_buf = 0;
		}
		break;

	case RPC_COMPLETE:
		internal_error("RPC state inconsistency");
	}

	if ( n < len )
		// More data to munch on.
		DeliverStream(len - n, data + n, orig);
	}

RPC_Analyzer::RPC_Analyzer(AnalyzerTag::Tag tag, Connection* conn,
				RPC_Interpreter* arg_interp)
: TCP_ApplicationAnalyzer(tag, conn)
	{
	interp = arg_interp;

	if ( Conn()->ConnTransport() == TRANSPORT_UDP )
		ADD_ANALYZER_TIMER(&RPC_Analyzer::ExpireTimer,
			network_time + rpc_timeout, 1, TIMER_RPC_EXPIRE);
	}

RPC_Analyzer::~RPC_Analyzer()
	{
	delete interp;
	}

void RPC_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
					int seq, const IP_Hdr* ip, int caplen)
	{
	TCP_ApplicationAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	if ( orig )
		{
		if ( ! interp->DeliverRPC(data, len, 1) )
			Weird("bad_RPC");
		}
	else
		{
		if ( ! interp->DeliverRPC(data, len, 0) )
			Weird("bad_RPC");
		}
	}

void RPC_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	// This code was replicated in NFS.cc and Portmap.cc, so we factor
	// it into here.  The semantics have slightly changed - it used
	// to be we'd always execute interp->Timeout(), but now we only
	// do for UDP.

	if ( Conn()->ConnTransport() == TRANSPORT_TCP && TCP() )
		{
		if ( orig_rpc->State() != RPC_COMPLETE &&
		     (TCP()->OrigState() == TCP_ENDPOINT_CLOSED ||
		      TCP()->OrigPrevState() == TCP_ENDPOINT_CLOSED) &&
		     // Sometimes things like tcpwrappers will immediately
		     // close the connection, without any data having been
		     // transferred.  Don't bother flagging these.
		     TCP()->Orig()->Size() > 0 )
			Weird("partial_RPC_request");
		}
	else
		interp->Timeout();
	}

void RPC_Analyzer::ExpireTimer(double /* t */)
	{
	Event(connection_timeout);
	sessions->Remove(Conn());
	}

// The binpac version of interpreter.
#include "rpc_pac.h"

RPC_UDP_Analyzer_binpac::RPC_UDP_Analyzer_binpac(Connection* conn)
: Analyzer(AnalyzerTag::RPC_UDP_BINPAC, conn)
	{
	interp = new binpac::SunRPC::RPC_Conn(this);
	ADD_ANALYZER_TIMER(&RPC_UDP_Analyzer_binpac::ExpireTimer,
			network_time + rpc_timeout, 1, TIMER_RPC_EXPIRE);
	}

RPC_UDP_Analyzer_binpac::~RPC_UDP_Analyzer_binpac()
	{
	delete interp;
	}

void RPC_UDP_Analyzer_binpac::Done()
	{
	Analyzer::Done();
	interp->Timeout();
	}

void RPC_UDP_Analyzer_binpac::DeliverPacket(int len, const u_char* data, bool orig, int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);
	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( binpac::Exception &e )
		{
		Weird(fmt("bad_RPC: %s", e.msg().c_str()));
		}
	}

void RPC_UDP_Analyzer_binpac::ExpireTimer(double /* t */)
	{
	Event(connection_timeout);
	sessions->Remove(Conn());
	}
