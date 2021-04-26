// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/analyzer/protocol/netbios/NetbiosSSN.h"

#include <ctype.h>

#include "zeek/ZeekString.h"
#include "zeek/NetVar.h"
#include "zeek/session/SessionManager.h"
#include "zeek/Event.h"
#include "zeek/RunState.h"

#include "zeek/analyzer/protocol/netbios/events.bif.h"

constexpr double netbios_ssn_session_timeout = 15.0;

#define MAKE_INT16(dest, src) dest = *src; dest <<=8; src++; dest |= *src; src++;

namespace zeek::analyzer::netbios_ssn {
namespace detail {

NetbiosSSN_RawMsgHdr::NetbiosSSN_RawMsgHdr(const u_char*& data, int& len)
	{
	type = *data; ++data, --len;
	flags = *data; ++data, --len;
	length = *data; ++data, --len;

	length <<= 8;
	length |= *data;
	++data, --len;
	}

NetbiosDGM_RawMsgHdr::NetbiosDGM_RawMsgHdr(const u_char*& data, int& len)
	{
	type = *data; ++data, --len;
	flags = *data; ++data, --len;

	MAKE_INT16(id, data); len -= 2;

	srcip = *data++ << 24;
	srcip |= *data++ << 16;
	srcip |= *data++ << 8;
	srcip |= *data++;
	len -=4;

	MAKE_INT16(srcport, data); len -= 2;
	MAKE_INT16(length, data); len -= 2;
	MAKE_INT16(offset, data);; len -= 2;
	}

NetbiosSSN_Interpreter::NetbiosSSN_Interpreter(analyzer::Analyzer* arg_analyzer)
	{
	analyzer = arg_analyzer;
	//smb_session = arg_smb_session;
	}

void NetbiosSSN_Interpreter::ParseMessage(unsigned int type, unsigned int flags,
                                          const u_char* data, int len, bool is_query)
	{
	if ( netbios_session_message )
		analyzer->EnqueueConnEvent(netbios_session_message,
			analyzer->ConnVal(),
			val_mgr->Bool(is_query),
			val_mgr->Count(type),
			val_mgr->Count(len)
		);

	switch ( type ) {
	case NETBIOS_SSN_MSG:
		ParseSessionMsg(data, len, is_query);
		break;

	case NETBIOS_SSN_REQ:
		ParseSessionReq(data, len, is_query);
		break;

	case NETBIOS_SSN_POS_RESP:
		ParseSessionPosResp(data, len, is_query);
		break;

	case NETBIOS_SSN_NEG_RESP:
		ParseSessionNegResp(data, len, is_query);
		break;

	case NETBIOS_SSN_RETARG_RESP:
		ParseRetArgResp(data, len, is_query);
		break;

	case NETBIOS_SSN_KEEP_ALIVE:
		ParseKeepAlive(data, len, is_query);
		break;

	case NETBIOS_DGM_DIRECT_UNIQUE:
	case NETBIOS_DGM_DIRECT_GROUP:
	case NETBIOS_DGM_BROADCAST:
		ParseBroadcast(data, len, is_query);
		break;

	case NETBIOS_DGM_ERROR:
	case NETBIOS_DGG_QUERY_REQ:
	case NETBIOS_DGM_POS_RESP:
	case NETBIOS_DGM_NEG_RESP:
		ParseDatagram(data, len, is_query);
		break;

 	default:
		analyzer->Weird("unknown_netbios_type", util::fmt("0x%x", type));
		break;
	}
	}

void NetbiosSSN_Interpreter::ParseDatagram(const u_char* data, int len,
						bool is_query)
	{
	//if ( smb_session )
	//	{
	//	smb_session->Deliver(is_query, len, data);
	//	}
 	}

void NetbiosSSN_Interpreter::ParseBroadcast(const u_char* data, int len,
						bool is_query)
 	{
	// FIND THE NUL-TERMINATED NAME STRINGS HERE!
	// Not sure what's in them, so we don't keep them currently.

	String* srcname = new String((char*) data);
	data += srcname->Len()+1;
	len -= srcname->Len();

	String* dstname = new String((char*) data);
	data += dstname->Len()+1;
	len -= dstname->Len();

	delete srcname;
	delete dstname;

	//if ( smb_session )
	//	smb_session->Deliver(is_query, len, data);
	}

void NetbiosSSN_Interpreter::ParseMessageTCP(const u_char* data, int len,
						bool is_query)
	{
	NetbiosSSN_RawMsgHdr hdr(data, len);

	if ( hdr.length > unsigned(len) )
		analyzer->Weird("excess_netbios_hdr_len", util::fmt("(%d > %d)",
					hdr.length, len));

	else if ( hdr.length < unsigned(len) )
		{
		analyzer->Weird("deficit_netbios_hdr_len");
		len = hdr.length;
		}

	ParseMessage(hdr.type, hdr.flags, data, len, is_query);
	}

void NetbiosSSN_Interpreter::ParseMessageUDP(const u_char* data, int len,
						bool is_query)
	{
	NetbiosDGM_RawMsgHdr hdr(data, len);

	if ( unsigned(hdr.length-14) > unsigned(len) )
		analyzer->Weird("excess_netbios_hdr_len", util::fmt("(%d > %d)",
				hdr.length, len));

	else if ( hdr.length < unsigned(len) )
		{
		analyzer->Weird("deficit_netbios_hdr_len", util::fmt("(%d < %d)",
				hdr.length, len));
		len = hdr.length;
		}

	ParseMessage(hdr.type, hdr.flags, data, len, is_query);
	}


void NetbiosSSN_Interpreter::ParseSessionMsg(const u_char* data, int len,
						bool is_query)
	{
	if ( len < 4 || strncmp((const char*) data, "\xffSMB", 4) )
		{
		// This should be an event, too.
		analyzer->Weird("netbios_raw_session_msg");
		Event(netbios_session_raw_message, data, len, is_query);
		return;
		}

	//if ( smb_session )
	//	{
	//	smb_session->Deliver(is_query, len, data);
	//	return 0;
	//	}
	//else
		{
		analyzer->Weird("no_smb_session_using_parsesambamsg");
		data += 4;
		len -= 4;
		ParseSambaMsg(data, len, is_query);
		}
	}

void NetbiosSSN_Interpreter::ParseSambaMsg(const u_char* data, int len,
						bool is_query)
	{
	}

int NetbiosSSN_Interpreter::ConvertName(const u_char* name, int name_len,
					u_char*& xname, int& xlen)
	{
	// Taken from tcpdump's smbutil.c.

	xname = nullptr;

	if ( name_len < 1 )
		return 0;

	int len = (*name++) / 2;
	xlen = len;

	if ( len > 30 || len < 1 || name_len < len )
		return 0;

	u_char* convert_name = new u_char[len + 1];
	*convert_name = 0;
	xname = convert_name;

	while ( len-- )
		{
		if ( name[0] < 'A' || name[0] > 'P' ||
		     name[1] < 'A' || name[1] > 'P' )
			{
			*convert_name = 0;
			return 0;
			}

		*convert_name = ((name[0] - 'A') << 4) + (name[1] - 'A');
		name += 2;
		++convert_name;
		}

	*convert_name = 0;

	return 1;
	}

void NetbiosSSN_Interpreter::ParseSessionReq(const u_char* data, int len,
						bool is_query)
	{
	if ( ! is_query )
		analyzer->Weird("netbios_server_session_request");

	u_char* xname;
	int xlen;

	if ( ConvertName(data, len, xname, xlen) )
		Event(netbios_session_request, xname, xlen);

	delete [] xname;
	}

void NetbiosSSN_Interpreter::ParseSessionPosResp(const u_char* data, int len,
						bool is_query)
	{
	if ( is_query )
		analyzer->Weird("netbios_client_session_reply");

	Event(netbios_session_accepted, data, len);
	}

void NetbiosSSN_Interpreter::ParseSessionNegResp(const u_char* data, int len,
						bool is_query)
	{
	if ( is_query )
		analyzer->Weird("netbios_client_session_reply");

	Event(netbios_session_rejected, data, len);

#if 0
	case 0x80:
		printf("Not listening on called name\n");
		break;
	case 0x81:
		printf("Not listening for calling name\n");
		break;
	case 0x82:
		printf("Called name not present\n");
		break;
	case 0x83:
		printf("Called name present, but insufficient resources\n");
		break;
	default:
		printf("Unspecified error 0x%X\n",ecode);
		break;
#endif
	}

void NetbiosSSN_Interpreter::ParseRetArgResp(const u_char* data, int len,
						bool is_query)
	{
	if ( is_query )
		analyzer->Weird("netbios_client_session_reply");

	Event(netbios_session_ret_arg_resp, data, len);
	}

void NetbiosSSN_Interpreter::ParseKeepAlive(const u_char* data, int len,
						bool is_query)
	{
	Event(netbios_session_keepalive, data, len);
	}

void NetbiosSSN_Interpreter::Event(EventHandlerPtr event, const u_char* data,
                                   int len, int is_orig)
	{
	if ( ! event )
		return;

	if ( is_orig >= 0 )
		analyzer->EnqueueConnEvent(event,
		                           analyzer->ConnVal(),
		                           val_mgr->Bool(is_orig),
		                           make_intrusive<StringVal>(new String(data, len, false)));
	else
		analyzer->EnqueueConnEvent(event,
		                           analyzer->ConnVal(),
		                           make_intrusive<StringVal>(new String(data, len, false)));
	}

} // namespace detail

Contents_NetbiosSSN::Contents_NetbiosSSN(Connection* conn, bool orig,
                                         detail::NetbiosSSN_Interpreter* arg_interp)
: analyzer::tcp::TCP_SupportAnalyzer("CONTENTS_NETBIOSSSN", conn, orig)
	{
	interp = arg_interp;
	type = flags = msg_size = 0;
	msg_buf = nullptr;
	buf_n = buf_len = msg_size = 0;
	state = detail::NETBIOS_SSN_TYPE;
	}

Contents_NetbiosSSN::~Contents_NetbiosSSN()
	{
	delete [] msg_buf;
	}

void Contents_NetbiosSSN::Flush()
	{
	if ( buf_n > 0 )
		{ // Deliver partial message.
		interp->ParseMessage(type, flags, msg_buf, buf_n, IsOrig());
		msg_size = 0;
		}
	}

void Contents_NetbiosSSN::DeliverStream(int len, const u_char* data, bool orig)
	{
	while ( len > 0 )
		ProcessChunk(len, data, orig);
	}

void Contents_NetbiosSSN::ProcessChunk(int& len, const u_char*& data, bool orig)
	{
	analyzer::tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

	if ( state == detail::NETBIOS_SSN_TYPE )
		{
		type = *data;
		state = detail::NETBIOS_SSN_FLAGS;

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state == detail::NETBIOS_SSN_FLAGS )
		{
		flags = *data;
		state = detail::NETBIOS_SSN_LEN_HI;

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state == detail::NETBIOS_SSN_LEN_HI )
		{
		msg_size = (*data) << 8;
		state = detail::NETBIOS_SSN_LEN_LO;

		++data;
		--len;

		if ( len == 0 )
			return;
		}

	if ( state == detail::NETBIOS_SSN_LEN_LO )
		{
		msg_size += *data;
		state = detail::NETBIOS_SSN_BUF;

		buf_n = 0;

		if ( msg_buf )
			{
			if ( buf_len < msg_size )
				{
				delete [] msg_buf;
				buf_len = msg_size;
				msg_buf = new u_char[buf_len];
				}
			}
		else
			{
			buf_len = msg_size;
			if ( buf_len > 0 )
				msg_buf = new u_char[buf_len];
			}

		++data;
		--len;

		if ( len == 0 && msg_size != 0 )
			return;
		}

	if ( state != detail::NETBIOS_SSN_BUF )
		Conn()->Internal("state inconsistency in Contents_NetbiosSSN::Deliver");

	int n;
	for ( n = 0; buf_n < msg_size && n < len; ++n )
		msg_buf[buf_n++] = data[n];

	data += n;
	len -= n;

	if ( buf_n < msg_size )
		// Haven't filled up the message buffer yet, no more to do.
		return;

	interp->ParseMessage(type, flags, msg_buf, msg_size, IsOrig());
	buf_n = 0;

	state = detail::NETBIOS_SSN_TYPE;
	}

NetbiosSSN_Analyzer::NetbiosSSN_Analyzer(Connection* conn)
: analyzer::tcp::TCP_ApplicationAnalyzer("NETBIOSSSN", conn)
	{
	//smb_session = new SMB_Session(this);
	interp = new detail::NetbiosSSN_Interpreter(this);
	orig_netbios = resp_netbios = nullptr;
	did_session_done = 0;

	if ( Conn()->ConnTransport() == TRANSPORT_TCP )
		{
		orig_netbios = new Contents_NetbiosSSN(conn, true, interp);
		resp_netbios = new Contents_NetbiosSSN(conn, false, interp);
		AddSupportAnalyzer(orig_netbios);
		AddSupportAnalyzer(resp_netbios);
		}
	else
		{
		ADD_ANALYZER_TIMER(&NetbiosSSN_Analyzer::ExpireTimer,
		                   run_state::network_time + netbios_ssn_session_timeout, true,
		                   zeek::detail::TIMER_NB_EXPIRE);
		}
	}

NetbiosSSN_Analyzer::~NetbiosSSN_Analyzer()
	{
	delete interp;
	//delete smb_session;
	}

void NetbiosSSN_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();
	interp->Timeout();

	if ( Conn()->ConnTransport() == TRANSPORT_UDP && ! did_session_done )
		Event(udp_session_done);
	else
		interp->Timeout();
	}

void NetbiosSSN_Analyzer::EndpointEOF(bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(orig);

	(orig ? orig_netbios : resp_netbios)->Flush();
	}

void NetbiosSSN_Analyzer::ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
                                           analyzer::tcp::TCP_Endpoint* peer, bool gen_event)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);

	// Question: Why do we flush *both* endpoints upon connection close?
	// orig_netbios->Flush();
	// resp_netbios->Flush();
	}

void NetbiosSSN_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
					uint64_t seq, const IP_Hdr* ip, int caplen)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	if ( orig )
		interp->ParseMessageUDP(data, len, true);
	else
		interp->ParseMessageUDP(data, len, false);
	}

void NetbiosSSN_Analyzer::ExpireTimer(double t)
	{
	// The - 1.0 in the following is to allow 1 second for the
	// common case of a single request followed by a single reply,
	// so we don't needlessly set the timer twice in that case.
	if ( run_state::terminating ||
	     run_state::network_time - Conn()->LastTime() >=
		     netbios_ssn_session_timeout - 1.0 )
		{
		Event(connection_timeout);
		session_mgr->Remove(Conn());
		}
	else
		ADD_ANALYZER_TIMER(&NetbiosSSN_Analyzer::ExpireTimer,
		                   t + netbios_ssn_session_timeout,
		                   true, zeek::detail::TIMER_NB_EXPIRE);
	}

} // namespace zeek::analyzer::netbios_ssn
