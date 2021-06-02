// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/analyzer/protocol/login/RSH.h"

#include "zeek/NetVar.h"
#include "zeek/Event.h"
#include "zeek/Reporter.h"

#include "zeek/analyzer/protocol/login/events.bif.h"

namespace zeek::analyzer::login {

// FIXME: this code should probably be merged with Rlogin.cc.

Contents_Rsh_Analyzer::Contents_Rsh_Analyzer(Connection* conn, bool orig,
                                             Rsh_Analyzer* arg_analyzer)
	: analyzer::tcp::ContentLine_Analyzer("CONTENTS_RSH", conn, orig)
	{
	num_bytes_to_scan = 0;
	analyzer = arg_analyzer;

	if ( orig )
		state = save_state = RSH_FIRST_NULL;
	else
		{
		state = RSH_LINE_MODE;
		save_state = RSH_UNKNOWN;
		}
	}

Contents_Rsh_Analyzer::~Contents_Rsh_Analyzer()
	{
	}

void Contents_Rsh_Analyzer::DoDeliver(int len, const u_char* data)
	{
	auto* tcp = static_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(Parent())->TCP();
	assert(tcp);

	int endp_state = IsOrig() ? tcp->OrigState() : tcp->RespState();

	for ( ; len > 0; --len, ++data )
		{
		if ( offset >= buf_len )
			InitBuffer(buf_len * 2);

		unsigned int c = data[0];

		switch ( state ) {
		case RSH_FIRST_NULL:
			if ( endp_state == analyzer::tcp::TCP_ENDPOINT_PARTIAL ||
			     // We can be in closed if the data's due to
			     // a dataful FIN being the first thing we see.
			     endp_state == analyzer::tcp::TCP_ENDPOINT_CLOSED )
				{
				state = RSH_UNKNOWN;
				++len, --data;	// put back c and reprocess
				continue;
				}

			if ( c >= '0' && c <= '9' )
				; // skip stderr port number
			else if ( c == '\0' )
				state = RSH_CLIENT_USER_NAME;
			else
				BadProlog();

			break;

		case RSH_CLIENT_USER_NAME:
		case RSH_SERVER_USER_NAME:
			buf[offset++] = c;
			if ( c == '\0' )
				{
				if ( state == RSH_CLIENT_USER_NAME )
					{
					analyzer->ClientUserName((const char*) buf);
					state = RSH_SERVER_USER_NAME;
					}

				else if ( state == RSH_SERVER_USER_NAME &&
					  offset > 1 )
					{
					analyzer->ServerUserName((const char*) buf);
					save_state = state;
					state = RSH_LINE_MODE;
					}

				offset = 0;
				}
			break;

		case RSH_LINE_MODE:
		case RSH_UNKNOWN:
		case RSH_PRESUMED_REJECTED:
			if ( state == RSH_PRESUMED_REJECTED )
				{
				Weird("rsh_text_after_rejected");
				state = RSH_UNKNOWN;
				}

			if ( c == '\n' || c == '\r' )
				{ // CR or LF (RFC 1282)
				if ( c == '\n' && last_char == '\r' )
					// Compress CRLF to just 1 termination.
					;
				else
					{
					buf[offset] = '\0';
					ForwardStream(offset, buf, IsOrig()); \
					save_state = RSH_LINE_MODE;
					offset = 0;
					break;
					}
				}

			if ( c == '\0' )
				{
				buf[offset] = '\0';
				ForwardStream(offset, buf, IsOrig()); \
				save_state = RSH_LINE_MODE;
				offset = 0;
				break;
				}

			else
				buf[offset++] = c;

			last_char = c;
			break;

		default:
			reporter->AnalyzerError(
				this, "bad state in Contents_Rsh_Analyzer::DoDeliver");
			break;
		}
		}
	}

void Contents_Rsh_Analyzer::BadProlog()
	{
	Weird("bad_rsh_prolog");
	state = RSH_UNKNOWN;
	}

Rsh_Analyzer::Rsh_Analyzer(Connection* conn)
: Login_Analyzer("RSH", conn)
	{
	contents_orig = new Contents_Rsh_Analyzer(conn, true, this);
	contents_resp = new Contents_Rsh_Analyzer(conn, false, this);
	AddSupportAnalyzer(contents_orig);
	AddSupportAnalyzer(contents_resp);
	}

void Rsh_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	Login_Analyzer::DeliverStream(len, data, orig);

	if ( orig )
		{
		if ( ! rsh_request )
			return;
		}
	else
		{
		if ( ! rsh_reply )
			return;
		}

	Args vl;
	vl.reserve(4 + orig);
	const char* line = (const char*) data;
	line = util::skip_whitespace(line);
	vl.emplace_back(ConnVal());

	if ( client_name )
		vl.emplace_back(NewRef{}, client_name);
	else
		vl.emplace_back(make_intrusive<StringVal>("<none>"));

	if ( username )
		vl.emplace_back(NewRef{}, username);
	else
		vl.emplace_back(make_intrusive<StringVal>("<none>"));

	vl.emplace_back(make_intrusive<StringVal>(line));

	if ( orig )
		{
		if ( contents_orig->RshSaveState() == RSH_SERVER_USER_NAME )
			// First input
			vl.emplace_back(val_mgr->True());
		else
			vl.emplace_back(val_mgr->False());

		EnqueueConnEvent(rsh_request, std::move(vl));
		}

	else
		EnqueueConnEvent(rsh_reply, std::move(vl));
	}

void Rsh_Analyzer::ClientUserName(const char* s)
	{
	if ( client_name )
		{
		reporter->AnalyzerError(this, "multiple rsh client names");
		return;
		}

	client_name = new StringVal(s);
	}

void Rsh_Analyzer::ServerUserName(const char* s)
	{
	if ( username )
		{
		reporter->AnalyzerError(this, "multiple rsh initial client names");
		return;
		}

	username = new StringVal(s);
	}

} // namespace zeek::analyzer::login
