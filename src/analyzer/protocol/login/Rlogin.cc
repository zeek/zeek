// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "NetVar.h"
#include "Event.h"
#include "Rlogin.h"

#include "events.bif.h"

using namespace analyzer::login;

Contents_Rlogin_Analyzer::Contents_Rlogin_Analyzer(Connection* conn, bool orig, Rlogin_Analyzer* arg_analyzer)
: tcp::ContentLine_Analyzer("CONTENTLINE", conn, orig)
	{
	num_bytes_to_scan = 0;
	analyzer = arg_analyzer;
	peer = 0;

	if ( orig )
		state = save_state = RLOGIN_FIRST_NULL;
	else
		state = save_state = RLOGIN_SERVER_ACK;
	}

Contents_Rlogin_Analyzer::~Contents_Rlogin_Analyzer()
	{
	}

void Contents_Rlogin_Analyzer::DoDeliver(int len, const u_char* data)
	{
	tcp::TCP_Analyzer* tcp = static_cast<tcp::TCP_ApplicationAnalyzer*>(Parent())->TCP();
	assert(tcp);

	int endp_state = IsOrig() ? tcp->OrigState() : tcp->RespState();

	for ( ; len > 0; --len, ++data )
		{
		if ( offset >= buf_len )
			InitBuffer(buf_len * 2);

		unsigned int c = data[0];

		switch ( state ) {
		case RLOGIN_FIRST_NULL:
			if ( endp_state == tcp::TCP_ENDPOINT_PARTIAL ||
			     // We can be in closed if the data's due to
			     // a dataful FIN being the first thing we see.
			     endp_state == tcp::TCP_ENDPOINT_CLOSED )
				{
				state = RLOGIN_UNKNOWN;
				++len, --data;	// put back c and reprocess
				continue;
				}

			if ( c == '\0' )
				state = RLOGIN_CLIENT_USER_NAME;
			else
				BadProlog();
			break;

		case RLOGIN_CLIENT_USER_NAME:
		case RLOGIN_SERVER_USER_NAME:
		case RLOGIN_TERMINAL_TYPE:
			buf[offset++] = c;
			if ( c == '\0' )
				{
				if ( state == RLOGIN_CLIENT_USER_NAME )
					{
					analyzer->ClientUserName((const char*) buf);
					state = RLOGIN_SERVER_USER_NAME;
					}

				else if ( state == RLOGIN_SERVER_USER_NAME )
					{
					analyzer->ServerUserName((const char*) buf);
					state = RLOGIN_TERMINAL_TYPE;
					}

				else if ( state == RLOGIN_TERMINAL_TYPE )
					{
					analyzer->TerminalType((const char*) buf);
					state = RLOGIN_LINE_MODE;
					}

				offset = 0;
				}
			break;

		case RLOGIN_SERVER_ACK:
			if ( endp_state == tcp::TCP_ENDPOINT_PARTIAL ||
			     // We can be in closed if the data's due to
			     // a dataful FIN being the first thing we see.
			     endp_state == tcp::TCP_ENDPOINT_CLOSED )
				{
				state = RLOGIN_UNKNOWN;
				++len, --data;	// put back c and reprocess
				continue;
				}

			if ( c == '\0' )
				state = RLOGIN_LINE_MODE;
			else
				state = RLOGIN_PRESUMED_REJECTED;
			break;

		case RLOGIN_IN_BAND_CONTROL_FF2:
			if ( c == 255 )
				state = RLOGIN_WINDOW_CHANGE_S1;
			else
				{
				// Put back the \ff that took us into
				// this state.
				buf[offset++] = 255;
				state = save_state;
				++len, --data;	// put back c and reprocess
				continue;
				}
			break;

		case RLOGIN_WINDOW_CHANGE_S1:
		case RLOGIN_WINDOW_CHANGE_S2:
			if ( c == 's' )
				{
				if ( state == RLOGIN_WINDOW_CHANGE_S1 )
					state = RLOGIN_WINDOW_CHANGE_S2;
				else
					{
					state = RLOGIN_WINDOW_CHANGE_REMAINDER;
					num_bytes_to_scan = 8;
					}
				}
			else
				{ 
				// Unknown control, or we're confused.
				// Put back what we've consumed.
				unsigned char buf[64];
				int n = 0;
				buf[n++] = '\xff';
				buf[n++] = '\xff';

				if ( state == RLOGIN_WINDOW_CHANGE_S2 )
					buf[n++] = 's';

				state = RLOGIN_UNKNOWN;

				DoDeliver(n, buf);
				}
			break;

		case RLOGIN_WINDOW_CHANGE_REMAINDER:
			if ( --num_bytes_to_scan == 0 )
				state = save_state;
			break;

		case RLOGIN_LINE_MODE:
		case RLOGIN_UNKNOWN:
		case RLOGIN_PRESUMED_REJECTED:
			assert(peer);
			if ( state == RLOGIN_LINE_MODE &&
			     peer->state == RLOGIN_PRESUMED_REJECTED )
				{
				Conn()->Weird("rlogin_text_after_rejected");
				state = RLOGIN_UNKNOWN;
				}

			if ( c == '\n' || c == '\r' ) // CR or LF (RFC 1282)
				{
				if ( c == '\n' && last_char == '\r' )
					// Compress CRLF to just 1 termination.
					;
				else
					{
					buf[offset] = '\0';
					ForwardStream(offset, buf, IsOrig()); \
					offset = 0;
					break;
					}
				}

			else if ( c == 255 && IsOrig() &&
				  state != RLOGIN_PRESUMED_REJECTED &&
				  state != RLOGIN_UNKNOWN )
				{
				save_state = state;
				state = RLOGIN_IN_BAND_CONTROL_FF2;
				}

			else
				buf[offset++] = c;

			last_char = c;
			break;

		default:
			reporter->AnalyzerError(this,
			  "bad state in Contents_Rlogin_Analyzer::DoDeliver");
			break;
		}
		}
	}

void Contents_Rlogin_Analyzer::BadProlog()
	{
	Conn()->Weird("bad_rlogin_prolog");
	state = RLOGIN_UNKNOWN;
	}


Rlogin_Analyzer::Rlogin_Analyzer(Connection* conn)
: Login_Analyzer("RLOGIN", conn)
	{
	Contents_Rlogin_Analyzer* orig =
		new Contents_Rlogin_Analyzer(conn, true, this);
	Contents_Rlogin_Analyzer* resp =
		new Contents_Rlogin_Analyzer(conn, false, this);

	orig->SetPeer(resp);
	resp->SetPeer(orig);

	AddSupportAnalyzer(orig);
	AddSupportAnalyzer(resp);
	}

void Rlogin_Analyzer::ClientUserName(const char* s)
	{
	if ( client_name )
		{
		reporter->AnalyzerError(this, "multiple rlogin client names");
		return;
		}

	client_name = new StringVal(s);
	}

void Rlogin_Analyzer::ServerUserName(const char* s)
	{
	++num_user_lines_seen;
	++login_prompt_line;
	AddUserText(s);
	}

void Rlogin_Analyzer::TerminalType(const char* s)
	{
	if ( login_terminal )
		{
		val_list* vl = new val_list;

		vl->append(BuildConnVal());
		vl->append(new StringVal(s));

		ConnectionEvent(login_terminal, vl);
		}
	}
