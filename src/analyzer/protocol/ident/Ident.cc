// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <ctype.h>

#include "ZeekString.h"
#include "NetVar.h"
#include "Ident.h"
#include "Event.h"

#include "events.bif.h"

namespace zeek::analyzer::ident {

Ident_Analyzer::Ident_Analyzer(zeek::Connection* conn)
: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("IDENT", conn)
	{
	did_bad_reply = did_deliver = false;

	orig_ident = new zeek::analyzer::tcp::ContentLine_Analyzer(conn, true, 1000);
	resp_ident = new zeek::analyzer::tcp::ContentLine_Analyzer(conn, false, 1000);

	orig_ident->SetIsNULSensitive(true);
	resp_ident->SetIsNULSensitive(true);

	AddSupportAnalyzer(orig_ident);
	AddSupportAnalyzer(resp_ident);
	}

void Ident_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	if ( TCP() )
		if ( (! did_deliver || orig_ident->HasPartialLine()) &&
		     (TCP()->OrigState() == zeek::analyzer::tcp::TCP_ENDPOINT_CLOSED ||
		      TCP()->OrigPrevState() == zeek::analyzer::tcp::TCP_ENDPOINT_CLOSED) &&
		     TCP()->OrigPrevState() != zeek::analyzer::tcp::TCP_ENDPOINT_PARTIAL &&
		     TCP()->RespPrevState() != zeek::analyzer::tcp::TCP_ENDPOINT_PARTIAL &&
		     TCP()->OrigPrevState() != zeek::analyzer::tcp::TCP_ENDPOINT_INACTIVE &&
		     TCP()->RespPrevState() != zeek::analyzer::tcp::TCP_ENDPOINT_INACTIVE )
			Weird("partial_ident_request");
	}

void Ident_Analyzer::DeliverStream(int length, const u_char* data, bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, is_orig);

	int remote_port, local_port;
	const char* line = (const char*) data;
	const char* orig_line = line;
	const char* end_of_line = line + length;

	zeek::analyzer::tcp::TCP_Endpoint* s = nullptr;

	if ( TCP() )
		s = is_orig ? TCP()->Orig() : TCP()->Resp();

	if ( length == 0 )
		return;

	if ( is_orig )
		{
		if ( ! ident_request )
			return;

		line = ParsePair(line, end_of_line, remote_port, local_port);
		if ( ! line )
			{
			if ( s && s->state == zeek::analyzer::tcp::TCP_ENDPOINT_CLOSED &&
			     (s->prev_state == zeek::analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
			      s->prev_state == zeek::analyzer::tcp::TCP_ENDPOINT_PARTIAL) )
				// not surprising the request is mangled.
				return;

			BadRequest(length, orig_line);
			return;
			}

		if ( line != end_of_line )
			{
			zeek::String s((const u_char*)orig_line, length, true);
			Weird("ident_request_addendum", s.CheckString());
			}

		EnqueueConnEvent(ident_request,
			ConnVal(),
			zeek::val_mgr->Port(local_port, TRANSPORT_TCP),
			zeek::val_mgr->Port(remote_port, TRANSPORT_TCP)
		);

		did_deliver = true;
		}

	else
		{
		if ( ! ident_reply )
			return;

		line = ParsePair(line, end_of_line, remote_port, local_port);

		if ( ! line || line == end_of_line || line[0] != ':' )
			{
			if ( s && s->state == zeek::analyzer::tcp::TCP_ENDPOINT_CLOSED &&
			     (s->prev_state == zeek::analyzer::tcp::TCP_ENDPOINT_INACTIVE ||
			      s->prev_state == zeek::analyzer::tcp::TCP_ENDPOINT_PARTIAL) )
				// not surprising the request is mangled.
				return;

			BadReply(length, orig_line);
			return;
			}

		line = zeek::util::skip_whitespace(line + 1, end_of_line);
		int restlen = end_of_line - line;

		int is_error;
		if ( restlen >= 5 && ! strncmp(line, "ERROR", 5) )
			{
			is_error = 1;
			line += 5;
			}
		else if ( restlen >= 6 && ! strncmp(line, "USERID", 6) )
			{
			is_error = 0;
			line += 6;
			}
		else
			{
			BadReply(length, orig_line);
			return;
			}

		line = zeek::util::skip_whitespace(line, end_of_line);

		if ( line >= end_of_line || line[0] != ':' )
			{
			BadReply(length, orig_line);
			return;
			}

		line = zeek::util::skip_whitespace(line + 1, end_of_line);

		if ( is_error )
			{
			if ( ident_error )
				EnqueueConnEvent(ident_error,
					ConnVal(),
					zeek::val_mgr->Port(local_port, TRANSPORT_TCP),
					zeek::val_mgr->Port(remote_port, TRANSPORT_TCP),
					zeek::make_intrusive<zeek::StringVal>(end_of_line - line, line)
				);
			}

		else
			{
			const char* sys_type = line;
			assert(line <= end_of_line);
			size_t n = end_of_line >= line ? end_of_line - line : 0; // just to be sure if assertions aren't on.
			const char* colon = reinterpret_cast<const char*>(memchr(line, ':', n));
			const char* comma = reinterpret_cast<const char*>(memchr(line, ',', n));
			if ( ! colon )
				{
				BadReply(length, orig_line);
				return;
				}

			const char* sys_end = (comma && comma < colon) ?
						comma : colon;

			while ( --sys_end > sys_type && isspace(*sys_end) )
				;

			zeek::String* sys_type_s =
				new zeek::String((const u_char*) sys_type,
				                    sys_end - sys_type + 1, true);

			line = zeek::util::skip_whitespace(colon + 1, end_of_line);

			EnqueueConnEvent(ident_reply,
				ConnVal(),
				zeek::val_mgr->Port(local_port, TRANSPORT_TCP),
				zeek::val_mgr->Port(remote_port, TRANSPORT_TCP),
				zeek::make_intrusive<zeek::StringVal>(end_of_line - line, line),
				zeek::make_intrusive<zeek::StringVal>(sys_type_s)
			);
			}
		}
	}

const char* Ident_Analyzer::ParsePair(const char* line, const char* end_of_line, int & p1, int& p2)
	{
	line = ParsePort(line, end_of_line, p1);
	if ( ! line )
		{
		return nullptr;
		}

	if ( line >= end_of_line || line[0] != ',' )
		return nullptr;

	++line;

	line = ParsePort(line, end_of_line, p2);
	if ( ! line )
		return nullptr;

	return line;
	}

const char* Ident_Analyzer::ParsePort(const char* line, const char* end_of_line,
				int& pn)
	{
	int n = 0;

	line = zeek::util::skip_whitespace(line, end_of_line);
	if ( line >= end_of_line || ! isdigit(*line) )
		return nullptr;

	const char* l = line;

	do
		{
		n = n * 10 + (*line - '0');
		++line;
		}
	while ( line < end_of_line && isdigit(*line) );

	line = zeek::util::skip_whitespace(line, end_of_line);

	if ( n < 0 || n > 65535 )
		{
		Weird("bad_ident_port", l);
		n = 0;
		}

	pn = n;

	return line;
	}

void Ident_Analyzer::BadRequest(int length, const char* line)
	{
	zeek::String s((const u_char*)line, length, true);
	Weird("bad_ident_request", s.CheckString());
	}

void Ident_Analyzer::BadReply(int length, const char* line)
	{
	if ( ! did_bad_reply )
		{
		zeek::String s((const u_char*)line, length, true);
		Weird("bad_ident_reply", s.CheckString());
		did_bad_reply = true;
		}
	}

} // namespace zeek::analyzer::ident
