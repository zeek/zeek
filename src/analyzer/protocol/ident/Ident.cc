// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <ctype.h>

#include "NetVar.h"
#include "Ident.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::ident;

Ident_Analyzer::Ident_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("IDENT", conn)
	{
	did_bad_reply = did_deliver = 0;

	orig_ident = new tcp::ContentLine_Analyzer(conn, true);
	resp_ident = new tcp::ContentLine_Analyzer(conn, false);

	orig_ident->SetIsNULSensitive(true);
	resp_ident->SetIsNULSensitive(true);

	AddSupportAnalyzer(orig_ident);
	AddSupportAnalyzer(resp_ident);
	}

void Ident_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( TCP() )
		if ( (! did_deliver || orig_ident->HasPartialLine()) &&
		     (TCP()->OrigState() == tcp::TCP_ENDPOINT_CLOSED ||
		      TCP()->OrigPrevState() == tcp::TCP_ENDPOINT_CLOSED) &&
		     TCP()->OrigPrevState() != tcp::TCP_ENDPOINT_PARTIAL &&
		     TCP()->RespPrevState() != tcp::TCP_ENDPOINT_PARTIAL &&
		     TCP()->OrigPrevState() != tcp::TCP_ENDPOINT_INACTIVE &&
		     TCP()->RespPrevState() != tcp::TCP_ENDPOINT_INACTIVE )
			Weird("partial_ident_request");
	}

void Ident_Analyzer::DeliverStream(int length, const u_char* data, bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(length, data, is_orig);

	int remote_port, local_port;
	const char* line = (const char*) data;
	const char* orig_line = line;
	const char* end_of_line = line + length;

	tcp::TCP_Endpoint* s = 0;

	if ( TCP() )
		s = is_orig ? TCP()->Orig() : TCP()->Resp();

	if ( is_orig )
		{
		if ( ! ident_request )
			return;

		line = ParsePair(line, end_of_line, remote_port, local_port);
		if ( ! line )
			{
			if ( s && s->state == tcp::TCP_ENDPOINT_CLOSED &&
			     (s->prev_state == tcp::TCP_ENDPOINT_INACTIVE ||
			      s->prev_state == tcp::TCP_ENDPOINT_PARTIAL) )
				// not surprising the request is mangled.
				return;

			BadRequest(length, orig_line);
			return;
			}

		if ( line != end_of_line )
			{
			BroString s((const u_char*)orig_line, length, true);
			Weird("ident_request_addendum", s.CheckString());
			}

		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new PortVal(local_port, TRANSPORT_TCP));
		vl->append(new PortVal(remote_port, TRANSPORT_TCP));

		ConnectionEvent(ident_request, vl);

		did_deliver = 1;
		}

	else
		{
		if ( ! ident_reply )
			return;

		line = ParsePair(line, end_of_line, remote_port, local_port);

		if ( ! line || line == end_of_line || line[0] != ':' )
			{
			if ( s && s->state == tcp::TCP_ENDPOINT_CLOSED &&
			     (s->prev_state == tcp::TCP_ENDPOINT_INACTIVE ||
			      s->prev_state == tcp::TCP_ENDPOINT_PARTIAL) )
				// not surprising the request is mangled.
				return;

			BadReply(length, orig_line);
			return;
			}

		line = skip_whitespace(line + 1, end_of_line);
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

		line = skip_whitespace(line, end_of_line);

		if ( line >= end_of_line || line[0] != ':' )
			{
			BadReply(length, orig_line);
			return;
			}

		line = skip_whitespace(line + 1, end_of_line);

		if ( is_error )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(new PortVal(local_port, TRANSPORT_TCP));
			vl->append(new PortVal(remote_port, TRANSPORT_TCP));
			vl->append(new StringVal(end_of_line - line, line));

			ConnectionEvent(ident_error, vl);
			}

		else
			{
			const char* sys_type = line;
			const char* colon = strchr_n(line, end_of_line, ':');
			const char* comma = strchr_n(line, end_of_line, ',');
			if ( ! colon )
				{
				BadReply(length, orig_line);
				return;
				}

			const char* sys_end = (comma && comma < colon) ?
						comma : colon;

			while ( --sys_end > sys_type && isspace(*sys_end) )
				;

			BroString* sys_type_s =
				new BroString((const u_char*) sys_type,
						sys_end - sys_type + 1, 1);

			line = skip_whitespace(colon + 1, end_of_line);

			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			vl->append(new PortVal(local_port, TRANSPORT_TCP));
			vl->append(new PortVal(remote_port, TRANSPORT_TCP));
			vl->append(new StringVal(end_of_line - line, line));
			vl->append(new StringVal(sys_type_s));

			ConnectionEvent(ident_reply, vl);
			}
		}
	}

const char* Ident_Analyzer::ParsePair(const char* line, const char* end_of_line, int & p1, int& p2)
	{
	line = ParsePort(line, end_of_line, p1);
	if ( ! line )
		{
		return 0;
		}

	if ( line >= end_of_line || line[0] != ',' )
		return 0;

	++line;

	line = ParsePort(line, end_of_line, p2);
	if ( ! line )
		return 0;

	return line;
	}

const char* Ident_Analyzer::ParsePort(const char* line, const char* end_of_line,
				int& pn)
	{
	int n = 0;

	line = skip_whitespace(line, end_of_line);
	if ( ! isdigit(*line) )
		return 0;

	const char* l = line;

	do
		{
		n = n * 10 + (*line - '0');
		++line;
		}
	while ( isdigit(*line) );

	line = skip_whitespace(line, end_of_line);

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
	BroString s((const u_char*)line, length, true);
	Weird("bad_ident_request", s.CheckString());
	}

void Ident_Analyzer::BadReply(int length, const char* line)
	{
	if ( ! did_bad_reply )
		{
		BroString s((const u_char*)line, length, true);
		Weird("bad_ident_reply", s.CheckString());
		did_bad_reply = 1;
		}
	}
