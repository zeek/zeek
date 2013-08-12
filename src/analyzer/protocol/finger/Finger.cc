// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <ctype.h>

#include "NetVar.h"
#include "Finger.h"
#include "Event.h"
#include "analyzer/protocol/tcp/ContentLine.h"

#include "events.bif.h"

using namespace analyzer::finger;

Finger_Analyzer::Finger_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("FINGER", conn)
	{
	did_deliver = 0;
	content_line_orig = new tcp::ContentLine_Analyzer(conn, true);
	content_line_orig->SetIsNULSensitive(true);
	content_line_resp = new tcp::ContentLine_Analyzer(conn, false);
	AddSupportAnalyzer(content_line_orig);
	AddSupportAnalyzer(content_line_resp);
	}

void Finger_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( TCP() )
		if ( (! did_deliver || content_line_orig->HasPartialLine()) &&
		     (TCP()->OrigState() == tcp::TCP_ENDPOINT_CLOSED ||
		      TCP()->OrigPrevState() == tcp::TCP_ENDPOINT_CLOSED) )
			// ### should include the partial text
			Weird("partial_finger_request");
	}

void Finger_Analyzer::DeliverStream(int length, const u_char* data, bool is_orig)
	{
	const char* line = (const char*) data;
	const char* end_of_line = line + length;

	if ( is_orig )
		{

		if ( ! finger_request )
			return;

		line = skip_whitespace(line, end_of_line);

		// Check for /W.
		int long_cnt = (line + 2 <= end_of_line && line[0] == '/' && toupper(line[1]) == 'W');
		if ( long_cnt )
			line = skip_whitespace(line+2, end_of_line);

		const char* at = strchr_n(line, end_of_line, '@');
		const char* host = 0;
		if ( ! at )
			at = host = end_of_line;
		else
			host = at + 1;

		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new Val(long_cnt, TYPE_BOOL));
		vl->append(new StringVal(at - line, line));
		vl->append(new StringVal(end_of_line - host, host));

		if ( finger_request )
			ConnectionEvent(finger_request, vl);

		Conn()->Match(Rule::FINGER, (const u_char *) line,
			  end_of_line - line, true, true, 1, true);

		did_deliver = 1;
		}

	else
		{
		if ( ! finger_reply )
			return;

		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new StringVal(end_of_line - line, line));

		ConnectionEvent(finger_reply, vl);
		}
	}
