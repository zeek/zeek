// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/finger/Finger.h"

#include "zeek/zeek-config.h"

#include <cctype>

#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/finger/events.bif.h"
#include "zeek/analyzer/protocol/tcp/ContentLine.h"

namespace zeek::analyzer::finger
	{

Finger_Analyzer::Finger_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("FINGER", conn)
	{
	did_deliver = 0;
	content_line_orig = new analyzer::tcp::ContentLine_Analyzer(conn, true, 1000);
	content_line_orig->SetIsNULSensitive(true);
	content_line_resp = new analyzer::tcp::ContentLine_Analyzer(conn, false, 1000);
	AddSupportAnalyzer(content_line_orig);
	AddSupportAnalyzer(content_line_resp);
	}

void Finger_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	if ( TCP() )
		if ( (! did_deliver || content_line_orig->HasPartialLine()) &&
		     (TCP()->OrigState() == analyzer::tcp::TCP_ENDPOINT_CLOSED ||
		      TCP()->OrigPrevState() == analyzer::tcp::TCP_ENDPOINT_CLOSED) )
			// ### should include the partial text
			Weird("partial_finger_request");
	}

void Finger_Analyzer::DeliverStream(int length, const u_char* data, bool is_orig)
	{
	const char* line = (const char*)data;
	const char* end_of_line = line + length;

	if ( length == 0 )
		return;

	if ( is_orig )
		{

		if ( ! finger_request )
			return;

		line = util::skip_whitespace(line, end_of_line);

		// Check for /W.
		int long_cnt = (line + 2 <= end_of_line && line[0] == '/' && toupper(line[1]) == 'W');
		if ( long_cnt )
			line = util::skip_whitespace(line + 2, end_of_line);

		assert(line <= end_of_line);
		size_t n = end_of_line >= line ? end_of_line - line
		                               : 0; // just to be sure if assertions aren't on.
		const char* at = reinterpret_cast<const char*>(memchr(line, '@', n));
		const char* host = nullptr;
		if ( ! at )
			at = host = end_of_line;
		else
			host = at + 1;

		if ( finger_request )
			EnqueueConnEvent(finger_request, ConnVal(), val_mgr->Bool(long_cnt),
			                 make_intrusive<StringVal>(at - line, line),
			                 make_intrusive<StringVal>(end_of_line - host, host));

		Conn()->Match(zeek::detail::Rule::FINGER, (const u_char*)line, end_of_line - line, true,
		              true, true, true);

		did_deliver = 1;
		}

	else
		{
		if ( ! finger_reply )
			return;

		EnqueueConnEvent(finger_reply, ConnVal(),
		                 make_intrusive<StringVal>(end_of_line - line, line));
		}
	}

	} // namespace zeek::analyzer::finger
