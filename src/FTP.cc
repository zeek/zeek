// $Id: FTP.cc 6782 2009-06-28 02:19:03Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>

#include "NetVar.h"
#include "FTP.h"
#include "NVT.h"
#include "Event.h"
#include "TCP_Rewriter.h"

FTP_Analyzer::FTP_Analyzer(Connection* conn)
: TCP_ApplicationAnalyzer(AnalyzerTag::FTP, conn)
	{
	pending_reply = 0;

	nvt_orig = new NVT_Analyzer(conn, true);
	nvt_orig->SetIsNULSensitive(true);
	nvt_orig->SetIsNULSensitive(true);
	nvt_orig->SetCRLFAsEOL(LF_as_EOL);
	nvt_orig->SetIsNULSensitive(LF_as_EOL);

	nvt_resp = new NVT_Analyzer(conn, false);
	nvt_resp->SetIsNULSensitive(true);
	nvt_resp->SetIsNULSensitive(true);
	nvt_resp->SetCRLFAsEOL(LF_as_EOL);
	nvt_resp->SetIsNULSensitive(LF_as_EOL);

	nvt_resp->SetPeer(nvt_orig);
	nvt_orig->SetPeer(nvt_resp);

	AddSupportAnalyzer(nvt_orig);
	AddSupportAnalyzer(nvt_resp);
	}

void FTP_Analyzer::Done()
	{
	TCP_ApplicationAnalyzer::Done();

	if ( nvt_orig->HasPartialLine() &&
	     (TCP()->OrigState() == TCP_ENDPOINT_CLOSED ||
	      TCP()->OrigPrevState() == TCP_ENDPOINT_CLOSED) )
		// ### should include the partial text
		Weird("partial_ftp_request");
	}

void FTP_Analyzer::DeliverStream(int length, const u_char* data, bool orig)
	{
	TCP_ApplicationAnalyzer::DeliverStream(length, data, orig);

	if ( (orig && ! ftp_request) || (! orig && ! ftp_reply) )
		return;

	// const char* orig_line = line;
	const char* line = (const char*) data;
	const char* end_of_line = line + length;

	val_list* vl = new val_list;
	vl->append(BuildConnVal());

	EventHandlerPtr f;
	if ( orig )
		{
		int cmd_len;
		const char* cmd;
		StringVal* cmd_str;

		line = skip_whitespace(line, end_of_line);
		get_word(length, line, cmd_len, cmd);
		line = skip_whitespace(line + cmd_len, end_of_line);

		if ( cmd_len == 0 )
			{
			// Weird("FTP command missing", end_of_line - orig_line, orig_line);
			cmd_str = new StringVal("<missing>");
			}
		else
			cmd_str = (new StringVal(cmd_len, cmd))->ToUpper();

		vl->append(cmd_str);
		vl->append(new StringVal(end_of_line - line, line));

		f = ftp_request;
		ProtocolConfirmation();

		if ( strncmp((const char*) cmd_str->Bytes(),
			     "AUTH", cmd_len) == 0 )
			auth_requested = string(line, end_of_line - line);

		if ( rule_matcher )
			Conn()->Match(Rule::FTP, (const u_char *) cmd,
				end_of_line - cmd, true, true, 1, true);
		}
	else
		{
		uint32 reply_code;
		if ( length >= 3 &&
		     isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2]) )
			{
			reply_code = (line[0] - '0') * 100 +
					(line[1] - '0') * 10 +
					(line[2] - '0');
			}
		else
			reply_code = 0;

		int cont_resp;

		if ( pending_reply )
			{
			if ( reply_code == pending_reply &&
			     length > 3 && line[3] == ' ' )
				{
				// This is the end of the reply.
				line = skip_whitespace(line + 3, end_of_line);
				pending_reply = 0;
				cont_resp = 0;
				}
			else
				{
				cont_resp = 1;	// not the end
				reply_code = 0;	// flag as intermediary
				}
			}
		else
			{ // a new reply
			if ( reply_code > 0 && length > 3 && line[3] == '-' )
				{ // a continued reply
				pending_reply = reply_code;
				line = skip_whitespace(line + 4, end_of_line);
				cont_resp = 1;
				}
			else
				{ // a self-contained reply
				if ( reply_code > 0 )
					line += 3;
				else
					ProtocolViolation("non-numeric reply code",
						(const char*) data, length);

				if ( line < end_of_line )
					line = skip_whitespace(line, end_of_line);
				else
					line = end_of_line;

				if ( auth_requested.size() > 0 &&
				     (reply_code == 234 || reply_code == 335) )
					// Server accepted AUTH requested,
					// which means that very likely we
					// won't be able to parse the rest
					// of the session, and thus we stop
					// here.
					SetSkip(true);

				cont_resp = 0;
				}
			}

		vl->append(new Val(reply_code, TYPE_COUNT));
		vl->append(new StringVal(end_of_line - line, line));
		vl->append(new Val(cont_resp, TYPE_BOOL));

		f = ftp_reply;
		}

	ConnectionEvent(f, vl);
	}


#include "ftp-rw.bif.func_def"
