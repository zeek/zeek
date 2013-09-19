// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <stdlib.h>

#include "NetVar.h"
#include "SMTP.h"
#include "Event.h"
#include "Reporter.h"
#include "analyzer/protocol/tcp/ContentLine.h"

#include "events.bif.h"

using namespace analyzer::smtp;

#undef SMTP_CMD_DEF
#define SMTP_CMD_DEF(cmd)	#cmd,

static const char* smtp_cmd_word[] = {
#include "SMTP_cmd.def"
};

#define SMTP_CMD_WORD(code) ((code >= 0) ? smtp_cmd_word[code] : "(UNKNOWN)")


SMTP_Analyzer::SMTP_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("SMTP", conn)
	{
	expect_sender = 0;
	expect_recver = 1;
	state = SMTP_CONNECTED;
	last_replied_cmd = -1;
	first_cmd = SMTP_CMD_CONN_ESTABLISHMENT;
	pending_reply = 0;

	// Some clients appear to assume pipelining is always enabled
	// and do not bother to check whether "PIPELINING" appears in
	// the server reply to EHLO.
	pipelining = 1;

	skip_data = 0;
	orig_is_sender = true;
	line_after_gap = 0;
	mail = 0;
	UpdateState(first_cmd, 0);
	tcp::ContentLine_Analyzer* cl_orig = new tcp::ContentLine_Analyzer(conn, true);
	cl_orig->SetIsNULSensitive(true);
	cl_orig->SetSkipPartial(true);
	AddSupportAnalyzer(cl_orig);

	tcp::ContentLine_Analyzer* cl_resp = new tcp::ContentLine_Analyzer(conn, false);
	cl_resp->SetIsNULSensitive(true);
	cl_resp->SetSkipPartial(true);
	AddSupportAnalyzer(cl_resp);
	}

void SMTP_Analyzer::ConnectionFinished(int half_finished)
	{
	tcp::TCP_ApplicationAnalyzer::ConnectionFinished(half_finished);

	if ( ! half_finished && mail )
		EndData();
	}

SMTP_Analyzer::~SMTP_Analyzer()
	{
	delete line_after_gap;
	}

void SMTP_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( mail )
		EndData();
	}

void SMTP_Analyzer::Undelivered(int seq, int len, bool is_orig)
	{
	tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, is_orig);

	if ( len <= 0 )
		return;

	const char* buf = fmt("seq = %d, len = %d", seq, len);
	int buf_len = strlen(buf);

	Unexpected(is_orig, "content gap", buf_len, buf);

	if ( state == SMTP_IN_DATA )
		{
		// Record the SMTP data gap and terminate the
		// ongoing mail transaction.
		if ( mail )
			mail->Undelivered(len);

		EndData();
		}

	if ( line_after_gap )
		{
		delete line_after_gap;
		line_after_gap = 0;
		}

	pending_cmd_q.clear();

	first_cmd = last_replied_cmd = -1;

	// Missing either the sender's packets or their replies
	// (e.g. code 354) is critical, so we set state to SMTP_AFTER_GAP
	// in both cases
	state = SMTP_AFTER_GAP;
	}

void SMTP_Analyzer::DeliverStream(int length, const u_char* line, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(length, line, orig);

	// NOTE: do not use IsOrig() here, because of TURN command.
	int is_sender = orig_is_sender ? orig : ! orig;

#if 0
	###
	if ( line[length] != '\r' || line[length+1] != '\n' )
		Unexpected(is_sender, "line does not end with <CR><LF>", length, line);
#endif

	// Some weird client uses '\r\r\n' for end-of-line sequence
	// So we make a compromise here to allow /(\r)*\n/ as end-of-line sequences
	if ( length > 0 && line[length-1] == '\r' )
		{
		Unexpected(is_sender, "more than one <CR> at the end of line", length, (const char*) line);
		do
			--length;
		while ( length > 0 && line[length-1] == '\r' );
		}

	for ( int i = 0; i < length; ++i )
		if ( line[i] == '\r' || line[i] == '\n' )
			{
			Unexpected(is_sender, "Bare <CR> or <LF> appears in the middle of line",
				   length, (const char*) line);
			break;
			}

	ProcessLine(length, (const char*) line, orig);
	}


void SMTP_Analyzer::ProcessLine(int length, const char* line, bool orig)
	{
	const char* end_of_line = line + length;
	if ( state == SMTP_IN_TLS )
		// Do not try to parse contents after STARTTLS/220.
		return;

	int cmd_len = 0;
	const char* cmd = "";

	// NOTE: do not use IsOrig() here, because of TURN command.
	int is_sender = orig_is_sender ? orig : ! orig;

	if ( ! pipelining &&
	     ((is_sender && ! expect_sender) ||
	      (! is_sender && ! expect_recver)) )
		Unexpected(is_sender, "out of order", length, line);

	if ( is_sender )
		{
		int cmd_code = -1;

		if ( state == SMTP_AFTER_GAP )
			{
			// Don't know whether it is a command line or
			// a data line.
			if ( line_after_gap )
				delete line_after_gap;

			line_after_gap =
				new BroString((const u_char *) line, length, 1);
			}

		else if ( state == SMTP_IN_DATA && line[0] == '.' && length == 1 )
			{
			cmd = ".";
			cmd_len = 1;
			cmd_code = SMTP_CMD_END_OF_DATA;
			NewCmd(cmd_code);

			expect_sender = 0;
			expect_recver = 1;
			}

		else if ( state == SMTP_IN_DATA )
			{
			// Check "." for end of data.
			expect_recver = 0; // ?? MAY server respond to mail data?

			if ( line[0] == '.' )
				++line;

			int data_len = end_of_line - line;

			if ( ! mail )
				// This can happen if we're already shut
				// down the connection due to seeing a RST
				// but are now processing packets sent
				// afterwards (because, e.g., the RST was
				// dropped or ignored).
				BeginData();

			ProcessData(data_len, line);

			if ( smtp_data && ! skip_data )
				{
				val_list* vl = new val_list;
				vl->append(BuildConnVal());
				vl->append(new Val(orig, TYPE_BOOL));
				vl->append(new StringVal(data_len, line));
				ConnectionEvent(smtp_data, vl);
				}
			}

		else if ( state == SMTP_IN_AUTH )
			{
			cmd = "***";
			cmd_len = 2;
			cmd_code = SMTP_CMD_AUTH_ANSWER;
			NewCmd(cmd_code);
			}

		else
			{
			expect_sender = 0;
			expect_recver = 1;

			get_word(length, line, cmd_len, cmd);
			line = skip_whitespace(line + cmd_len, end_of_line);
			cmd_code = ParseCmd(cmd_len, cmd);

			if ( cmd_code == -1 )
				{
				Unexpected(1, "unknown command", cmd_len, cmd);
				cmd = 0;
				}
			else
				NewCmd(cmd_code);
			}

		// Generate smtp_request event
		if ( cmd_code >= 0 )
			{
			// In order for all MIME events nested
			// between SMTP command DATA and END_OF_DATA,
			// we need to call UpdateState(), which in
			// turn calls BeginData() and EndData(),  and
			// RequestEvent() in different orders for the
			// two commands.
			if ( cmd_code == SMTP_CMD_END_OF_DATA )
				UpdateState(cmd_code, 0);

			if ( smtp_request )
				{
				int data_len = end_of_line - line;
				RequestEvent(cmd_len, cmd, data_len, line);
				}

			if ( cmd_code != SMTP_CMD_END_OF_DATA )
				UpdateState(cmd_code, 0);
			}
		}

	else
		{
		int reply_code;

		if ( length >= 3 &&
		     isdigit(line[0]) && isdigit(line[1]) && isdigit(line[2]) )
			{
			reply_code = (line[0] - '0') * 100 +
					(line[1] - '0') * 10 +
					(line[2] - '0');
			}
		else
			reply_code = -1;

		// The first digit of reply code must be between 1 and 5,
		// and the second between 0 and 5 (RFC 2821).  But sometimes
		// we see 5xx codes larger than 559, so we still tolerate that.
		if ( reply_code < 100 || reply_code > 599 )
			{
			reply_code = -1;
			Unexpected(is_sender, "reply code out of range", length, line);
			ProtocolViolation(fmt("reply code %d out of range",
						reply_code), line, length);
			}

		else
			{ // Valid reply code.
			if ( pending_reply && reply_code != pending_reply )
				{
				Unexpected(is_sender, "reply code does not match the continuing reply", length, line);
				pending_reply = 0;
				}

			if ( ! pending_reply && reply_code >= 0 )
				// It is not a continuation.
				NewReply(reply_code);

			// Update pending_reply.
			if ( reply_code >= 0 && length > 3 && line[3] == '-' )
				{ // A continued reply.
				pending_reply = reply_code;
				line = skip_whitespace(line+4, end_of_line);
				}

			else
				{ // This is the end of the reply.
				line = skip_whitespace(line+3, end_of_line);

				pending_reply = 0;
				expect_sender = 1;
				expect_recver = 0;
				}

			// Generate events.
			if ( smtp_reply && reply_code >= 0 )
				{
				const int cmd_code = last_replied_cmd;
				switch ( cmd_code ) {
					case SMTP_CMD_CONN_ESTABLISHMENT:
						cmd = ">";
						break;

					case SMTP_CMD_END_OF_DATA:
						cmd = ".";
						break;

					default:
						cmd = SMTP_CMD_WORD(cmd_code);
						break;
				}

				val_list* vl = new val_list;
				vl->append(BuildConnVal());
				vl->append(new Val(orig, TYPE_BOOL));
				vl->append(new Val(reply_code, TYPE_COUNT));
				vl->append(new StringVal(cmd));
				vl->append(new StringVal(end_of_line - line, line));
				vl->append(new Val((pending_reply > 0), TYPE_BOOL));

				ConnectionEvent(smtp_reply, vl);
				}
			}

		// Process SMTP extensions, e.g. PIPELINING.
		if ( last_replied_cmd == SMTP_CMD_EHLO && reply_code == 250 )
			{
			const char* ext;
			int ext_len;

			get_word(end_of_line - line, line, ext_len, ext);
			ProcessExtension(ext_len, ext);
			}
		}
	}

void SMTP_Analyzer::NewCmd(const int cmd_code)
	{
	if ( pipelining )
		{
		if ( first_cmd < 0 )
			first_cmd = cmd_code;
		else
			pending_cmd_q.push_back(cmd_code);
		}
	else
		first_cmd = cmd_code;
	}


// Here we keep a SMTP state machine and update it on each reply.
// However, the purpose is NOT to check correctness of SMTP commands
// and replies, but to guess the state of the SMTP session and,
// particularly, to know when we are in the SMTP_IN_DATA state.
//
// That is why state transition does not depend on the previous state,
// but only depend on the <command, reply> pair.
//
// Why not simply have two-state machine, IN_DATA/NOT_IN_DATA?  Because
// we want to understand the behavior of SMTP and check how far it may
// deviate from our knowledge.

void SMTP_Analyzer::NewReply(const int reply_code)
	{
	if ( state == SMTP_AFTER_GAP && reply_code > 0 )
		{
		state = SMTP_GAP_RECOVERY;
		const char* unknown_cmd = SMTP_CMD_WORD(-1);
		RequestEvent(strlen(unknown_cmd), unknown_cmd, 0, "");
		/*
		if ( line_after_gap )
			ProcessLine(sender, line_after_gap->Len(), (const char *) line_after_gap->Bytes());
		*/
		}

	// Make all parameters constants.
	const int cmd_code = first_cmd;

	// To recover from a gap, we detect replies -- the critical
	// assumptions here are 1) receiver does not reply during a DATA
	// session; 2) there is no TURN in the gap.

	last_replied_cmd = first_cmd;
	first_cmd = -1;

	if ( pipelining && pending_cmd_q.size() > 0 )
		{
		first_cmd = pending_cmd_q.front();
		pending_cmd_q.pop_front();
		}

	UpdateState(cmd_code, reply_code);
	}

// Note: reply_code == 0 means we haven't seen the reply, in which case we
// still update the state as if the command will succeed, and later
// adjust the state if it turns out otherwise. This is because some
// clients are really aggressive in pipelining (beyond the restrictions
// in the RPC), and as a result we have to update the state following
// the commands in addition to the replies.

void SMTP_Analyzer::UpdateState(const int cmd_code, const int reply_code)
	{
	const int st = state;

	if ( st == SMTP_QUIT && reply_code == 0 )
		UnexpectedCommand(cmd_code, reply_code);

	switch ( cmd_code ) {
	case SMTP_CMD_CONN_ESTABLISHMENT:
		switch ( reply_code ) {
		case 0:
			if ( st != SMTP_CONNECTED )
				{
				// Impossible state, because the command
				// CONN_ESTABLISHMENT should only appear
				// in the very beginning.
				UnexpectedCommand(cmd_code, reply_code);
				}
			state = SMTP_INITIATED;
			break;

		case 220:
			break;

		case 421:
		case 554:
			state = SMTP_NOT_AVAILABLE;
			break;

		default:
			UnexpectedReply(cmd_code, reply_code);
			break;
		}
		break;

	case SMTP_CMD_EHLO:
	case SMTP_CMD_HELO:
		switch ( reply_code ) {
			case 0:
				if ( st != SMTP_INITIATED )
					UnexpectedCommand(cmd_code, reply_code);
				state = SMTP_READY;
				break;

			case 250:
				break;

			case 421:
			case 500:
			case 501:
			case 504:
			case 550:
				state = SMTP_INITIATED;
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				break;
		}
		break;

	case SMTP_CMD_MAIL:
	case SMTP_CMD_SEND:
	case SMTP_CMD_SOML:
	case SMTP_CMD_SAML:
		switch ( reply_code ) {
			case 0:
				if ( st != SMTP_READY )
					UnexpectedCommand(cmd_code, reply_code);
				state = SMTP_MAIL_OK;
				break;

			case 250:
				break;

			case 421:
			case 451:
			case 452:
			case 500:
			case 501:
			case 503:
			case 550:
			case 552:
			case 553:
				if ( state != SMTP_IN_DATA )
					state = SMTP_READY;
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				break;
		}
		break;

	case SMTP_CMD_RCPT:
		switch ( reply_code ) {
			case 0:
				if ( st != SMTP_MAIL_OK && st != SMTP_RCPT_OK )
					UnexpectedCommand(cmd_code, reply_code);
				state = SMTP_RCPT_OK;
				break;

			case 250:
			case 251: // ?? Shall we catch 251? (RFC 2821)
				break;

			case 421:
			case 450:
			case 451:
			case 452:
			case 500:
			case 501:
			case 503:
			case 550:
			case 551: // ?? Shall we catch 551?
			case 552:
			case 553:
			case 554: // = transaction failed/recipient refused
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				break;
		}
		break;

	case SMTP_CMD_DATA:
		switch ( reply_code ) {
			case 0:
				if ( state != SMTP_RCPT_OK )
					UnexpectedCommand(cmd_code, reply_code);
				BeginData();
				break;

			case 354:
				break;

			case 421:
				if ( state == SMTP_IN_DATA )
					EndData();
				state = SMTP_QUIT;
				break;

			case 500:
			case 501:
			case 503:
			case 451:
			case 554:
				if ( state == SMTP_IN_DATA )
					EndData();
				state = SMTP_READY;
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				if ( state == SMTP_IN_DATA )
					EndData();
				state = SMTP_READY;
				break;
		}
		break;

	case SMTP_CMD_END_OF_DATA:
		switch ( reply_code ) {
			case 0:
				if ( st != SMTP_IN_DATA )
					UnexpectedCommand(cmd_code, reply_code);
				EndData();
				state = SMTP_AFTER_DATA;
				break;

			case 250:
				break;

			case 421:
			case 451:
			case 452:
			case 552:
			case 554:
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				break;
		}

		if ( reply_code > 0 )
			state = SMTP_READY;
		break;

	case SMTP_CMD_RSET:
		switch ( reply_code ) {
			case 0:
				state = SMTP_READY;
				break;

			case 250:
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				break;
		}

		break;

	case SMTP_CMD_QUIT:
		switch ( reply_code ) {
			case 0:
				state = SMTP_QUIT;
				break;

			case 221:
				break;

			default:
				UnexpectedReply(cmd_code, reply_code);
				break;
		}

		break;

	case SMTP_CMD_AUTH:
		if ( st != SMTP_READY )
			UnexpectedCommand(cmd_code, reply_code);

		switch ( reply_code ) {
			case 0:
				// Here we wait till there's a reply.
				break;

			case 334:
				state = SMTP_IN_AUTH;
				break;

			case 235:
				state = SMTP_INITIATED;
				break;

			case 432:
			case 454:
			case 501:
			case 503:
			case 504:
			case 534:
			case 535:
			case 538:
			default:
				state = SMTP_INITIATED;
				break;
		}
		break;

	case SMTP_CMD_AUTH_ANSWER:
		if ( st != SMTP_IN_AUTH )
			UnexpectedCommand(cmd_code, reply_code);

		switch ( reply_code ) {
			case 0:
				// Here we wait till there's a reply.
				break;

			case 334:
				state = SMTP_IN_AUTH;
				break;

			case 235:
			case 535:
			default:
				state = SMTP_INITIATED;
				break;
		}
		break;

	case SMTP_CMD_TURN:
		if ( st != SMTP_READY )
			UnexpectedCommand(cmd_code, reply_code);

		switch ( reply_code ) {
			case 0:
				// Here we wait till there's a reply.
				break;

			case 250:
				// flip-side
				orig_is_sender = ! orig_is_sender;

				state = SMTP_CONNECTED;
				expect_sender = 0;
				expect_recver = 1;
				break;

			case 502:
			default:
				break;
		}
		break;

	case SMTP_CMD_STARTTLS:
		if ( st != SMTP_READY )
			UnexpectedCommand(cmd_code, reply_code);

		switch ( reply_code ) {
			case 0:
				// Here we wait till there's a reply.
				break;

			case 220:
				state = SMTP_IN_TLS;
				expect_sender = expect_recver = 1;
				break;

			case 454:
			case 501:
			default:
				break;
		}
		break;

	case SMTP_CMD_VRFY:
	case SMTP_CMD_EXPN:
	case SMTP_CMD_HELP:
	case SMTP_CMD_NOOP:
		// These commands do not affect state.
		// ?? However, later we may want to add reply
		// and state check code.

	default:
		if ( st == SMTP_GAP_RECOVERY && reply_code == 354 )
			{
			BeginData();
			}
		break;
	}

	// A hack: whenever the server makes a valid reply during a DATA
	// section, we assume that the DATA section has ended (the end
	// of data line might have been lost due to gaps in trace).  Note,
	// BeginData() won't be called till the next DATA command.
#if 0
	if ( state == SMTP_IN_DATA && reply_code >= 400 )
		{
		EndData();
		state = SMTP_READY;
		}
#endif
	}

void SMTP_Analyzer::ProcessExtension(int ext_len, const char* ext)
	{
	if ( ! ext )
		return;

	if ( ! strcasecmp_n(ext_len, ext, "PIPELINING") )
		pipelining = 1;
	}

int SMTP_Analyzer::ParseCmd(int cmd_len, const char* cmd)
	{
	if ( ! cmd )
		return -1;

	for ( int code = SMTP_CMD_EHLO; code < SMTP_CMD_LAST; ++code )
		if ( ! strcasecmp_n(cmd_len, cmd, smtp_cmd_word[code - SMTP_CMD_EHLO]) )
			return code;

	return -1;
	}

void SMTP_Analyzer::RequestEvent(int cmd_len, const char* cmd,
				int arg_len, const char* arg)
	{
	ProtocolConfirmation();
	val_list* vl = new val_list;

	vl->append(BuildConnVal());
	vl->append(new Val(orig_is_sender, TYPE_BOOL));
	vl->append((new StringVal(cmd_len, cmd))->ToUpper());
	vl->append(new StringVal(arg_len, arg));

	ConnectionEvent(smtp_request, vl);
	}

void SMTP_Analyzer::Unexpected(const int is_sender, const char* msg,
				int detail_len, const char* detail)
	{
	// Either party can send a line after an unexpected line.
	expect_sender = expect_recver = 1;

	if ( smtp_unexpected )
		{
		val_list* vl = new val_list;
		int is_orig = is_sender;
		if ( ! orig_is_sender )
			is_orig = ! is_orig;

		vl->append(BuildConnVal());
		vl->append(new Val(is_orig, TYPE_BOOL));
		vl->append(new StringVal(msg));
		vl->append(new StringVal(detail_len, detail));

		ConnectionEvent(smtp_unexpected, vl);
		}
	}

void SMTP_Analyzer::UnexpectedCommand(const int cmd_code, const int reply_code)
	{
	// If this happens, please fix the SMTP state machine!
	// ### Eventually, these should be turned into "weird" events.
	static char buf[512];
	int len = safe_snprintf(buf, sizeof(buf),
				"%s reply = %d state = %d",
				SMTP_CMD_WORD(cmd_code), reply_code, state);
	if ( len > (int) sizeof(buf) )
		len = sizeof(buf);
	Unexpected (1, "unexpected command", len, buf);
	}

void SMTP_Analyzer::UnexpectedReply(const int cmd_code, const int reply_code)
	{
	// If this happens, please fix the SMTP state machine!
	// ### Eventually, these should be turned into "weird" events.
	static char buf[512];
	int len = safe_snprintf(buf, sizeof(buf),
				"%d state = %d, last command = %s",
				reply_code, state, SMTP_CMD_WORD(cmd_code));
	Unexpected (1, "unexpected reply", len, buf);
	}

void SMTP_Analyzer::ProcessData(int length, const char* line)
	{
	mail->Deliver(length, line, 1 /* trailing_CRLF */);
	}

void SMTP_Analyzer::BeginData()
	{
	state = SMTP_IN_DATA;
	skip_data = 0; // reset the flag at the beginning of the mail
	if ( mail != 0 )
		{
		reporter->Warning("nested mail transaction");
		mail->Done();
		delete mail;
		}

	mail = new mime::MIME_Mail(this);
	}

void SMTP_Analyzer::EndData()
	{
	if ( ! mail )
		reporter->Warning("Unmatched end of data");
	else
		{
		mail->Done();
		delete mail;
		mail = 0;
		}
	}
