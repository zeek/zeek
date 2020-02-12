// This code contributed to Bro by Florian Schimandl, Hugh Dollman and
// Robin Sommer.

#include "zeek-config.h"
#include "POP3.h"

#include <vector>
#include <string>
#include <ctype.h>

#include "Base64.h"
#include "Reporter.h"
#include "analyzer/Manager.h"

#include "events.bif.h"

using namespace analyzer::pop3;

#undef POP3_CMD_DEF
#define POP3_CMD_DEF(cmd)	#cmd,

static const char* pop3_cmd_word[] = {
#include "POP3_cmd.def"
};

#define POP3_CMD_WORD(code) ((code >= 0) ? pop3_cmd_word[code] : "(UNKNOWN)")


POP3_Analyzer::POP3_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("POP3", conn)
	{
	masterState = POP3_START;
	subState = POP3_WOK;
	state = START;
	lastState = START;

	guessing = false;
	waitingForAuthentication = false;
	requestForMultiLine = false;
	multiLine = false;
	tls = false;

	lastRequiredCommand = 0;
	authLines = 0;

	mail = 0;

	cl_orig = new tcp::ContentLine_Analyzer(conn, true);
	AddSupportAnalyzer(cl_orig);

	cl_resp = new tcp::ContentLine_Analyzer(conn, false);
	AddSupportAnalyzer(cl_resp);
	}

POP3_Analyzer::~POP3_Analyzer()
	{
	}

void POP3_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( mail )
		EndData();
	}


void POP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( tls )
		{
		ForwardStream(len, data, orig);
		return;
		}

	if ( (TCP() && TCP()->IsPartial()) )
		return;

	BroString terminated_string(data, len, 1);

	if ( orig )
		ProcessRequest(len, (char*) terminated_string.Bytes());
	else
		ProcessReply(len, (char*) terminated_string.Bytes());
	}

static string trim_whitespace(const char* in)
	{
	int n = strlen(in);
	char* out = new char[n + 1];
	char* out_p = out;

	in = skip_whitespace(in);

	while ( *in )
		{
		// It might be better to use isspace() here, but the
		// original code just compared with ' '.
		if ( *in == ' ' )
			{
			// See if there is any following character.
			++in;
			while ( *in && *in == ' ' )
				++in;

			if ( ! *in )
				break;

			// There's a following character, so put in a
			// single blank to represent the ones we
			// compressed out.
			*(out_p++) = ' ';
			}

		// If we get this far, then we have a non-blank
		// character to copy.
		*(out_p++) = *(in++);
		}

	*out_p = 0;

	string rval(out);
	delete [] out;
	return rval;
	}

void POP3_Analyzer::ProcessRequest(int length, const char* line)
	{
	if ( length == 0 )
		return;

	if ( waitingForAuthentication )
		{
		++authLines;

		BroString encoded(line);
		BroString* decoded = decode_base64(&encoded, 0, Conn());

		if ( ! decoded )
			{
			Weird("pop3_bad_base64_encoding");
			return;
			}

		switch ( state ) {
		case AUTH_LOGIN:
			// Format: Line 1 - User
			//         Line 2 - Password
			if ( authLines == 1 )
				user = decoded->CheckString();

			else if ( authLines == 2 )
				password = decoded->CheckString();

			break;

		case AUTH_PLAIN:
			{
			// Format: "authorization identity<NUL>authentication
			//		identity<NUL>password"
			char* str = (char*) decoded->Bytes();
			int len = decoded->Len();
			char* end = str + len;
			char* s;
			char* e;

			for ( s = str; s < end && *s; ++s )
				;
			++s;

			for ( e = s; e < end && *e; ++e )
				;

			if ( e >= end )
				{
				Weird("pop3_malformed_auth_plain");
				delete decoded;
				return;
				}

			user = s;
			s = e + 1;

			if ( s >= end )
				{
				Weird("pop3_malformed_auth_plain");
				delete decoded;
				return;
				}

			char tmp[len];	// more than enough
			int n = len - (s - str);
			memcpy(tmp, s, n);
			tmp[n] = '\0';
			password = tmp;

			break;
			}

		case AUTH_CRAM_MD5:
			{ // Format: "user<space>password-hash"
			const char* s;
			const char* str = (char*) decoded->CheckString();

			for ( s = str; *s && *s != '\t' && *s != ' '; ++s )
				;

			user = std::string(str, s);
			password = "";

			break;
			}

		case AUTH:
			break;

		default:
			reporter->AnalyzerError(this,
			  "unexpected POP3 authorization state");
			delete decoded;
			return;
		}

		delete decoded;
		}

	else
		{
		// Some clients pipeline their commands (i.e., keep sending
		// without waiting for a server's responses). Therefore we
		// keep a list of pending commands.
		cmds.push_back(string(line));

		if ( cmds.size() == 1 )
			// Not waiting for another server response,
			// so we can process it immediately.
			ProcessClientCmd();
		}

	}

static string commands[] = {
	"OK", "ERR", "USER", "PASS", "APOP", "AUTH",
	"STAT", "LIST", "RETR", "DELE", "RSET", "NOOP", "LAST", "QUIT",
	"TOP", "CAPA", "UIDL", "STLS", "XSENDER",
};

void POP3_Analyzer::NotAllowed(const char* cmd, const char* state)
	{
	POP3Event(pop3_unexpected, true, cmd,
		fmt("not allowed in other state than '%s'", state));
	}

void POP3_Analyzer::ProcessClientCmd()
	{
	if ( ! cmds.size() )
		return;

	string str = trim_whitespace(cmds.front().c_str());
	vector<string> tokens = TokenizeLine(str, ' ');

	int cmd_code = -1;
	const char* cmd = "";

	if ( tokens.size() > 0 )
		cmd_code = ParseCmd(tokens[0]);

	if ( cmd_code == -1 )
		{
		if ( ! waitingForAuthentication )
			{
			Weird("pop3_client_command_unknown");
			if ( subState == POP3_WOK )
				subState = POP3_OK;
			}
		return;
		}

	cmd = commands[cmd_code].c_str();

	const char* message = tokens.size() > 1 ? tokens[1].c_str() : "";

	switch ( cmd_code ) {
	case POP3_CMD_ERR:
	case POP3_CMD_OK:
		Weird("pop3_client_sending_server_commands");
		break;

	case POP3_CMD_USER:
		if ( masterState == POP3_AUTHORIZATION )
			{
			POP3Event(pop3_request, true, cmd, message);
			state = USER;
			subState = POP3_WOK;
			user = message;
			}
		else
			NotAllowed(cmd, "authorization");
		break;

	case POP3_CMD_PASS:
		if ( masterState == POP3_AUTHORIZATION )
			{
			if ( state == USER )
				{
				POP3Event(pop3_request, true, cmd, message);
				state = PASS;
				subState = POP3_WOK;
				password = message;
				}
			else
				POP3Event(pop3_unexpected, true, cmd,
					"pass must follow the command 'USER'");
			}
		else
			NotAllowed(cmd, "authorization");
		break;

	case POP3_CMD_APOP:
		if ( masterState == POP3_AUTHORIZATION )
			{
			POP3Event(pop3_request, true, cmd, message);
			state = APOP;
			subState = POP3_WOK;

			char* arg1 = copy_string(message);
			char* e;
			for ( e = arg1; *e && *e != ' ' && *e != '\t'; ++e )
				;
			*e = '\0';
			user = arg1;
			delete [] arg1;
			}
		else
			NotAllowed(cmd, "authorization");
		break;

	case POP3_CMD_AUTH:
		if ( masterState == POP3_AUTHORIZATION )
			{
			POP3Event(pop3_request, true, cmd, message);
			if ( ! *message )
				{
				requestForMultiLine = true;
				state = AUTH;
				subState = POP3_WOK;
				}
			else
				{
				if ( strstr(message, "LOGIN") )
					state = AUTH_LOGIN;
				else if ( strstr(message, "PLAIN") )
					state = AUTH_PLAIN;
				else if ( strstr(message, "CRAM-MD5") )
					state = AUTH_CRAM_MD5;
				else
					{
					state = AUTH;
					POP3Event(pop3_unexpected, true, cmd,
						fmt("unknown AUTH method %s", message));
					}

				subState = POP3_WOK;
				waitingForAuthentication = true;
				authLines = 0;
				}
			}
		else
			POP3Event(pop3_unexpected, true, cmd,
				"pass must follow the command 'USER'");
		break;

	case POP3_CMD_STAT:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = STAT;
			}
		else
			NotAllowed(cmd, "transaction");
		break;

	case POP3_CMD_LIST:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			if ( ! *message )
				{
				requestForMultiLine = true;
				state = LIST;
				subState = POP3_WOK;
				}
			else
				{
				state = LIST;
				subState = POP3_WOK;
				}
			}
		else
			{
			if ( ! *message )
				requestForMultiLine = true;

			guessing = true;
			lastState = LIST;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_RETR:
		requestForMultiLine = true;
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = RETR;
			}
		else
			{
			guessing = true;
			lastState = RETR;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_DELE:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = DELE;
			}
		else
			{
			guessing = true;
			lastState = DELE;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_RSET:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = RSET;
			}
		else
			{
			guessing = true;
			lastState = RSET;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_NOOP:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = NOOP;
			}
		else
			{
			guessing = true;
			lastState = NOOP;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_LAST:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = LAST;
			}
		else
			{
			guessing = true;
			lastState = LAST;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_QUIT:
		if ( masterState == POP3_AUTHORIZATION ||
		     masterState == POP3_TRANSACTION ||
		     masterState == POP3_START )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = QUIT;
			}
		else
			{
			guessing = true;
			lastState = LAST;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_TOP:
		requestForMultiLine = true;

		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = TOP;
			}
		else
			{
			guessing = true;
			lastState = TOP;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_CAPA:
		POP3Event(pop3_request, true, cmd, message);
		subState = POP3_WOK;
		state = CAPA;
		requestForMultiLine = true;
		break;

	case POP3_CMD_STLS:
		POP3Event(pop3_request, true, cmd, message);
		subState = POP3_WOK;
		state = STLS;
		break;

	case POP3_CMD_UIDL:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			if ( ! *message )
				{
				requestForMultiLine = true;
				state = UIDL;
				subState = POP3_WOK;
				}
			else
				{
				state = UIDL;
				subState = POP3_WOK;
				}
			}
		else
			{
			if ( ! *message )
				requestForMultiLine = true;

			guessing = true;
			lastState = UIDL;
			NotAllowed(cmd, "transaction");
			}
		break;

	case POP3_CMD_XSENDER:
		if ( masterState == POP3_TRANSACTION )
			{
			POP3Event(pop3_request, true, cmd, message);
			subState = POP3_WOK;
			state = LAST;
			}
		else
			{
			guessing = true;
			lastState = XSENDER;
			NotAllowed(cmd, "transaction");
			}
		break;

	default:
		reporter->AnalyzerError(this, "unknown POP3 command");
		return;
	}
	}

void POP3_Analyzer::FinishClientCmd()
	{
	if ( ! cmds.size() )
		return;

	cmds.pop_front();
	ProcessClientCmd();
	}

void POP3_Analyzer::ProcessReply(int length, const char* line)
	{
	const char* end_of_line = line + length;
	string str = trim_whitespace(line);

	if ( multiLine == true )
		{
		bool terminator =
			line[0] == '.' &&
			(length == 1 ||
			 (length > 1 &&
			  (line[1] == '\n' ||
			  (length > 2 && line[1] == '\r' && line[2] == '\n'))));

		if ( terminator )
			{
			requestForMultiLine = false;
			multiLine = false;
			if ( mail )
				EndData();
			FinishClientCmd();
			}
		else
			{
			if ( state == RETR || state == TOP )
				{
				int data_len = end_of_line - line;
				ProcessData(data_len, line);
				}

			// ### It can be quite costly doing this per-line
			// as opposed to amortized over large packets that
			// contain many lines.
			POP3Event(pop3_data, false, str.c_str());
			}
		return;
		}

	int cmd_code = -1;
	const char* cmd = "";

	vector<string> tokens = TokenizeLine(str, ' ');
	if ( tokens.size() > 0 )
		cmd_code = ParseCmd(tokens[0]);

	if ( cmd_code == -1 )
		{
		if ( ! waitingForAuthentication )
			{
			ProtocolViolation(fmt("unknown server command (%s)",
						(tokens.size() > 0 ?
							tokens[0].c_str() :
							"???")),
						line, length);

			Weird("pop3_server_command_unknown");
			if ( subState == POP3_WOK )
				subState = POP3_OK;
			}
		return;
		}

	cmd = commands[cmd_code].c_str();

	const char* message = tokens.size() > 1 ? tokens[1].c_str() : "";

	switch ( cmd_code ) {
	case POP3_CMD_OK:
		if ( subState == POP3_WOK )
			subState = POP3_OK;

		if ( guessing )
			{
			masterState = POP3_TRANSACTION;
			guessing = false;
			state = lastState;
			POP3Event(pop3_unexpected, false, cmd,
				"no auth required -> state changed to 'transaction'");
			}

		switch ( state ) {
		case START:
			masterState = POP3_AUTHORIZATION;
			break;

		case USER:
			state = USER;
			masterState = POP3_AUTHORIZATION;
			ProtocolConfirmation();
			break;

		case PASS:
		case APOP:
		case NOOP:
		case LAST:
		case STAT:
		case RSET:
		case DELE:
		case XSENDER:
			if ( masterState == POP3_AUTHORIZATION )
				AuthSuccessfull();
			masterState = POP3_TRANSACTION;
			break;

		case AUTH:
		case AUTH_PLAIN:
		case AUTH_CRAM_MD5:
		case AUTH_LOGIN:
			if ( requestForMultiLine == true )
				multiLine = true;
			if ( waitingForAuthentication )
				masterState = POP3_TRANSACTION;
			waitingForAuthentication = false;
			AuthSuccessfull();
			break;

		case TOP:
		case RETR:
			{
			int data_len = end_of_line - line;
			if ( ! mail )
				// ProcessReply is only called if orig == false
				BeginData(false);
			ProcessData(data_len, line);
			if ( requestForMultiLine == true )
				multiLine = true;
			break;
			}

		case CAPA:
			ProtocolConfirmation();
			// Fall-through.

		case UIDL:
		case LIST:
			if (requestForMultiLine == true)
				multiLine = true;
			break;

		case STLS:
			ProtocolConfirmation();
			tls = true;
			StartTLS();
			return;

		case QUIT:
			if ( masterState == POP3_AUTHORIZATION ||
			     masterState == POP3_START )
				masterState = POP3_FINISHED;

			else if ( masterState == POP3_TRANSACTION )
				masterState = POP3_UPDATE;

			break;
		}

		POP3Event(pop3_reply, false, cmd, message);
		// no else part, ignoring multiple OKs

		if ( ! multiLine )
			FinishClientCmd();
		break;

	case POP3_CMD_ERR:
		if ( subState == POP3_WOK )
			subState = POP3_OK;

		multiLine = false;
		requestForMultiLine = false;
		guessing = false;
		waitingForAuthentication = false;

		switch ( state ) {
		case START:
			break;

		case USER:
		case PASS:
		case APOP:
		case AUTH:
		case AUTH_LOGIN:
		case AUTH_PLAIN:
		case AUTH_CRAM_MD5:
			masterState = POP3_AUTHORIZATION;
			state = START;
			waitingForAuthentication = false;

			if ( user.size() )
				POP3Event(pop3_login_failure, false,
					user.c_str(), password.c_str());
			break;

		case NOOP:
		case LAST:
		case STAT:
		case RSET:
		case DELE:
		case LIST:
		case RETR:
		case UIDL:
		case TOP:
		case XSENDER:
			masterState = POP3_TRANSACTION;
			break;

		case CAPA:
			break;

		case QUIT:
			if ( masterState == POP3_AUTHORIZATION ||
			     masterState == POP3_TRANSACTION ||
			     masterState == POP3_START )
				masterState = POP3_FINISHED;
			break;
		}

		POP3Event(pop3_reply, false, cmd, message);

		if ( ! multiLine )
			FinishClientCmd();
		break;

	default:
		Weird("pop3_server_sending_client_commands");
		break;
	}
	}

void POP3_Analyzer::StartTLS()
	{
	// STARTTLS was succesful. Remove support analyzers, add SSL
	// analyzer, and throw event signifying the change.
	RemoveSupportAnalyzer(cl_orig);
	RemoveSupportAnalyzer(cl_resp);

	Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
	if ( ssl )
		AddChildAnalyzer(ssl);

	if ( pop3_starttls )
		ConnectionEventFast(pop3_starttls, {BuildConnVal()});
	}

void POP3_Analyzer::AuthSuccessfull()
	{
	if ( user.size() )
		POP3Event(pop3_login_success, false,
				user.c_str(), password.c_str());
	}

void POP3_Analyzer::BeginData(bool orig)
	{
	delete mail;
	mail = new mime::MIME_Mail(this, orig);
	}

void POP3_Analyzer::EndData()
	{
	if ( ! mail )
		reporter->Warning("unmatched end of data");
	else
		{
		mail->Done();
		delete mail;
		mail = 0;
		}
	}

void POP3_Analyzer::ProcessData(int length, const char* line)
	{
	mail->Deliver(length, line, 1);
	}

int POP3_Analyzer::ParseCmd(string cmd)
	{
	if ( cmd.size() == 0 )
		return -1;

	for ( int code = POP3_CMD_OK; code <= POP3_CMD_END; ++code )
		{
		char c = cmd.c_str()[0];
		if ( c == '+' || c == '-' )
			cmd = cmd.substr(1);

		for ( unsigned int i = 0; i < cmd.size(); ++i )
			cmd[i] = toupper(cmd[i]);

		if ( ! cmd.compare(pop3_cmd_word[code]) )
			return code;
		}

	return -1;
	}

vector<string> POP3_Analyzer::TokenizeLine(const string& input, char split)
	{
	vector<string> tokens;

	if ( input.size() < 1 )
		return tokens;

	int start = 0;
	unsigned int splitPos = 0;
	string token = "";

	if ( input.find(split, 0) == string::npos )
		{
		tokens.push_back(input);
		return tokens;
		}

	if ( (splitPos = input.find(split, 0)) < input.size() )
		{
		token = input.substr(start, splitPos);
		if ( token.size() > 0 && token[0] != split )
			tokens.push_back(token);

		token = input.substr(splitPos+1, input.size() - splitPos);
		tokens.push_back(token);
		}

	return tokens;
	}

void POP3_Analyzer::POP3Event(EventHandlerPtr event, bool is_orig,
				const char* arg1, const char* arg2)
	{
	if ( ! event )
		return;

	val_list vl(2 + (bool)arg1 + (bool)arg2);

	vl.push_back(BuildConnVal());
	vl.push_back(val_mgr->GetBool(is_orig));
	if ( arg1 )
		vl.push_back(new StringVal(arg1));
	if ( arg2 )
		vl.push_back(new StringVal(arg2));

	ConnectionEventFast(event, std::move(vl));
	}
