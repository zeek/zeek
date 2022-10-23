// This code contributed to Zeek/Bro by Florian Schimandl, Hugh Dollman and
// Robin Sommer.

#include "zeek/analyzer/protocol/pop3/POP3.h"

#include "zeek/zeek-config.h"

#include <cctype>
#include <string>
#include <vector>

#include "zeek/Base64.h"
#include "zeek/Reporter.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pop3/events.bif.h"

namespace zeek::analyzer::pop3
	{

#undef POP3_CMD_DEF
#define POP3_CMD_DEF(cmd) #cmd,

static const char* pop3_cmd_word[] = {
#include "POP3_cmd.def"
};

#define POP3_CMD_WORD(code) ((code >= 0) ? pop3_cmd_word[code] : "(UNKNOWN)")

POP3_Analyzer::POP3_Analyzer(Connection* conn)
	: analyzer::tcp::TCP_ApplicationAnalyzer("POP3", conn)
	{
	masterState = detail::POP3_START;
	subState = detail::POP3_WOK;
	state = detail::START;
	lastState = detail::START;

	guessing = false;
	waitingForAuthentication = false;
	requestForMultiLine = false;
	multiLine = false;
	tls = false;

	lastRequiredCommand = 0;
	authLines = 0;

	mail = nullptr;

	cl_orig = new analyzer::tcp::ContentLine_Analyzer(conn, true);
	AddSupportAnalyzer(cl_orig);

	cl_resp = new analyzer::tcp::ContentLine_Analyzer(conn, false);
	AddSupportAnalyzer(cl_resp);
	}

POP3_Analyzer::~POP3_Analyzer() { }

void POP3_Analyzer::Done()
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	if ( mail )
		EndData();
	}

void POP3_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	if ( tls )
		{
		ForwardStream(len, data, orig);
		return;
		}

	if ( (TCP() && TCP()->IsPartial()) )
		return;

	String terminated_string(data, len, true);

	if ( orig )
		ProcessRequest(len, (char*)terminated_string.Bytes());
	else
		ProcessReply(len, (char*)terminated_string.Bytes());
	}

static std::string trim_whitespace(const char* in)
	{
	int n = strlen(in);
	char* out = new char[n + 1];
	char* out_p = out;

	in = util::skip_whitespace(in);

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

	std::string rval(out);
	delete[] out;
	return rval;
	}

void POP3_Analyzer::ProcessRequest(int length, const char* line)
	{
	if ( length == 0 )
		return;

	if ( waitingForAuthentication )
		{
		++authLines;

		String encoded(line);
		String* decoded = zeek::detail::decode_base64(&encoded, nullptr, Conn());

		if ( ! decoded )
			{
			Weird("pop3_bad_base64_encoding");
			return;
			}

		switch ( state )
			{
			case detail::AUTH_LOGIN:
				// Format: Line 1 - User
				//         Line 2 - Password
				if ( authLines == 1 )
					user = decoded->CheckString();

				else if ( authLines == 2 )
					password = decoded->CheckString();

				break;

			case detail::AUTH_PLAIN:
				{
				// Format: "authorization identity<NUL>authentication
				//		identity<NUL>password"
				char* str = (char*)decoded->Bytes();
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

				password.assign(s, len - (s - str));

				break;
				}

			case detail::AUTH_CRAM_MD5:
				{ // Format: "user<space>password-hash"
				const char* s;
				const char* str = (char*)decoded->CheckString();

				for ( s = str; *s && *s != '\t' && *s != ' '; ++s )
					;

				user = std::string(str, s);
				password = "";

				break;
				}

			case detail::AUTH:
				break;

			default:
				reporter->AnalyzerError(this, "unexpected POP3 authorization state");
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
		cmds.push_back(std::string(line));

		if ( cmds.size() == 1 )
			// Not waiting for another server response,
			// so we can process it immediately.
			ProcessClientCmd();
		}
	}

static std::string commands[] = {
	"OK",   "ERR",  "USER", "PASS", "APOP", "AUTH", "STAT", "LIST", "RETR",    "DELE",
	"RSET", "NOOP", "LAST", "QUIT", "TOP",  "CAPA", "UIDL", "STLS", "XSENDER",
};

void POP3_Analyzer::NotAllowed(const char* cmd, const char* state)
	{
	POP3Event(pop3_unexpected, true, cmd, util::fmt("not allowed in other state than '%s'", state));
	}

void POP3_Analyzer::ProcessClientCmd()
	{
	if ( ! cmds.size() )
		return;

	std::string str = trim_whitespace(cmds.front().c_str());
	std::vector<std::string> tokens = TokenizeLine(str, ' ');

	int cmd_code = -1;
	const char* cmd = "";

	if ( tokens.size() > 0 )
		cmd_code = ParseCmd(tokens[0]);

	if ( cmd_code == -1 )
		{
		if ( ! waitingForAuthentication )
			{
			Weird("pop3_client_command_unknown");
			if ( subState == detail::POP3_WOK )
				subState = detail::POP3_OK;
			}
		return;
		}

	cmd = commands[cmd_code].c_str();

	const char* message = tokens.size() > 1 ? tokens[1].c_str() : "";

	switch ( cmd_code )
		{
		case detail::POP3_CMD_ERR:
		case detail::POP3_CMD_OK:
			Weird("pop3_client_sending_server_commands");
			break;

		case detail::POP3_CMD_USER:
			if ( masterState == detail::POP3_AUTHORIZATION )
				{
				POP3Event(pop3_request, true, cmd, message);
				state = detail::USER;
				subState = detail::POP3_WOK;
				user = message;
				}
			else
				NotAllowed(cmd, "authorization");
			break;

		case detail::POP3_CMD_PASS:
			if ( masterState == detail::POP3_AUTHORIZATION )
				{
				if ( state == detail::USER )
					{
					POP3Event(pop3_request, true, cmd, message);
					state = detail::PASS;
					subState = detail::POP3_WOK;
					password = message;
					}
				else
					POP3Event(pop3_unexpected, true, cmd, "pass must follow the command 'USER'");
				}
			else
				NotAllowed(cmd, "authorization");
			break;

		case detail::POP3_CMD_APOP:
			if ( masterState == detail::POP3_AUTHORIZATION )
				{
				POP3Event(pop3_request, true, cmd, message);
				state = detail::APOP;
				subState = detail::POP3_WOK;

				char* arg1 = util::copy_string(message);
				char* e;
				for ( e = arg1; *e && *e != ' ' && *e != '\t'; ++e )
					;
				*e = '\0';
				user = arg1;
				delete[] arg1;
				}
			else
				NotAllowed(cmd, "authorization");
			break;

		case detail::POP3_CMD_AUTH:
			if ( masterState == detail::POP3_AUTHORIZATION )
				{
				POP3Event(pop3_request, true, cmd, message);
				if ( ! *message )
					{
					requestForMultiLine = true;
					state = detail::AUTH;
					subState = detail::POP3_WOK;
					}
				else
					{
					if ( strstr(message, "LOGIN") )
						state = detail::AUTH_LOGIN;
					else if ( strstr(message, "PLAIN") )
						state = detail::AUTH_PLAIN;
					else if ( strstr(message, "CRAM-MD5") )
						state = detail::AUTH_CRAM_MD5;
					else
						{
						state = detail::AUTH;
						POP3Event(pop3_unexpected, true, cmd,
						          util::fmt("unknown AUTH method %s", message));
						}

					subState = detail::POP3_WOK;
					waitingForAuthentication = true;
					authLines = 0;
					}
				}
			else
				POP3Event(pop3_unexpected, true, cmd, "pass must follow the command 'USER'");
			break;

		case detail::POP3_CMD_STAT:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::STAT;
				}
			else
				NotAllowed(cmd, "transaction");
			break;

		case detail::POP3_CMD_LIST:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				if ( ! *message )
					{
					requestForMultiLine = true;
					state = detail::LIST;
					subState = detail::POP3_WOK;
					}
				else
					{
					state = detail::LIST;
					subState = detail::POP3_WOK;
					}
				}
			else
				{
				if ( ! *message )
					requestForMultiLine = true;

				guessing = true;
				lastState = detail::LIST;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_RETR:
			requestForMultiLine = true;
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::RETR;
				}
			else
				{
				guessing = true;
				lastState = detail::RETR;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_DELE:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::DELE;
				}
			else
				{
				guessing = true;
				lastState = detail::DELE;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_RSET:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::RSET;
				}
			else
				{
				guessing = true;
				lastState = detail::RSET;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_NOOP:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::NOOP;
				}
			else
				{
				guessing = true;
				lastState = detail::NOOP;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_LAST:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::LAST;
				}
			else
				{
				guessing = true;
				lastState = detail::LAST;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_QUIT:
			if ( masterState == detail::POP3_AUTHORIZATION ||
			     masterState == detail::POP3_TRANSACTION || masterState == detail::POP3_START )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::QUIT;
				}
			else
				{
				guessing = true;
				lastState = detail::LAST;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_TOP:
			requestForMultiLine = true;

			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::TOP;
				}
			else
				{
				guessing = true;
				lastState = detail::TOP;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_CAPA:
			POP3Event(pop3_request, true, cmd, message);
			subState = detail::POP3_WOK;
			state = detail::CAPA;
			requestForMultiLine = true;
			break;

		case detail::POP3_CMD_STLS:
			POP3Event(pop3_request, true, cmd, message);
			subState = detail::POP3_WOK;
			state = detail::STLS;
			break;

		case detail::POP3_CMD_UIDL:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				if ( ! *message )
					{
					requestForMultiLine = true;
					state = detail::UIDL;
					subState = detail::POP3_WOK;
					}
				else
					{
					state = detail::UIDL;
					subState = detail::POP3_WOK;
					}
				}
			else
				{
				if ( ! *message )
					requestForMultiLine = true;

				guessing = true;
				lastState = detail::UIDL;
				NotAllowed(cmd, "transaction");
				}
			break;

		case detail::POP3_CMD_XSENDER:
			if ( masterState == detail::POP3_TRANSACTION )
				{
				POP3Event(pop3_request, true, cmd, message);
				subState = detail::POP3_WOK;
				state = detail::LAST;
				}
			else
				{
				guessing = true;
				lastState = detail::XSENDER;
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
	std::string str = trim_whitespace(line);

	if ( multiLine == true )
		{
		bool terminator = line[0] == '.' &&
		                  (length == 1 ||
		                   (length > 1 && (line[1] == '\n' ||
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
			if ( state == detail::RETR || state == detail::TOP )
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

	std::vector<std::string> tokens = TokenizeLine(str, ' ');
	if ( tokens.size() > 0 )
		cmd_code = ParseCmd(tokens[0]);

	if ( cmd_code == -1 )
		{
		if ( ! waitingForAuthentication )
			{
			AnalyzerViolation(util::fmt("unknown server command (%s)",
			                            (tokens.size() > 0 ? tokens[0].c_str() : "???")),
			                  line, length);

			Weird("pop3_server_command_unknown");
			if ( subState == detail::POP3_WOK )
				subState = detail::POP3_OK;
			}
		return;
		}

	cmd = commands[cmd_code].c_str();

	const char* message = tokens.size() > 1 ? tokens[1].c_str() : "";

	switch ( cmd_code )
		{
		case detail::POP3_CMD_OK:
			if ( subState == detail::POP3_WOK )
				subState = detail::POP3_OK;

			if ( guessing )
				{
				masterState = detail::POP3_TRANSACTION;
				guessing = false;
				state = lastState;
				POP3Event(pop3_unexpected, false, cmd,
				          "no auth required -> state changed to 'transaction'");
				}

			switch ( state )
				{
				case detail::START:
					masterState = detail::POP3_AUTHORIZATION;
					break;

				case detail::USER:
					state = detail::USER;
					masterState = detail::POP3_AUTHORIZATION;
					AnalyzerConfirmation();
					break;

				case detail::PASS:
				case detail::APOP:
				case detail::NOOP:
				case detail::LAST:
				case detail::STAT:
				case detail::RSET:
				case detail::DELE:
				case detail::XSENDER:
					if ( masterState == detail::POP3_AUTHORIZATION )
						AuthSuccessful();
					masterState = detail::POP3_TRANSACTION;
					break;

				case detail::AUTH:
				case detail::AUTH_PLAIN:
				case detail::AUTH_CRAM_MD5:
				case detail::AUTH_LOGIN:
					if ( requestForMultiLine == true )
						multiLine = true;
					if ( waitingForAuthentication )
						masterState = detail::POP3_TRANSACTION;
					waitingForAuthentication = false;
					AuthSuccessful();
					break;

				case detail::TOP:
				case detail::RETR:
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

				case detail::CAPA:
					AnalyzerConfirmation();
					// Fall-through.

				case detail::UIDL:
				case detail::LIST:
					if ( requestForMultiLine == true )
						multiLine = true;
					break;

				case detail::STLS:
					AnalyzerConfirmation();
					tls = true;
					StartTLS();
					return;

				case detail::QUIT:
					if ( masterState == detail::POP3_AUTHORIZATION ||
					     masterState == detail::POP3_START )
						masterState = detail::POP3_FINISHED;

					else if ( masterState == detail::POP3_TRANSACTION )
						masterState = detail::POP3_UPDATE;

					break;
				}

			POP3Event(pop3_reply, false, cmd, message);
			// no else part, ignoring multiple OKs

			if ( ! multiLine )
				FinishClientCmd();
			break;

		case detail::POP3_CMD_ERR:
			if ( subState == detail::POP3_WOK )
				subState = detail::POP3_OK;

			multiLine = false;
			requestForMultiLine = false;
			guessing = false;
			waitingForAuthentication = false;

			switch ( state )
				{
				case detail::START:
					break;

				case detail::USER:
				case detail::PASS:
				case detail::APOP:
				case detail::AUTH:
				case detail::AUTH_LOGIN:
				case detail::AUTH_PLAIN:
				case detail::AUTH_CRAM_MD5:
					masterState = detail::POP3_AUTHORIZATION;
					state = detail::START;
					waitingForAuthentication = false;

					if ( user.size() )
						POP3Event(pop3_login_failure, false, user.c_str(), password.c_str());
					break;

				case detail::NOOP:
				case detail::LAST:
				case detail::STAT:
				case detail::RSET:
				case detail::DELE:
				case detail::LIST:
				case detail::RETR:
				case detail::UIDL:
				case detail::TOP:
				case detail::XSENDER:
					masterState = detail::POP3_TRANSACTION;
					break;

				case detail::CAPA:
					break;

				case detail::QUIT:
					if ( masterState == detail::POP3_AUTHORIZATION ||
					     masterState == detail::POP3_TRANSACTION ||
					     masterState == detail::POP3_START )
						masterState = detail::POP3_FINISHED;
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
		EnqueueConnEvent(pop3_starttls, ConnVal());
	}

void POP3_Analyzer::AuthSuccessful()
	{
	if ( user.size() )
		POP3Event(pop3_login_success, false, user.c_str(), password.c_str());
	}

void POP3_Analyzer::BeginData(bool orig)
	{
	delete mail;
	mail = new analyzer::mime::MIME_Mail(this, orig);
	}

void POP3_Analyzer::EndData()
	{
	if ( ! mail )
		reporter->Warning("unmatched end of data");
	else
		{
		mail->Done();
		delete mail;
		mail = nullptr;
		}
	}

void POP3_Analyzer::ProcessData(int length, const char* line)
	{
	mail->Deliver(length, line, true);
	}

int POP3_Analyzer::ParseCmd(std::string cmd)
	{
	if ( cmd.size() == 0 )
		return -1;

	for ( int code = detail::POP3_CMD_OK; code < detail::POP3_CMD_END; ++code )
		{
		char c = cmd.c_str()[0];
		if ( c == '+' || c == '-' )
			cmd = cmd.substr(1);

		for ( size_t i = 0; i < cmd.size(); ++i )
			cmd[i] = toupper(cmd[i]);

		if ( ! cmd.compare(pop3_cmd_word[code]) )
			return code;
		}

	return -1;
	}

std::vector<std::string> POP3_Analyzer::TokenizeLine(const std::string& input, char split)
	{
	std::vector<std::string> tokens;

	if ( input.size() < 1 )
		return tokens;

	int start = 0;
	unsigned int splitPos = 0;
	std::string token = "";

	if ( input.find(split, 0) == std::string::npos )
		{
		tokens.push_back(input);
		return tokens;
		}

	if ( (splitPos = input.find(split, 0)) < input.size() )
		{
		token = input.substr(start, splitPos);
		if ( token.size() > 0 && token[0] != split )
			tokens.push_back(token);

		token = input.substr(splitPos + 1, input.size() - splitPos);
		tokens.push_back(token);
		}

	return tokens;
	}

void POP3_Analyzer::POP3Event(EventHandlerPtr event, bool is_orig, const char* arg1,
                              const char* arg2)
	{
	if ( ! event )
		return;

	Args vl;
	vl.reserve(2 + (bool)arg1 + (bool)arg2);

	vl.emplace_back(ConnVal());
	vl.emplace_back(val_mgr->Bool(is_orig));

	if ( arg1 )
		vl.emplace_back(make_intrusive<StringVal>(arg1));
	if ( arg2 )
		vl.emplace_back(make_intrusive<StringVal>(arg2));

	EnqueueConnEvent(event, std::move(vl));
	}

	} // namespace zeek::analyzer::pop3
