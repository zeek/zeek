// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include <ctype.h>
#include <stdlib.h>

#include "NetVar.h"
#include "Login.h"
#include "RE.h"
#include "Event.h"

#include "events.bif.h"

using namespace analyzer::login;

static RE_Matcher* re_skip_authentication = 0;
static RE_Matcher* re_direct_login_prompts;
static RE_Matcher* re_login_prompts;
static RE_Matcher* re_login_non_failure_msgs;
static RE_Matcher* re_login_failure_msgs;
static RE_Matcher* re_login_success_msgs;
static RE_Matcher* re_login_timeouts;

static RE_Matcher* init_RE(ListVal* l);

Login_Analyzer::Login_Analyzer(const char* name, Connection* conn)
    : tcp::TCP_ApplicationAnalyzer(name, conn), user_text()
	{
	state = LOGIN_STATE_AUTHENTICATE;
	num_user_lines_seen = lines_scanned = 0;
	// Set last_failure_num_user_lines so we will always generate
	// at least one failure message, even if the user doesn't
	// type anything (but we see, e.g., a timeout).
	last_failure_num_user_lines = -1;
	login_prompt_line = failure_line = 0;
	user_text_first = 0;
	user_text_last = MAX_USER_TEXT - 1;
	num_user_text = 0;
	client_name = username = 0;
	saw_ploy = is_VMS = 0;

	if ( ! re_skip_authentication )
		{
#ifdef USE_PERFTOOLS_DEBUG
		HeapLeakChecker::Disabler disabler;
#endif
		re_skip_authentication = init_RE(skip_authentication);
		re_direct_login_prompts = init_RE(direct_login_prompts);
		re_login_prompts = init_RE(login_prompts);
		re_login_non_failure_msgs = init_RE(login_non_failure_msgs);
		re_login_failure_msgs = init_RE(login_failure_msgs);
		re_login_success_msgs = init_RE(login_success_msgs);
		re_login_timeouts = init_RE(login_timeouts);
		}
	}

Login_Analyzer::~Login_Analyzer()
	{
	while ( num_user_text > 0 )
		{
		char* s = PopUserText();
		delete [] s;
		}

	Unref(username);
	Unref(client_name);
	}

void Login_Analyzer::DeliverStream(int length, const u_char* line, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(length, line, orig);

	char* str = new char[length+1];

	// Eliminate NUL characters.
	int i, j;
	for ( i = 0, j = 0; i < length; ++i )
		if ( line[i] != '\0' )
			str[j++] = line[i];
		else
			{
			if ( Conn()->FlagEvent(NUL_IN_LINE) )
				Weird("NUL_in_line");
			}

	str[j] = '\0';

	NewLine(orig, str);
	delete [] str;
	}

void Login_Analyzer::NewLine(bool orig, char* line)
	{
	if ( state == LOGIN_STATE_SKIP )
		return;

	if ( orig && login_input_line )
		LineEvent(login_input_line, line);

	if ( ! orig && login_output_line )
		LineEvent(login_output_line, line);

	if ( state == LOGIN_STATE_LOGGED_IN )
		return;

	if ( state == LOGIN_STATE_AUTHENTICATE )
		{
		if ( TCP()->OrigState() == tcp::TCP_ENDPOINT_PARTIAL ||
		     TCP()->RespState() == tcp::TCP_ENDPOINT_PARTIAL )
			state = LOGIN_STATE_CONFUSED;	// unknown login state
		else
			{
			AuthenticationDialog(orig, line);
			return;
			}
		}

	if ( state != LOGIN_STATE_CONFUSED )
		{
		reporter->AnalyzerError(this,
		                                "bad state in Login_Analyzer::NewLine");
		return;
		}

	// When we're in "confused", we feed each user input line to
	// login_confused_text, but also scan the text in the
	// other direction for evidence of successful login.
	if ( orig )
		{
		(void) IsPloy(line);
		ConfusionText(line);
		}

	else if ( ! saw_ploy && IsSuccessMsg(line) )
		{
		LoginEvent(login_success, line, 1);
		state = LOGIN_STATE_LOGGED_IN;
		}
	}

void Login_Analyzer::AuthenticationDialog(bool orig, char* line)
	{
	if ( orig )
		{
		if ( is_VMS )
			{
#define VMS_REPEAT_SEQ "\x1b[A"
			char* repeat_prev_line = strstr(line, VMS_REPEAT_SEQ);
			if ( repeat_prev_line )
				{
				if ( repeat_prev_line[strlen(VMS_REPEAT_SEQ)] )
					{
					Confused("extra_repeat_text", line);
					return;
					}

				// VMS repeats the username, not the last line
				// typed (which presumably is the password).
				if ( username )
					{
					line = (char*) username->AsString()->Bytes();
					if ( strstr(line, VMS_REPEAT_SEQ) )
						Confused("username_with_embedded_repeat", line);
					else
						NewLine(orig, line);
					}

				else
					Confused("repeat_without_username", line);
				return;
				}
			}

		++num_user_lines_seen;

		if ( ! IsPloy(line) )
			AddUserText(line);

		return;
		}

	// Ignore blank lines from the responder - some systems spew
	// out a whole bunch of these.
	if ( IsEmpty(line) )
		return;

	if ( ++lines_scanned > MAX_AUTHENTICATE_LINES &&
	     login_prompt_line == 0 && failure_line == 0 )
		Confused("no_login_prompt", line);

	const char* prompt = IsLoginPrompt(line);
	int is_timeout = IsTimeout(line);
	if ( prompt && ! IsSuccessMsg(line) && ! is_timeout )
		{
		is_VMS = strstr(line, "Username:") != 0;

		// If we see multiple login prompts, presume that
		// each is consuming one line of typeahead.
		//
		// We can also get multiple login prompts spread
		// across adjacent lines, for example if the user
		// enters a blank line or a line that wasn't accepted
		// (e.g., "foo^C").

		int multi_line_prompt =
			(login_prompt_line == lines_scanned - 1 &&
			 // if login_prompt_line is the same as failure_line,
			 // then we didn't actually see a login prompt
			 // there, we're just remembering that as the
			 // prompt line so we can count typeahead with
			 // respect to it (see below).
			 login_prompt_line != failure_line);

		const char* next_prompt = 0;
		while ( (*prompt != '\0' &&
			 (next_prompt = IsLoginPrompt(prompt + 1))) ||
			multi_line_prompt )
			{
			if ( ! HaveTypeahead() )
				{
				Confused("multiple_login_prompts", line);
				break;
				}

			char* pop_str = PopUserText();
			bool empty = IsEmpty(pop_str);
			delete [] pop_str;

			if ( multi_line_prompt )
				break;

			if ( ! empty )
				{
				Confused("non_empty_multi_login", line);
				break;
				}

			prompt = next_prompt;
			}

		if ( state == LOGIN_STATE_CONFUSED )
			return;

		const char* user = GetUsername(prompt);
		if ( user && ! IsEmpty(user) )
			{
			if ( ! HaveTypeahead() )
				AddUserText(user);
			}

		login_prompt_line = lines_scanned;

		if ( IsDirectLoginPrompt(line) )
			{
			LoginEvent(login_success, line, 1);
			state = LOGIN_STATE_LOGGED_IN;
			SetSkip(1);
			return;
			}
		}

	else if ( is_timeout || IsFailureMsg(line) )
		{
		if ( num_user_lines_seen > last_failure_num_user_lines )
			{
			// The user has typed something since we last
			// generated a failure event, so it's worth
			// recording another failure event.
			//
			// We can otherwise wind up generating multiple
			// failure events for sequences like:
			//
			//	Error reading command input
			//	Timeout period expired
			if ( is_timeout )
				AddUserText("<timeout>");
			LoginEvent(login_failure, line);
			}

		// Set the login prompt line to be here, too, so
		// that we require MAX_LOGIN_LOOKAHEAD beyond this
		// point before deciding they've logged in.
		login_prompt_line = failure_line = lines_scanned;
		last_failure_num_user_lines = num_user_lines_seen;
		}

	else if ( IsSkipAuthentication(line) )
		{
		if ( authentication_skipped )
			{
			val_list* vl = new val_list;
			vl->append(BuildConnVal());
			ConnectionEvent(authentication_skipped, vl);
			}

		state = LOGIN_STATE_SKIP;
		SetSkip(1);
		}

	else if ( IsSuccessMsg(line) ||
		  (login_prompt_line > 0 &&
		   lines_scanned >
		   login_prompt_line + MAX_LOGIN_LOOKAHEAD + num_user_text) )
		{
		LoginEvent(login_success, line);
		state = LOGIN_STATE_LOGGED_IN;
		}
	}

void Login_Analyzer::SetEnv(bool orig, char* name, char* val)
	{
	if ( ! orig )
		// Why is the responder transmitting its environment??
		Confused("responder_environment", name);

	else
		{
		if ( streq(name, "USER") )
			{
			if ( username )
				{
				const BroString* u = username->AsString();
				const byte_vec ub = u->Bytes();
				const char* us = (const char*) ub;
				if ( ! streq(val, us) )
					Confused("multiple_USERs", val);
				Unref(username);
				}

			// "val" gets copied here.
			username = new StringVal(val);
			}

		else if ( login_terminal && streq(name, "TERM") )
			{
			val_list* vl = new val_list;

			vl->append(BuildConnVal());
			vl->append(new StringVal(val));

			ConnectionEvent(login_terminal, vl);
			}

		else if ( login_display && streq(name, "DISPLAY") )
			{
			val_list* vl = new val_list;

			vl->append(BuildConnVal());
			vl->append(new StringVal(val));

			ConnectionEvent(login_display, vl);
			}

		else if ( login_prompt && streq(name, "TTYPROMPT") )
			{
			val_list* vl = new val_list;

			vl->append(BuildConnVal());
			vl->append(new StringVal(val));

			ConnectionEvent(login_prompt, vl);
			}
		}

	delete [] name;
	delete [] val;
	}

void Login_Analyzer::EndpointEOF(bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::EndpointEOF(orig);

	if ( state == LOGIN_STATE_AUTHENTICATE && HaveTypeahead() )
		{
		LoginEvent(login_success, "<EOF>", 1);
		state = LOGIN_STATE_LOGGED_IN;
		}
	}

void Login_Analyzer::LoginEvent(EventHandlerPtr f, const char* line,
				int no_user_okay)
	{
	if ( ! f )
		return;

	if ( login_prompt_line > failure_line )
		{
		FlushEmptyTypeahead();

		// We should've seen a username.
		if ( ! HaveTypeahead() )
			{
			if ( no_user_okay )
				{
				Unref(username);
				username = new StringVal("<none>");
				}

			else
				{
				Confused("no_username", line);
				return;
				}
			}
		else
			{
			Unref(username);
			username = PopUserTextVal();
			}
		}

	else
		{
		// Evidently the system reprompted for a password upon an
		// earlier failure.  Use the previously-recorded username.
		if ( ! username )
			{
			if ( no_user_okay )
				{
				Unref(username);
				username = new StringVal("<none>");
				}

			else
				{
				Confused("no_username2", line);
				return;
				}
			}
		}

	Val* password = HaveTypeahead() ?
				PopUserTextVal() : new StringVal("<none>");

	val_list* vl = new val_list;

	vl->append(BuildConnVal());
	vl->append(username->Ref());
	vl->append(client_name ? client_name->Ref() : new StringVal(""));
	vl->append(password);
	vl->append(new StringVal(line));

	ConnectionEvent(f, vl);
	}

const char* Login_Analyzer::GetUsername(const char* line) const
	{
	while ( isspace(*line) )
		++line;

	return line;
	}

void Login_Analyzer::LineEvent(EventHandlerPtr f, const char* line)
	{
	val_list* vl = new val_list;

	vl->append(BuildConnVal());
	vl->append(new StringVal(line));

	ConnectionEvent(f, vl);
	}


void Login_Analyzer::Confused(const char* msg, const char* line)
	{
	state = LOGIN_STATE_CONFUSED;	// to suppress further messages

	if ( login_confused )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new StringVal(msg));
		vl->append(new StringVal(line));

		ConnectionEvent(login_confused, vl);
		}

	if ( login_confused_text )
		{
		// Send all of the typeahead, and the current line, as
		// confusion text.
		while ( HaveTypeahead() )
			{
			char* s = PopUserText();
			ConfusionText(s);
			delete [] s;
			}

		ConfusionText(line);
		}
	}

void Login_Analyzer::ConfusionText(const char* line)
	{
	if ( login_confused_text )
		{
		val_list* vl = new val_list;
		vl->append(BuildConnVal());
		vl->append(new StringVal(line));
		ConnectionEvent(login_confused_text, vl);
		}
	}

int Login_Analyzer::IsPloy(const char* line)
	{
	if ( IsLoginPrompt(line) || IsFailureMsg(line) || IsSuccessMsg(line) ||
	     IsSkipAuthentication(line) )
		{
		saw_ploy = 1;
		Confused("possible_login_ploy", line);
		return 1;
		}
	else
		return 0;
	}

int Login_Analyzer::IsSkipAuthentication(const char* line) const
	{
	return re_skip_authentication->MatchAnywhere(line);
	}

const char* Login_Analyzer::IsLoginPrompt(const char* line) const
	{
	int prompt_match = re_login_prompts->MatchAnywhere(line);
	if ( ! prompt_match || IsFailureMsg(line) )
		// IRIX can report "login: ERROR: Login incorrect"
		return 0;

	return &line[prompt_match];
	}

int Login_Analyzer::IsDirectLoginPrompt(const char* line) const
	{
	return re_direct_login_prompts->MatchAnywhere(line);
	}

int Login_Analyzer::IsFailureMsg(const char* line) const
	{
	return re_login_failure_msgs->MatchAnywhere(line) &&
		! re_login_non_failure_msgs->MatchAnywhere(line);
	}

int Login_Analyzer::IsSuccessMsg(const char* line) const
	{
	return re_login_success_msgs->MatchAnywhere(line);
	}

int Login_Analyzer::IsTimeout(const char* line) const
	{
	return re_login_timeouts->MatchAnywhere(line);
	}

int Login_Analyzer::IsEmpty(const char* line) const
	{
	if ( ! line )
		return true;

	while ( *line && isspace(*line) )
		++line;

	return *line == '\0';
	}

void Login_Analyzer::AddUserText(const char* line)
	{
	if ( num_user_text >= MAX_USER_TEXT )
		Confused("excessive_typeahead", line);
	else
		{
		if ( ++user_text_last == MAX_USER_TEXT )
			user_text_last = 0;

		user_text[user_text_last] = copy_string(line);

		++num_user_text;
		}
	}

char* Login_Analyzer::PeekUserText()
	{
	if ( num_user_text <= 0 )
		{
		reporter->AnalyzerError(this,
		  "underflow in Login_Analyzer::PeekUserText()");
		return 0;
		}

	return user_text[user_text_first];
	}

char* Login_Analyzer::PopUserText()
	{
	char* s = PeekUserText();

	if ( ! s )
		return 0;

	if ( ++user_text_first == MAX_USER_TEXT )
		user_text_first = 0;

	--num_user_text;

	return s;
	}

Val* Login_Analyzer::PopUserTextVal()
	{
	char* s = PopUserText();

	if ( s )
		return new StringVal(new BroString(1, byte_vec(s), strlen(s)));
	else
		return new StringVal("");
	}

int Login_Analyzer::MatchesTypeahead(const char* line) const
	{
	for ( int i = user_text_first, n = 0; n < num_user_text; ++i, ++n )
		{
		if ( i == MAX_USER_TEXT )
			i = 0;

		if ( streq(user_text[i], line) )
			return 1;
		}

	return 0;
	}

void Login_Analyzer::FlushEmptyTypeahead()
	{
	while ( HaveTypeahead() && IsEmpty(PeekUserText()) )
		delete [] PopUserText();
	}

RE_Matcher* init_RE(ListVal* l)
	{
	RE_Matcher* re = l->BuildRE();
	if ( re )
		re->Compile();

	return re;
	}
