// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_LOGIN_LOGIN_H
#define ANALYZER_PROTOCOL_LOGIN_LOGIN_H

#include "analyzer/protocol/tcp/TCP.h"

namespace analyzer { namespace login {

typedef enum {
	LOGIN_STATE_AUTHENTICATE,	// trying to authenticate

	LOGIN_STATE_LOGGED_IN,	// successful authentication
	LOGIN_STATE_SKIP,	// skip any further processing
	LOGIN_STATE_CONFUSED,	// we're confused
} login_state;

// If no action by this many lines, we're definitely confused.
#define MAX_AUTHENTICATE_LINES 50

// Maximum # lines look after login for failure.
#define MAX_LOGIN_LOOKAHEAD 10

class Login_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	Login_Analyzer(const char* name, Connection* conn);
	~Login_Analyzer();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	virtual void SetEnv(bool orig, char* name, char* val);

	login_state LoginState() const		{ return state; }
	void SetLoginState(login_state s)	{ state = s; }

	virtual void EndpointEOF(bool is_orig);

protected:
	void NewLine(bool orig, char* line);
	void AuthenticationDialog(bool orig, char* line);

	void LoginEvent(EventHandlerPtr f, const char* line, int no_user_okay=0);
	const char* GetUsername(const char* line) const;
	void LineEvent(EventHandlerPtr f, const char* line);
	void Confused(const char* msg, const char* addl);
	void ConfusionText(const char* line);

	int IsPloy(const char* line);
	int IsSkipAuthentication(const char* line) const;
	const char* IsLoginPrompt(const char* line) const;	// nil if not
	int IsDirectLoginPrompt(const char* line) const;
	int IsFailureMsg(const char* line) const;
	int IsSuccessMsg(const char* line) const;
	int IsTimeout(const char* line) const;
	int IsEmpty(const char* line) const;

	void AddUserText(const char* line);	// complains on overflow
	char* PeekUserText();	// internal warning on underflow
	char* PopUserText();		// internal warning on underflow
	Val* PopUserTextVal();

	int MatchesTypeahead(const char* line) const;
	int HaveTypeahead() const	{ return num_user_text > 0; }
	void FlushEmptyTypeahead();

// If we have more user text than this unprocessed, we complain about
// excessive typeahead.
#define MAX_USER_TEXT 12
	char* user_text[MAX_USER_TEXT];
	int user_text_first, user_text_last;	// indices into user_text
	int num_user_text;	// number of entries in user_text

	Val* username;	// last username reported
	Val* client_name;	// rlogin client name (or nil if none)

	login_state state;
	int lines_scanned;
	int num_user_lines_seen;
	int last_failure_num_user_lines;
	int login_prompt_line;
	int failure_line;

	int is_VMS;
	int saw_ploy;
};

} } // namespace analyzer::* 

#endif
