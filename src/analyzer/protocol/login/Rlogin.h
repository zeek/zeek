// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Login.h"
#include "analyzer/protocol/tcp/ContentLine.h"

namespace analyzer { namespace login {

typedef enum {
	RLOGIN_FIRST_NULL,	// waiting to see first NUL
	RLOGIN_CLIENT_USER_NAME,	// scanning client user name up to NUL
	RLOGIN_SERVER_USER_NAME,	// scanning server user name up to NUL
	RLOGIN_TERMINAL_TYPE,	// scanning terminal type & speed

	RLOGIN_SERVER_ACK,	// waiting to see NUL from server to ack client

	RLOGIN_IN_BAND_CONTROL_FF2,	// waiting to see the second FF

	RLOGIN_WINDOW_CHANGE_S1,	// waiting to see the first 's'
	RLOGIN_WINDOW_CHANGE_S2,	// waiting to see the second 's'
	RLOGIN_WINDOW_CHANGE_REMAINDER,	// remaining "bytes_to_scan" bytes

	RLOGIN_LINE_MODE,	// switch to line-oriented processing

	RLOGIN_PRESUMED_REJECTED,	// apparently server said No Way

	RLOGIN_UNKNOWN,	// we don't know what state we're in
} rlogin_state;

class Rlogin_Analyzer;

class Contents_Rlogin_Analyzer final : public tcp::ContentLine_Analyzer {
public:
	Contents_Rlogin_Analyzer(Connection* conn, bool orig,
					Rlogin_Analyzer* analyzer);
	~Contents_Rlogin_Analyzer() override;

	void SetPeer(Contents_Rlogin_Analyzer* arg_peer)
		{ peer = arg_peer; }

	rlogin_state RloginState() const
		{ return state; }

protected:
	void DoDeliver(int len, const u_char* data) override;
	void BadProlog();

	rlogin_state state, save_state;
	int num_bytes_to_scan;

	Contents_Rlogin_Analyzer* peer;
	Rlogin_Analyzer* analyzer;
};

class Rlogin_Analyzer final : public Login_Analyzer {
public:
	explicit Rlogin_Analyzer(Connection* conn);

	void ClientUserName(const char* s);
	void ServerUserName(const char* s);
	void TerminalType(const char* s);

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Rlogin_Analyzer(conn); }
};

} } // namespace analyzer::*
