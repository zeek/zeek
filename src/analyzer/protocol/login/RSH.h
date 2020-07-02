// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Login.h"
#include "analyzer/protocol/tcp/ContentLine.h"

namespace analyzer { namespace login {

typedef enum {
	RSH_FIRST_NULL,		// waiting to see first NUL
	RSH_CLIENT_USER_NAME,	// scanning client user name up to NUL
	RSH_SERVER_USER_NAME,	// scanning server user name up to NUL
	RSH_INITIAL_CMD,	// scanning initial command up to NUL

	RSH_LINE_MODE,		// switch to line-oriented processing

	RSH_PRESUMED_REJECTED,	// apparently server said No Way

	RSH_UNKNOWN,	// we don't know what state we're in
} rsh_state;

class Rsh_Analyzer;

class Contents_Rsh_Analyzer final : public tcp::ContentLine_Analyzer {
public:
	Contents_Rsh_Analyzer(Connection* conn, bool orig, Rsh_Analyzer* analyzer);
	~Contents_Rsh_Analyzer() override;

	rsh_state RshSaveState() const	{ return save_state; }

protected:
	void DoDeliver(int len, const u_char* data) override;
	void BadProlog();

	rsh_state state, save_state;
	int num_bytes_to_scan;

	Rsh_Analyzer* analyzer;
};

class Rsh_Analyzer final : public Login_Analyzer {
public:
	explicit Rsh_Analyzer(Connection* conn);

	void DeliverStream(int len, const u_char* data, bool orig) override;

	void ClientUserName(const char* s);
	void ServerUserName(const char* s);

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Rsh_Analyzer(conn); }

	Contents_Rsh_Analyzer* contents_orig;
	Contents_Rsh_Analyzer* contents_resp;
};

} } // namespace analyzer::*
