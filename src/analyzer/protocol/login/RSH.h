// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Login.h"
#include "analyzer/protocol/tcp/ContentLine.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Rsh_Analyzer, zeek, analyzer::login);

namespace zeek::analyzer::login {

enum rsh_state {
	RSH_FIRST_NULL,		// waiting to see first NUL
	RSH_CLIENT_USER_NAME,	// scanning client user name up to NUL
	RSH_SERVER_USER_NAME,	// scanning server user name up to NUL
	RSH_INITIAL_CMD,	// scanning initial command up to NUL

	RSH_LINE_MODE,		// switch to line-oriented processing

	RSH_PRESUMED_REJECTED,	// apparently server said No Way

	RSH_UNKNOWN,	// we don't know what state we're in
};

class Contents_Rsh_Analyzer final : public zeek::analyzer::tcp::ContentLine_Analyzer {
public:
	Contents_Rsh_Analyzer(zeek::Connection* conn, bool orig, Rsh_Analyzer* analyzer);
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
	explicit Rsh_Analyzer(zeek::Connection* conn);

	void DeliverStream(int len, const u_char* data, bool orig) override;

	void ClientUserName(const char* s);
	void ServerUserName(const char* s);

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new Rsh_Analyzer(conn); }

	Contents_Rsh_Analyzer* contents_orig;
	Contents_Rsh_Analyzer* contents_resp;
};

} // namespace zeek::analyzer::login

namespace analyzer::login {

	using rsh_state [[deprecated("Remove in v4.1. Use zeek::analyzer::login::rsh_state.")]] = zeek::analyzer::login::rsh_state;
	constexpr auto RSH_FIRST_NULL [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_FIRST_NULL.")]] = zeek::analyzer::login::RSH_FIRST_NULL;
	constexpr auto RSH_CLIENT_USER_NAME [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_CLIENT_USER_NAME.")]] = zeek::analyzer::login::RSH_CLIENT_USER_NAME;
	constexpr auto RSH_SERVER_USER_NAME [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_SERVER_USER_NAME.")]] = zeek::analyzer::login::RSH_SERVER_USER_NAME;
	constexpr auto RSH_INITIAL_CMD [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_INITIAL_CMD.")]] = zeek::analyzer::login::RSH_INITIAL_CMD;
	constexpr auto RSH_LINE_MODE [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_LINE_MODE.")]] = zeek::analyzer::login::RSH_LINE_MODE;
	constexpr auto RSH_PRESUMED_REJECTED [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_PRESUMED_REJECTED.")]] = zeek::analyzer::login::RSH_PRESUMED_REJECTED;
	constexpr auto RSH_UNKNOWN [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RSH_UNKNOWN.")]] = zeek::analyzer::login::RSH_UNKNOWN;

	using Contents_Rsh_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::login::Contents_Rsh_Analyzer.")]] = zeek::analyzer::login::Contents_Rsh_Analyzer;
	using Rsh_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::login::Rsh_Analyzer.")]] = zeek::analyzer::login::Rsh_Analyzer;

} // namespace analyzer::login
