// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Login.h"
#include "analyzer/protocol/tcp/ContentLine.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Rlogin_Analyzer, zeek, analyzer::login);

namespace zeek::analyzer::login {

enum rlogin_state {
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
};

class Contents_Rlogin_Analyzer final : public zeek::analyzer::tcp::ContentLine_Analyzer {
public:
	Contents_Rlogin_Analyzer(zeek::Connection* conn, bool orig,
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
	explicit Rlogin_Analyzer(zeek::Connection* conn);

	void ClientUserName(const char* s);
	void ServerUserName(const char* s);
	void TerminalType(const char* s);

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new Rlogin_Analyzer(conn); }
};

} // namespace zeek::analyzer::login

namespace analyzer::login {

	using rlogin_state [[deprecated("Remove in v4.1. Use zeek::analyzer::login::rlogin_state.")]] = zeek::analyzer::login::rlogin_state;
	constexpr auto RLOGIN_FIRST_NULL [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_FIRST_NULL.")]] = zeek::analyzer::login::RLOGIN_FIRST_NULL;
	constexpr auto RLOGIN_CLIENT_USER_NAME [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_CLIENT_USER_NAME.")]] = zeek::analyzer::login::RLOGIN_CLIENT_USER_NAME;
	constexpr auto RLOGIN_SERVER_USER_NAME [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_SERVER_USER_NAME.")]] = zeek::analyzer::login::RLOGIN_SERVER_USER_NAME;
	constexpr auto RLOGIN_TERMINAL_TYPE [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_TERMINAL_TYPE.")]] = zeek::analyzer::login::RLOGIN_TERMINAL_TYPE;
	constexpr auto RLOGIN_SERVER_ACK [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_SERVER_ACK.")]] = zeek::analyzer::login::RLOGIN_SERVER_ACK;
	constexpr auto RLOGIN_IN_BAND_CONTROL_FF2 [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_IN_BAND_CONTROL_FF2.")]] = zeek::analyzer::login::RLOGIN_IN_BAND_CONTROL_FF2;
	constexpr auto RLOGIN_WINDOW_CHANGE_S1 [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_WINDOW_CHANGE_S1.")]] = zeek::analyzer::login::RLOGIN_WINDOW_CHANGE_S1;
	constexpr auto RLOGIN_WINDOW_CHANGE_S2 [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_WINDOW_CHANGE_S2.")]] = zeek::analyzer::login::RLOGIN_WINDOW_CHANGE_S2;
	constexpr auto RLOGIN_WINDOW_CHANGE_REMAINDER [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_WINDOW_CHANGE_REMAINDER.")]] = zeek::analyzer::login::RLOGIN_WINDOW_CHANGE_REMAINDER;
	constexpr auto RLOGIN_LINE_MODE [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_LINE_MODE.")]] = zeek::analyzer::login::RLOGIN_LINE_MODE;
	constexpr auto RLOGIN_PRESUMED_REJECTED [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_PRESUMED_REJECTED.")]] = zeek::analyzer::login::RLOGIN_PRESUMED_REJECTED;
	constexpr auto RLOGIN_UNKNOWN [[deprecated("Remove in v4.1. Use zeek::analyzer::login::RLOGIN_UNKNOWN.")]] = zeek::analyzer::login::RLOGIN_UNKNOWN;

	using Contents_Rlogin_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::login::Contents_Rlogin_Analyzer.")]] = zeek::analyzer::login::Contents_Rlogin_Analyzer;
	using Rlogin_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::login::Rlogin_Analyzer.")]] = zeek::analyzer::login::Rlogin_Analyzer;

} // namespace analyzer::login
