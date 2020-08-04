// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Login.h"

namespace zeek::analyzer::login {

class Telnet_Analyzer : public Login_Analyzer {
public:
	explicit Telnet_Analyzer(zeek::Connection* conn);
	~Telnet_Analyzer() override {}

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new Telnet_Analyzer(conn); }
};

} // namespace zeek::analyzer::login

namespace analyzer::login {

	using Telnet_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::login::Telnet_Analyzer.")]] = zeek::analyzer::login::Telnet_Analyzer;

} // namespace analyzer::login
