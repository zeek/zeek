// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/login/Login.h"

namespace zeek::analyzer::login {

class Telnet_Analyzer : public Login_Analyzer {
public:
	explicit Telnet_Analyzer(Connection* conn);
	~Telnet_Analyzer() override {}

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new Telnet_Analyzer(conn); }
};

} // namespace zeek::analyzer::login
