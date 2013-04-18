// See the file "COPYING" in the main distribution directory for copyright.

#ifndef telnet_h
#define telnet_h

#include "Login.h"

namespace analyzer { namespace login {

class Telnet_Analyzer : public Login_Analyzer {
public:
	Telnet_Analyzer(Connection* conn);
	virtual ~Telnet_Analyzer()	{}

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Telnet_Analyzer(conn); }
};

} } // namespace analyzer::* 

#endif
