// $Id: Telnet.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef telnet_h
#define telnet_h

#include "Login.h"

class Telnet_Analyzer : public Login_Analyzer {
public:
	Telnet_Analyzer(Connection* conn);
	virtual ~Telnet_Analyzer()	{}

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Telnet_Analyzer(conn); }

	static bool Available()
		{
		return login_failure || login_success ||
			login_input_line || login_output_line;
		}
};

#endif
