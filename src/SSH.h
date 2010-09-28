// $Id: SSH.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ssh_h
#define ssh_h

#include "TCP.h"
#include "ContentLine.h"

class SSH_Analyzer : public TCP_ApplicationAnalyzer {
public:
	SSH_Analyzer(Connection* conn);

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SSH_Analyzer(conn); }

	static bool Available()
		{ return  ssh_client_version || ssh_server_version; }

private:
	ContentLine_Analyzer* orig;
	ContentLine_Analyzer* resp;
};

#endif
