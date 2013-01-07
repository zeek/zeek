// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ssh_h
#define ssh_h

#include "TCP.h"
#include "ContentLine.h"

class SSH_Analyzer : public TCP_ApplicationAnalyzer {
public:
	SSH_Analyzer(Connection* conn);

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn, const AnalyzerTag& tag)
		{ return new SSH_Analyzer(conn); }

	static bool Available(const AnalyzerTag& tag)
		{ return  ssh_client_version || ssh_server_version; }

private:
	ContentLine_Analyzer* orig;
	ContentLine_Analyzer* resp;
};

#endif
