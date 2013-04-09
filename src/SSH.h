// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ssh_h
#define ssh_h

#include "TCP.h"
#include "ContentLine.h"

class SSH_Analyzer : public TCP_ApplicationAnalyzer {
public:
	SSH_Analyzer(Connection* conn);

	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SSH_Analyzer(conn); }

private:
	ContentLine_Analyzer* orig;
	ContentLine_Analyzer* resp;
};

#endif
