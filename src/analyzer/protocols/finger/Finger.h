// See the file "COPYING" in the main distribution directory for copyright.

#ifndef finger_h
#define finger_h

#include "analyzer/protocols/tcp/TCP.h"
#include "analyzer/protocols/tcp/ContentLine.h"

namespace analyzer { namespace finger {

class Finger_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	Finger_Analyzer(Connection* conn);
	virtual ~Finger_Analyzer()	{}

	virtual void Done();
	// Line-based input.
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Finger_Analyzer(conn); }

protected:
	tcp::ContentLine_Analyzer* content_line_orig;
	tcp::ContentLine_Analyzer* content_line_resp;
	int did_deliver;
};

} } // namespace analyzer::* 

#endif
