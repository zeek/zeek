// See the file "COPYING" in the main distribution directory for copyright.

#ifndef finger_h
#define finger_h

#include "TCP.h"

class ContentLine_Analyzer;

class Finger_Analyzer : public TCP_ApplicationAnalyzer {
public:
	Finger_Analyzer(Connection* conn);
	virtual ~Finger_Analyzer()	{}

	virtual void Done();
	// Line-based input.
	virtual void DeliverStream(int len, const u_char* data, bool orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Finger_Analyzer(conn); }

	static bool Available()	{ return finger_request || finger_reply; }

protected:
	ContentLine_Analyzer* content_line_orig;
	ContentLine_Analyzer* content_line_resp;
	int did_deliver;
};

#endif
