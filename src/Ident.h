// $Id: Ident.h 6219 2008-10-01 05:39:07Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ident_h
#define ident_h

#include "TCP.h"
#include "ContentLine.h"

class Ident_Analyzer : public TCP_ApplicationAnalyzer {
public:
	Ident_Analyzer(Connection* conn);
	virtual void Done();

	virtual void DeliverStream(int length, const u_char* data, bool is_orig);
	virtual int RewritingTrace()
		{
		return rewriting_ident_trace ||
			TCP_ApplicationAnalyzer::RewritingTrace();
		}

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Ident_Analyzer(conn); }

	static bool Available()
		{ return ident_request || ident_reply || ident_error; }

protected:
	const char* ParsePair(const char* line, const char* end_of_line,
				int& p1, int &p2);
	const char* ParsePort(const char* line, const char* end_of_line,
				int& pn);

	void BadRequest(int length, const char* line);
	void BadReply(int length, const char* line);

	ContentLine_Analyzer* orig_ident;
	ContentLine_Analyzer* resp_ident;

	unsigned int did_deliver:1;
	unsigned int did_bad_reply:1;
};

#endif
