// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_IDENT_IDENT_H
#define ANALYZER_PROTOCOL_IDENT_IDENT_H

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"

namespace analyzer { namespace ident {

class Ident_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	Ident_Analyzer(Connection* conn);
	virtual void Done();

	virtual void DeliverStream(int length, const u_char* data, bool is_orig);

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new Ident_Analyzer(conn); }

protected:
	const char* ParsePair(const char* line, const char* end_of_line,
				int& p1, int &p2);
	const char* ParsePort(const char* line, const char* end_of_line,
				int& pn);

	void BadRequest(int length, const char* line);
	void BadReply(int length, const char* line);

	tcp::ContentLine_Analyzer* orig_ident;
	tcp::ContentLine_Analyzer* resp_ident;

	unsigned int did_deliver:1;
	unsigned int did_bad_reply:1;
};

} } // namespace analyzer::* 

#endif
