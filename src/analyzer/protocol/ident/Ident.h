// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"

namespace analyzer { namespace ident {

class Ident_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit Ident_Analyzer(Connection* conn);
	void Done() override;

	void DeliverStream(int length, const u_char* data, bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
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

	bool did_deliver;
	bool did_bad_reply;
};

} } // namespace analyzer::*
