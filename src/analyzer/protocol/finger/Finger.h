// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/tcp/ContentLine.h"

namespace zeek::analyzer::finger {

class Finger_Analyzer : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit Finger_Analyzer(zeek::Connection* conn);
	~Finger_Analyzer() override {}

	void Done() override;
	// Line-based input.
	void DeliverStream(int len, const u_char* data, bool orig) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new Finger_Analyzer(conn); }

protected:
	zeek::analyzer::tcp::ContentLine_Analyzer* content_line_orig;
	zeek::analyzer::tcp::ContentLine_Analyzer* content_line_resp;
	int did_deliver;
};

} // namespace zeek::analyzer::finger

namespace analyzer::finger {

	using Finger_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::finger::Finger_Analyzer.")]] = zeek::analyzer::finger::Finger_Analyzer;

} // namespace analyzer::finger
