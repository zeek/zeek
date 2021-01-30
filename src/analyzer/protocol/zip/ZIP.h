// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <zlib.h>

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::zip {

class ZIP_Analyzer final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
	enum Method { GZIP, DEFLATE };

	ZIP_Analyzer(Connection* conn, bool orig, Method method = GZIP);
	~ZIP_Analyzer() override;

	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;

protected:
	enum { NONE, ZIP_OK, ZIP_FAIL };
	z_stream* zip;
	int zip_status;
	Method method;
};

} // namespace zeek::analyzer::zip
