// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_ZIP_ZIP_H
#define ANALYZER_PROTOCOL_ZIP_ZIP_H

#include "zeek-config.h"

#include "zlib.h"
#include "analyzer/protocol/tcp/TCP.h"

namespace analyzer { namespace zip {

class ZIP_Analyzer : public tcp::TCP_SupportAnalyzer {
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

} } // namespace analyzer::* 

#endif
