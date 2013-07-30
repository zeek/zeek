// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_ZIP_ZIP_H
#define ANALYZER_PROTOCOL_ZIP_ZIP_H

#include "config.h"

#include "zlib.h"
#include "analyzer/protocol/tcp/TCP.h"

namespace analyzer { namespace zip {

class ZIP_Analyzer : public tcp::TCP_SupportAnalyzer {
public:
	enum Method { GZIP, DEFLATE };

	ZIP_Analyzer(Connection* conn, bool orig, Method method = GZIP);
	~ZIP_Analyzer();

	virtual void Done();

	virtual void DeliverStream(int len, const u_char* data, bool orig);

protected:
	enum { NONE, ZIP_OK, ZIP_FAIL };
	z_stream* zip;
	int zip_status;
	Method method;
};

} } // namespace analyzer::* 

#endif
