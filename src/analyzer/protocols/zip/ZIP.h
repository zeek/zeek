// See the file "COPYING" in the main distribution directory for copyright.

#ifndef zip_h
#define zip_h

#include "config.h"

#include "zlib.h"
#include "analyzer/protocols/tcp/TCP.h"

class ZIP_Analyzer : public TCP_SupportAnalyzer {
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

#endif
