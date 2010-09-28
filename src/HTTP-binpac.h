// $Id:$

#ifndef http_binpac_h
#define http_binpac_h

#include "TCP.h"

#include "http_pac.h"

class HTTP_Analyzer_binpac : public TCP_ApplicationAnalyzer {
public:
	HTTP_Analyzer_binpac(Connection* conn);
	virtual ~HTTP_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new HTTP_Analyzer_binpac(conn); }

	static bool Available()
		{ return (http_request || http_reply) && FLAGS_use_binpac; }

protected:
	binpac::HTTP::HTTP_Conn* interp;
};

#endif
