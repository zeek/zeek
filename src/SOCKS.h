#ifndef socks_h
#define socks_h

// SOCKS v4 analyzer.

#include "TCP.h"
#include "PIA.h"

namespace binpac  {
   namespace SOCKS {
	   class SOCKS_Conn;
   }
}


class SOCKS_Analyzer : public TCP_ApplicationAnalyzer {
public:
	SOCKS_Analyzer(Connection* conn);
	~SOCKS_Analyzer();

	void EndpointDone(bool orig);

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new SOCKS_Analyzer(conn); }

	static bool Available()
		{
		return socks_request || socks_reply;
		}

protected:

	bool orig_done;
	bool resp_done;

	PIA_TCP *pia;
	binpac::SOCKS::SOCKS_Conn* interp;
};

#endif
