// $Id:$
//
// This template code contributed by Kristin Stephens.

#ifndef dnp3tcp_h
#define dnp3tcp_h

#include "TCP.h"

#include "dnp3-tcp_pac.h"

class DNP3TCP_Analyzer : public TCP_ApplicationAnalyzer {
public:
	DNP3TCP_Analyzer(Connection* conn);
	virtual ~DNP3TCP_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DNP3TCP_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return sample_message; }

protected:
	binpac::Dnp3TCP::Dnp3TCP_Conn* interp;
};

#endif
