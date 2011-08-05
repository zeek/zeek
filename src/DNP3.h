// $Id:$
//
// This template code contributed by Kristin Stephens.

#ifndef dnp3_h
#define dnp3_h

#include "TCP.h"

#include "dnp3_pac.h"

class DNP3_Analyzer : public TCP_ApplicationAnalyzer {
public:
	DNP3_Analyzer(Connection* conn);
	virtual ~DNP3_Analyzer();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(TCP_Reassembler* endp);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new DNP3_Analyzer(conn); }

	// Put event names in this function
	static bool Available()
		{ return dnp3_application_request_header || dnp3_object_header ; }

protected:
	binpac::Dnp3::Dnp3_Conn* interp;
};

#endif
