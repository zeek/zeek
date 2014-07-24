#ifndef ANALYZER_PROTOCOL_MYSQL_MYSQL_H
#define ANALYZER_PROTOCOL_MYSQL_MYSQL_H

#include "events.bif.h"


#include "analyzer/protocol/tcp/TCP.h"

#include "mysql_pac.h"

namespace analyzer { namespace MySQL {

class MySQL_Analyzer

: public tcp::TCP_ApplicationAnalyzer {

public:
	MySQL_Analyzer(Connection* conn);
	virtual ~MySQL_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(uint64 seq, int len, bool orig);

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	virtual void EndpointEOF(bool is_orig);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new MySQL_Analyzer(conn); }

	static bool Available()
		{
		return ( mysql_command_response || mysql_server_version || mysql_debug || mysql_handshake_response || mysql_login || mysql_command_request );
		}

protected:
	binpac::MySQL::MySQL_Conn* interp;
	
	bool had_gap;
	
};

} } // namespace analyzer::* 

#endif
