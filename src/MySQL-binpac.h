#ifndef mysql_binpac_h
#define mysql_binpac_h

#include "TCP.h"
#include "mysql_pac.h"

class MySQL_Analyzer_binpac : public TCP_ApplicationAnalyzer {
public:
	MySQL_Analyzer_binpac(Connection* conn);
	virtual ~MySQL_Analyzer_binpac();

	virtual void Done();
	virtual void DeliverStream(int len, const u_char* data, bool orig);
	virtual void Undelivered(int seq, int len, bool orig);
	virtual void EndpointEOF(bool is_orig);

	static Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new MySQL_Analyzer_binpac(conn); }

	static bool Available()
		{ return (mysql_command_request || mysql_command_response || mysql_server_version || mysql_handshake_response || mysql_login); }

protected:
	binpac::MySQL::MySQL_Conn* interp;
	bool had_gap;
};

#endif
