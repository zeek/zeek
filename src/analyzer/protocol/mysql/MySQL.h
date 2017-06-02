// See the file "COPYING" in the main distribution directory for copyright.

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

	void Done() override;
  void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

  void StartTLS();

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new MySQL_Analyzer(conn); }

protected:
	std::unique_ptr<binpac::MySQL::MySQL_Conn> interp;
	bool had_gap;

  bool tls_active;
};

} } // namespace analyzer::*

#endif
