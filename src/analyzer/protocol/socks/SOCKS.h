#ifndef ANALYZER_PROTOCOL_SOCKS_SOCKS_H
#define ANALYZER_PROTOCOL_SOCKS_SOCKS_H

// SOCKS v4 analyzer.

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"

namespace binpac  {
   namespace SOCKS {
	   class SOCKS_Conn;
   }
}

namespace analyzer { namespace socks {

class SOCKS_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit SOCKS_Analyzer(Connection* conn);
	~SOCKS_Analyzer() override;

	void EndpointDone(bool orig);

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new SOCKS_Analyzer(conn); }

protected:

	bool orig_done;
	bool resp_done;

	pia::PIA_TCP *pia;
	binpac::SOCKS::SOCKS_Conn* interp;
};

} } // namespace analyzer::* 

#endif
