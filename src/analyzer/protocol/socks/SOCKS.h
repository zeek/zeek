#pragma once

// SOCKS v4 analyzer.

#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/pia/PIA.h"

namespace binpac  {
   namespace SOCKS {
	   class SOCKS_Conn;
   }
}

namespace analyzer { namespace socks {

class SOCKS_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit SOCKS_Analyzer(zeek::Connection* conn);
	~SOCKS_Analyzer() override;

	void EndpointDone(bool orig);

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new SOCKS_Analyzer(conn); }

protected:

	bool orig_done;
	bool resp_done;

	zeek::analyzer::pia::PIA_TCP *pia;
	binpac::SOCKS::SOCKS_Conn* interp;
};

} } // namespace analyzer::*
