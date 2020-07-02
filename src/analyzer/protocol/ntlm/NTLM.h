// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "events.bif.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "ntlm_pac.h"

namespace analyzer { namespace ntlm {

class NTLM_Analyzer final : public tcp::TCP_ApplicationAnalyzer {

public:
	explicit NTLM_Analyzer(Connection* conn);
	~NTLM_Analyzer() override;

	// Overriden from Analyzer.
	void Done() override;

	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;

	// Overriden from tcp::TCP_ApplicationAnalyzer.
	void EndpointEOF(bool is_orig) override;

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new NTLM_Analyzer(conn); }

protected:
	binpac::NTLM::NTLM_Conn* interp;
};

} } // namespace analyzer::*
