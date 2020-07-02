// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/dce-rpc/events.bif.h"
#include "IPAddr.h"

#include "dce_rpc_pac.h"

namespace analyzer { namespace dce_rpc {

class DCE_RPC_Analyzer final : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit DCE_RPC_Analyzer(Connection* conn);
	~DCE_RPC_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	bool SetFileID(uint64_t fid_in)
		{ interp->set_file_id(fid_in); return true; }

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DCE_RPC_Analyzer(conn); }

protected:
	bool had_gap;
	binpac::DCE_RPC::DCE_RPC_Conn* interp;
};

} } // namespace analyzer::*
