// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/IPAddr.h"

#include "analyzer/protocol/dce-rpc/events.bif.h"
#include "analyzer/protocol/dce-rpc/dce_rpc_pac.h"

namespace zeek::analyzer::dce_rpc {

class DCE_RPC_Analyzer final : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit DCE_RPC_Analyzer(Connection* conn);
	~DCE_RPC_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	bool SetFileID(uint64_t fid_in)
		{ interp->set_file_id(fid_in); return true; }

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DCE_RPC_Analyzer(conn); }

protected:
	bool had_gap;
	binpac::DCE_RPC::DCE_RPC_Conn* interp;
};

} // namespace zeek::analyzer::dce_rpc
