// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/dce-rpc/events.bif.h"
#include "IPAddr.h"

#include "dce_rpc_pac.h"

namespace zeek::analyzer::dce_rpc {

class DCE_RPC_Analyzer final : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	explicit DCE_RPC_Analyzer(zeek::Connection* conn);
	~DCE_RPC_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	bool SetFileID(uint64_t fid_in)
		{ interp->set_file_id(fid_in); return true; }

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new DCE_RPC_Analyzer(conn); }

protected:
	bool had_gap;
	binpac::DCE_RPC::DCE_RPC_Conn* interp;
};

} // namespace zeek::analyzer::dce_rpc

namespace analyzer::dce_rpc {
	using DCE_RPC_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::dce_rpc::DCE_RPC_Analyzer.")]] = zeek::analyzer::dce_rpc::DCE_RPC_Analyzer;
}
