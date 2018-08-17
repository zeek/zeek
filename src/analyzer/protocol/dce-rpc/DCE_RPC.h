// See the file "COPYING" in the main distribution directory for copyright.

#ifndef ANALYZER_PROTOCOL_DCE_RPC_DCE_RPC_H
#define ANALYZER_PROTOCOL_DCE_RPC_DCE_RPC_H

#include "NetVar.h"
#include "analyzer/protocol/tcp/TCP.h"
#include "analyzer/protocol/dce-rpc/events.bif.h"
#include "IPAddr.h"

#include "dce_rpc_pac.h"

namespace analyzer { namespace dce_rpc {

class DCE_RPC_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit DCE_RPC_Analyzer(Connection* conn);
	~DCE_RPC_Analyzer() override;

	void Done() override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64 seq, int len, bool orig) override;
	void EndpointEOF(bool is_orig) override;

	bool SetFileID(uint64 fid_in)
		{ interp->set_file_id(fid_in); return true; }

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new DCE_RPC_Analyzer(conn); }

protected:
	bool had_gap;
	binpac::DCE_RPC::DCE_RPC_Conn* interp;
};

} } // namespace analyzer::*

#endif /* dce_rpc_h */
