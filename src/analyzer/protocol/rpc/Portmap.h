// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "RPC.h"

namespace zeek::analyzer::rpc {
namespace detail {

class PortmapperInterp : public RPC_Interpreter {
public:
	explicit PortmapperInterp(zeek::analyzer::Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) { }

protected:
	bool RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) override;
	bool RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success,
			   const u_char*& buf, int& n, double start_time,
			   double last_time, int reply_len) override;
	uint32_t CheckPort(uint32_t port);

	void Event(zeek::EventHandlerPtr f, zeek::ValPtr request, BifEnum::rpc_status status, zeek::ValPtr reply);

	zeek::ValPtr ExtractMapping(const u_char*& buf, int& len);
	zeek::ValPtr ExtractPortRequest(const u_char*& buf, int& len);
	zeek::ValPtr ExtractCallItRequest(const u_char*& buf, int& len);
};

} // namespace detail

class Portmapper_Analyzer : public RPC_Analyzer {
public:
	explicit Portmapper_Analyzer(zeek::Connection* conn);
	~Portmapper_Analyzer() override;
	void Init() override;

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new Portmapper_Analyzer(conn); }
};

} // namespace zeek::analyzer::detail

namespace analyzer::rpc {

using PortmapperInterp [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::detail::PortmapperInterp.")]] = zeek::analyzer::rpc::detail::PortmapperInterp;
using Portmapper_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::rpc::Portmapper_Analyzer.")]] = zeek::analyzer::rpc::Portmapper_Analyzer;

} // namespace analyzer::rpc
