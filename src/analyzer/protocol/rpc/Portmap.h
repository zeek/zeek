// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/protocol/rpc/RPC.h"

namespace zeek::analyzer::rpc {
namespace detail {

class PortmapperInterp : public RPC_Interpreter {
public:
    explicit PortmapperInterp(analyzer::Analyzer* arg_analyzer) : RPC_Interpreter(arg_analyzer) {}

protected:
    bool RPC_BuildCall(RPC_CallInfo* c, const u_char*& buf, int& n) override;
    bool RPC_BuildReply(RPC_CallInfo* c, BifEnum::rpc_status success, const u_char*& buf, int& n, double start_time,
                        double last_time, int reply_len) override;
    uint32_t CheckPort(uint32_t port);

    void Event(EventHandlerPtr f, ValPtr request, BifEnum::rpc_status status, ValPtr reply);

    RecordValPtr ExtractMapping(const u_char*& buf, int& len);
    RecordValPtr ExtractPortRequest(const u_char*& buf, int& len);
    RecordValPtr ExtractCallItRequest(const u_char*& buf, int& len);
};

} // namespace detail

class Portmapper_Analyzer : public RPC_Analyzer {
public:
    explicit Portmapper_Analyzer(Connection* conn);
    void Init() override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new Portmapper_Analyzer(conn); }
};

} // namespace zeek::analyzer::rpc
