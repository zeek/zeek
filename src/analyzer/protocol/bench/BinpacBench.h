#pragma once

#include "zeek/analyzer/protocol/tcp/TCP.h"

#include "analyzer/protocol/bench/bench_pac.h"

namespace zeek::analyzer::bench {

class BinpacBench_Analyzer : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
    explicit BinpacBench_Analyzer(Connection* conn);
    ~BinpacBench_Analyzer() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;
    void Done() override;

    static analyzer::Analyzer* Instantiate(Connection* conn) { return new BinpacBench_Analyzer(conn); }

protected:
    binpac::BinpacBench::Bench_Conn* interp;
};

} // namespace zeek::analyzer::bench
