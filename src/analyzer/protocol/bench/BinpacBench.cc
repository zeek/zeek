#include "zeek/analyzer/protocol/bench/BinpacBench.h"

#include "zeek/analyzer/protocol/bench/events.bif.h"
#include "zeek/analyzer/protocol/tcp/TCP_Reassembler.h"

namespace zeek::analyzer::bench {

BinpacBench_Analyzer::BinpacBench_Analyzer(Connection* conn)
    : analyzer::tcp::TCP_ApplicationAnalyzer("BINPAC_BENCH", conn) {
    interp = new binpac::BinpacBench::Bench_Conn(this);
}

BinpacBench_Analyzer::~BinpacBench_Analyzer() { delete interp; }

void BinpacBench_Analyzer::Done() { Analyzer::Done(); }

void BinpacBench_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    Analyzer::DeliverStream(len, data, orig);
    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(util::fmt("Binpac exception: %s", e.c_msg()));
    }
}


} // namespace zeek::analyzer::bench
