// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/stream_event/StreamEvent.h"

#include "zeek/analyzer/protocol/stream_event/events.bif.h"

namespace zeek::analyzer::stream_event {

StreamEvent_Analyzer::StreamEvent_Analyzer(Connection* conn)
    : analyzer::tcp::TCP_ApplicationAnalyzer("STREAM_EVENT", conn) {}


void StreamEvent_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

    auto s = len > 0 ? zeek::make_intrusive<StringVal>(len, reinterpret_cast<const char*>(data)) :
                       zeek::val_mgr->EmptyString();

    BifEvent::enqueue_stream_deliver(this, Conn(), orig, std::move(s));
}
void StreamEvent_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

    BifEvent::enqueue_stream_undelivered(this, Conn(), orig, seq, len);
}

} // namespace zeek::analyzer::stream_event
