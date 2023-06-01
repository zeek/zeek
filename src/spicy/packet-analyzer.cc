// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/spicy/packet-analyzer.h"

#include "zeek/spicy/manager.h"
#include "zeek/spicy/runtime-support.h"

using namespace zeek;
using namespace zeek::spicy;
using namespace zeek::spicy::rt;

#ifdef DEBUG
#define STATE_DEBUG_MSG(...) DebugMsg(__VA_ARGS__)
#else
#define STATE_DEBUG_MSG(...)
#endif

void PacketState::debug(const std::string& msg) { spicy::rt::debug(_cookie, msg); }

static auto create_packet_state(PacketAnalyzer* analyzer) {
    cookie::PacketAnalyzer cookie;
    cookie.analyzer = analyzer;
    return PacketState(std::move(cookie));
}

PacketAnalyzer::PacketAnalyzer(std::string name)
    : packet_analysis::Analyzer(std::move(name)), _state(create_packet_state(this)) {}

PacketAnalyzer::~PacketAnalyzer() = default;

bool PacketAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    if ( auto parser = spicy_mgr->parserForPacketAnalyzer(_state.packet().analyzer->GetAnalyzerTag()) )
        _state.setParser(parser);
    else
        reporter->FatalError("no valid unit specified for parsing");

    try {
        hilti::rt::context::CookieSetter _(_state.cookie());
        _state.packet().next_analyzer.reset();
        _state.packet().packet = packet;
        _state.process(len, reinterpret_cast<const char*>(data));
        auto offset = _state.finish();
        assert(offset);
        _state.packet().packet = nullptr;
        _state.packet().packet_val = nullptr;
        _state.reset();
        auto num_processed = offset->Ref();
        const auto& next_analyzer = _state.packet().next_analyzer;
        STATE_DEBUG_MSG(hilti::rt::fmt("processed %" PRIu64 " out of %" PRIu64 " bytes, %s", num_processed, len,
                                       (next_analyzer ? hilti::rt::fmt("next analyzer is 0x%" PRIx32, *next_analyzer) :
                                                        std::string("no next analyzer"))));
        if ( next_analyzer )
            return ForwardPacket(len - num_processed, data + num_processed, packet, *next_analyzer);
        else
            return true;
    } catch ( const hilti::rt::RuntimeError& e ) {
        STATE_DEBUG_MSG(hilti::rt::fmt("error during parsing, triggering analyzer violation: %s", e.what()));
        auto tag = _state.packet().analyzer->GetAnalyzerTag();

        if ( auto* session = packet->session )
            _state.packet().analyzer->AnalyzerViolation(e.what(), session, reinterpret_cast<const char*>(data), len,
                                                        tag);

        _state.reset();
        return false;
    } catch ( const hilti::rt::Exception& e ) {
        STATE_DEBUG_MSG(e.what());
        spicy_mgr->analyzerError(_state.packet().analyzer, e.description(),
                                 e.location()); // this sets Zeek to skip sending any further input
        _state.reset();
        return false;
    }
}
