// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/spicy/protocol-analyzer.h"

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

void EndpointState::debug(const std::string& msg) { spicy::rt::debug(_cookie, msg); }

static auto create_endpoint(bool is_orig, analyzer::Analyzer* analyzer, ::spicy::rt::driver::ParsingType type) {
    static uint64_t id_counter = 0;

    ++id_counter;

    cookie::ProtocolAnalyzer cookie{.analyzer = analyzer,
                                    .is_orig = is_orig,
                                    .fstate_orig =
                                        cookie::FileStateStack(hilti::rt::fmt("%" PRIx64 ".orig", id_counter)),
                                    .fstate_resp =
                                        cookie::FileStateStack(hilti::rt::fmt("%" PRIx64 ".resp", id_counter))};

    // Cannot get parser here yet, analyzer may not have been fully set up.
    return EndpointState(std::move(cookie), type);
}

ProtocolAnalyzer::ProtocolAnalyzer(analyzer::Analyzer* analyzer, ::spicy::rt::driver::ParsingType type)
    : _originator(create_endpoint(true, analyzer, type)), _responder(create_endpoint(false, analyzer, type)) {}

ProtocolAnalyzer::~ProtocolAnalyzer() {}

void ProtocolAnalyzer::Init() {}

void ProtocolAnalyzer::Done() {
    Finish(true);
    Finish(false);
}

void ProtocolAnalyzer::Process(bool is_orig, int len, const u_char* data) {
    auto* endp = is_orig ? &_originator : &_responder;

    if ( endp->protocol().analyzer->Skipping() )
        return;

    if ( ! endp->hasParser() && ! endp->isSkipping() ) {
        auto parser = spicy_mgr->parserForProtocolAnalyzer(endp->protocol().analyzer->GetAnalyzerTag(), is_orig);
        if ( parser ) {
            if ( ! _context )
                _context = parser->createContext();

            endp->setParser(parser, _context);
        }
        else {
            STATE_DEBUG_MSG(is_orig, "no unit specified for parsing");
            endp->skipRemaining();
            return;
        }
    }

    try {
        hilti::rt::context::CookieSetter _(endp->cookie());
        endp->process(len, reinterpret_cast<const char*>(data));
    } catch ( const hilti::rt::RuntimeError& e ) {
        STATE_DEBUG_MSG(is_orig, hilti::rt::fmt("error during parsing, triggering analyzer violation: %s", e.what()));
        auto tag = spicy_mgr->tagForProtocolAnalyzer(endp->protocol().analyzer->GetAnalyzerTag());
        endp->protocol().analyzer->AnalyzerViolation(e.what(), reinterpret_cast<const char*>(data), len, tag);
        originator().skipRemaining();
        responder().skipRemaining();
        endp->protocol().analyzer->SetSkip(true);
    } catch ( const hilti::rt::Exception& e ) {
        spicy_mgr->analyzerError(endp->protocol().analyzer, e.description(),
                                 e.location()); // this sets Zeek to skip sending any further input
    }
}

void ProtocolAnalyzer::Finish(bool is_orig) {
    auto* endp = is_orig ? &_originator : &_responder;

    if ( endp->protocol().analyzer->Skipping() )
        return;

    try {
        hilti::rt::context::CookieSetter _(endp->cookie());
        endp->finish();
    } catch ( const hilti::rt::RuntimeError& e ) {
        STATE_DEBUG_MSG(is_orig, hilti::rt::fmt("error during parsing, triggering analyzer violation: %s", e.what()));
        auto tag = spicy_mgr->tagForProtocolAnalyzer(endp->protocol().analyzer->GetAnalyzerTag());
        endp->protocol().analyzer->AnalyzerViolation(e.what(), nullptr, 0, tag);
        endp->skipRemaining();
    } catch ( const hilti::rt::Exception& e ) {
        spicy_mgr->analyzerError(endp->protocol().analyzer, e.description(),
                                 e.location()); // this sets Zeek to skip sending any further input
    }
}

cookie::ProtocolAnalyzer& ProtocolAnalyzer::cookie(bool is_orig) {
    if ( is_orig )
        return _originator.protocol();
    else
        return _responder.protocol();
}

void ProtocolAnalyzer::DebugMsg(bool is_orig, const std::string& msg) {
    if ( is_orig )
        _originator.DebugMsg(msg);
    else
        _responder.DebugMsg(msg);
}

void ProtocolAnalyzer::FlipRoles() { std::swap(_originator, _responder); }

analyzer::Analyzer* TCP_Analyzer::InstantiateAnalyzer(Connection* conn) { return new TCP_Analyzer(conn); }

TCP_Analyzer::TCP_Analyzer(Connection* conn)
    : ProtocolAnalyzer(this, ::spicy::rt::driver::ParsingType::Stream), analyzer::tcp::TCP_ApplicationAnalyzer(conn) {}

TCP_Analyzer::~TCP_Analyzer() {}

void TCP_Analyzer::Init() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Init();
    ProtocolAnalyzer::Init();
}

void TCP_Analyzer::Done() {
    analyzer::tcp::TCP_ApplicationAnalyzer::Done();
    ProtocolAnalyzer::Done();

    EndOfData(true);
    EndOfData(false);
}

void TCP_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, is_orig);

    Process(is_orig, len, data);

    if ( originator().isFinished() && responder().isFinished() &&
         (! originator().isSkipping() || ! responder().isSkipping()) ) {
        STATE_DEBUG_MSG(is_orig, "both endpoints finished, skipping all further TCP processing");
        originator().skipRemaining();
        responder().skipRemaining();

        if ( is_orig ) // doesn't really matter which endpoint here.
            originator().protocol().analyzer->SetSkip(true);
        else
            responder().protocol().analyzer->SetSkip(true);
    }
}

void TCP_Analyzer::Undelivered(uint64_t seq, int len, bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, is_orig);

    Process(is_orig, len, nullptr);
}

void TCP_Analyzer::EndOfData(bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::EndOfData(is_orig);

    if ( TCP() && TCP()->IsPartial() ) {
        STATE_DEBUG_MSG(is_orig, "skipping end-of-data delivery on partial TCP connection");
        return;
    }

    Finish(is_orig);
}

void TCP_Analyzer::FlipRoles() {
    analyzer::tcp::TCP_ApplicationAnalyzer::FlipRoles();
    ProtocolAnalyzer::FlipRoles();
}

void TCP_Analyzer::EndpointEOF(bool is_orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    Finish(is_orig);
}

void TCP_Analyzer::ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint, analyzer::tcp::TCP_Endpoint* peer,
                                    bool gen_event) {
    analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionClosed(endpoint, peer, gen_event);
}

void TCP_Analyzer::ConnectionFinished(bool half_finished) {
    analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionFinished(half_finished);
}

void TCP_Analyzer::ConnectionReset() { analyzer::tcp::TCP_ApplicationAnalyzer::ConnectionReset(); }

void TCP_Analyzer::PacketWithRST() { analyzer::tcp::TCP_ApplicationAnalyzer::PacketWithRST(); }

analyzer::Analyzer* UDP_Analyzer::InstantiateAnalyzer(Connection* conn) { return new UDP_Analyzer(conn); }

UDP_Analyzer::UDP_Analyzer(Connection* conn)
    : ProtocolAnalyzer(this, ::spicy::rt::driver::ParsingType::Block), analyzer::Analyzer(conn) {}

UDP_Analyzer::~UDP_Analyzer() {}

void UDP_Analyzer::Init() {
    analyzer::Analyzer::Init();
    ProtocolAnalyzer::Init();
}

void UDP_Analyzer::Done() {
    analyzer::Analyzer::Done();
    ProtocolAnalyzer::Done();
}

void UDP_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip,
                                 int caplen) {
    analyzer::Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

    ++cookie(is_orig).num_packets;
    Process(is_orig, len, data);
}

void UDP_Analyzer::Undelivered(uint64_t seq, int len, bool is_orig) {
    analyzer::Analyzer::Undelivered(seq, len, is_orig);
}

void UDP_Analyzer::EndOfData(bool is_orig) {
    analyzer::Analyzer::EndOfData(is_orig);
    Finish(is_orig);
}

void UDP_Analyzer::FlipRoles() {
    analyzer::Analyzer::FlipRoles();
    ProtocolAnalyzer::FlipRoles();
}
