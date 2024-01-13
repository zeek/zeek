// See the file  in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/websocket/WebSocket.h"

#include <string_view>

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/websocket/events.bif.h"

namespace zeek::analyzer::websocket {

WebSocket_Analyzer::WebSocket_Analyzer(Connection* conn) : analyzer::tcp::TCP_ApplicationAnalyzer("WebSocket", conn) {
    // TODO: Consider approaches dispatching to optionally use a
    // Spicy analyzer here instead of the BinPac interpreter.
    //
    // E.g. we could instantiate a SPICY_WEBSOCKET analyzer and pass it the necessary
    // information and call DeliverStream() directly on it.
    interp = std::make_unique<binpac::WebSocket::WebSocket_Conn>(this);
}

void WebSocket_Analyzer::Init() {
    tcp::TCP_ApplicationAnalyzer::Init();

    // This event calls back via Configure()
    zeek::BifEvent::enqueue_websocket_handshake(this, Conn(), GetID());
}

bool WebSocket_Analyzer::Configure(zeek::RecordValPtr config) {
    // TODO: Check extensions and modify parsing if needed, e.g. WebSocket frame
    // compression extension: https://www.rfc-editor.org/rfc/rfc7692.html
    //
    // interp->SetExtensions(...)
    //
    // TODO: The Sec-WebSocket-Protocol header might provide some information
    // that we could leverage to instantiate a more specific analyzer.
    //
    // For now, we just attach a PIA analyzer as child analyzer.

    static const auto& config_type = id::find_type<zeek::RecordType>("WebSocket::AnalyzerConfig");
    static int analyzer_idx = config_type->FieldOffset("analyzer");
    static int use_dpd_idx = config_type->FieldOffset("use_dpd");

    if ( config->HasField(analyzer_idx) ) {
        const auto& analyzer_tag_val = config->GetField(analyzer_idx);
        auto analyzer_tag = analyzer_mgr->GetComponentTag(analyzer_tag_val.get());

        if ( analyzer_tag == zeek::Tag() ) {
            reporter->InternalWarning("no component tag for enum '%s'",
                                      analyzer_tag_val->GetType<EnumType>()->Lookup(analyzer_tag_val->AsEnum()));
            return false;
        }

        DBG_LOG(DBG_ANALYZER, "%s Configure() using analyzer %s", fmt_analyzer(this).c_str(),
                analyzer_tag_val->GetType<EnumType>()->Lookup(analyzer_tag_val->AsEnum()));

        auto* analyzer = analyzer_mgr->InstantiateAnalyzer(analyzer_tag, Conn());
        if ( ! analyzer )
            return false;

        return AddChildAnalyzer(analyzer);
    }
    else if ( config->GetField(use_dpd_idx)->AsBool() ) {
        DBG_LOG(DBG_ANALYZER, "%s Configure() enables DPD via PIA_TCP", fmt_analyzer(this).c_str());

        auto* pia = new analyzer::pia::PIA_TCP(Conn());
        if ( AddChildAnalyzer(pia) ) {
            pia->FirstPacket(true, nullptr);
            pia->FirstPacket(false, nullptr);
            return true;
        }

        return false;
    }

    // Neither analyzer nor dpd was enabled, success.
    return true;
}


void WebSocket_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
    if ( had_gap ) {
        DBG_LOG(DBG_ANALYZER, "Skipping data after gap len=%d orig=%d", len, orig);
        return;
    }

    try {
        interp->NewData(orig, data, data + len);
    } catch ( const binpac::Exception& e ) {
        AnalyzerViolation(e.c_msg(), reinterpret_cast<const char*>(data), len);
    }
}

void WebSocket_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    interp->NewGap(orig, len);
    had_gap = true;
}

} // namespace zeek::analyzer::websocket
