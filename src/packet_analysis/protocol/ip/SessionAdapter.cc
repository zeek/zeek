// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

#include "zeek/File.h"
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

using namespace zeek::packet_analysis::IP;

void SessionAdapter::Done() {
    Analyzer::Done();
    for ( const auto& ta : tap_analyzers )
        ta->Done();

    // Ensure no more TapPacket() calls after Done() on TapAnalyzer instances.
    tap_analyzers.clear();
}

bool SessionAdapter::IsReuse(double t, const u_char* pkt) { return parent->IsReuse(t, pkt); }

void SessionAdapter::SetContentsFile(unsigned int /* direction */, FilePtr /* f */) {
    reporter->Error("analyzer type does not support writing to a contents file");
}

zeek::FilePtr SessionAdapter::GetContentsFile(unsigned int /* direction */) const {
    reporter->Error("analyzer type does not support writing to a contents file");
    return nullptr;
}

void SessionAdapter::PacketContents(const u_char* data, int len) {
    if ( packet_contents && len > 0 ) {
        zeek::String* cbs = new zeek::String(data, len, true);
        auto contents = make_intrusive<StringVal>(cbs);
        EnqueueConnEvent(packet_contents, ConnVal(), std::move(contents));
    }
}

void SessionAdapter::AddTapAnalyzer(TapAnalyzerPtr ta) {
    assert(! IsFinished());
    tap_analyzers.push_back(std::move(ta));
    tap_analyzers.back()->Init();
}

bool SessionAdapter::RemoveTapAnalyzer(const TapAnalyzer* ta) {
    // Find the raw pointer, call Done(), remove it, thereby destructing it.
    for ( auto it = tap_analyzers.begin(); it != tap_analyzers.end(); ++it ) {
        if ( it->get() == ta ) {
            // Ensure Done() is called only after removal from tap_analyzers.
            auto ptr{std::move(*it)};
            tap_analyzers.erase(it);
            ptr->Done();
            ptr.reset();
            return true;
        }
    }

    return false;
}

void SessionAdapter::TapPacket(const Packet* pkt, PacketAction action, SkipReason skip_reason) const {
    for ( const auto& ta : tap_analyzers )
        ta->TapPacket(*pkt, action, skip_reason);
}

void SessionAdapter::UpdateConnVal(RecordVal* conn_val) {
    Analyzer::UpdateConnVal(conn_val);

    for ( const auto& ta : tap_analyzers )
        ta->UpdateConnVal(conn_val);
}
