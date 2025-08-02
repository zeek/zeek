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

    // Ensure no DeliverPacket() or SkippedPacket() calls after Done() on TapAnalyzer instances.
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

void SessionAdapter::AddTapAnalyzer(detail::TapAnalyzerPtr ta) { tap_analyzers.push_back(std::move(ta)); }

bool SessionAdapter::RemoveTapAnalyzer(const detail::TapAnalyzer* ta) {
    // Find the raw pointer, call Done(), remove it from the list, thereby destructing it.
    for ( auto it = tap_analyzers.begin(); it != tap_analyzers.end(); ++it ) {
        if ( it->get() == ta ) {
            (*it)->Done();
            tap_analyzers.remove(*it);
            return true;
        }
    }

    return false;
}

void SessionAdapter::TapPacket(const Packet* pkt) {
    for ( const auto& ta : tap_analyzers )
        ta->DeliverPacket(*pkt);
}
void SessionAdapter::TapSkippedPacket(const Packet* pkt, detail::SkipReason skip_reason) {
    for ( const auto& ta : tap_analyzers )
        ta->SkippedPacket(*pkt, skip_reason);
}
