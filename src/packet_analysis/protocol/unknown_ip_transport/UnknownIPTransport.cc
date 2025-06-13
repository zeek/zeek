// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/unknown_ip_transport/UnknownIPTransport.h"

#include "zeek/Conn.h"
#include "zeek/RunState.h"
#include "zeek/packet_analysis/protocol/unknown_ip_transport/UnknownIPSessionAdapter.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::UnknownIPTransport;
using namespace zeek::packet_analysis::IP;

UnknownIPTransportAnalyzer::UnknownIPTransportAnalyzer()
    : IPBasedAnalyzer("Unknown_IP_Transport", TRANSPORT_UNKNOWN, 0 /*mask*/, true) {}

bool UnknownIPTransportAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    IPBasedAnalyzer::AnalyzePacket(len, data, packet);

    packet->processed = false;

    if ( report_unknown_protocols )
        packet_mgr->ReportUnknownProtocol(GetAnalyzerName(), htons(packet->ip_hdr->NextProto()), data, len);

    return false;
}

SessionAdapter* UnknownIPTransportAnalyzer::MakeSessionAdapter(Connection* conn) {
    auto* root = new UnknownIPSessionAdapter(conn);
    root->SetParent(this);

    conn->SetInactivityTimeout(zeek::detail::unknown_ip_inactivity_timeout);

    return root;
}

bool UnknownIPTransportAnalyzer::InitConnKey(size_t len, const uint8_t* data, Packet* packet, IPBasedConnKey& key) {
    key.InitTuple(packet->ip_hdr->SrcAddr(), 0, packet->ip_hdr->DstAddr(), 0, packet->proto);

    return true;
}

void UnknownIPTransportAnalyzer::DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) {
    auto* adapter = static_cast<UnknownIPSessionAdapter*>(c->GetSessionAdapter());

    const u_char* data = pkt->ip_hdr->Payload();
    int len = pkt->ip_hdr->PayloadLen();
    // If segment offloading or similar is enabled, the payload len will return 0.
    // Thus, let's ignore that case.
    if ( len == 0 )
        len = remaining;

    if ( packet_contents && len > 0 )
        adapter->PacketContents(data + 8, std::min(len, remaining) - 8);

    c->SetLastTime(run_state::current_timestamp);

    const std::shared_ptr<IP_Hdr>& ip = pkt->ip_hdr;
    adapter->ForwardPacket(std::min(len, remaining), data, is_orig, -1, ip.get(), pkt->cap_len);

    // Dnn't forward from here back into the packet_analysis framework. The protocol identifier
    // that lead analysis to this analyzer should be handled by the IP analyzer if it's valid,
    // instead of being passed along from this analyzer.
}
