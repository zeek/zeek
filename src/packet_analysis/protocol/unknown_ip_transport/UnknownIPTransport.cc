// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/unknown_ip_transport/UnknownIPTransport.h"

#include "zeek/Conn.h"
#include "zeek/RunState.h"
#include "zeek/packet_analysis/protocol/unknown_ip_transport/UnknownIPSessionAdapter.h"
#include "zeek/session/Manager.h"

using namespace zeek::packet_analysis::UnknownIPTransport;
using namespace zeek::packet_analysis::IP;

UnknownIPTransportAnalyzer::UnknownIPTransportAnalyzer()
    : IPBasedAnalyzer("Unknown_IP_Transport", TRANSPORT_UNKNOWN, 0 /*mask*/, false) {}

bool UnknownIPTransportAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    IPBasedAnalyzer::AnalyzePacket(len, data, packet);
    return false;
}

SessionAdapter* UnknownIPTransportAnalyzer::MakeSessionAdapter(Connection* conn) {
    auto* root = new UnknownIPSessionAdapter(conn);
    root->SetParent(this);

    conn->SetInactivityTimeout(zeek::detail::unknown_ip_inactivity_timeout);

    return root;
}

bool UnknownIPTransportAnalyzer::BuildConnTuple(size_t len, const uint8_t* data, Packet* packet, ConnTuple& tuple) {
    tuple.src_addr = packet->ip_hdr->SrcAddr();
    tuple.dst_addr = packet->ip_hdr->DstAddr();
    tuple.proto = TRANSPORT_UNKNOWN;

    // Unknown IP encodes the protocol identifier in the port field so it can be logged
    tuple.src_port = htons(uint16_t(packet->ip_hdr->NextProto()));
    tuple.dst_port = htons(uint16_t(packet->ip_hdr->NextProto()));

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

    ForwardPacket(std::min(len, remaining), data, pkt);

    const std::shared_ptr<IP_Hdr>& ip = pkt->ip_hdr;
    adapter->ForwardPacket(std::min(len, remaining), data, is_orig, -1, ip.get(), pkt->cap_len);
}
