// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek {

class VectorVal;
using VectorValPtr = IntrusivePtr<VectorVal>;
class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace packet_analysis::ICMP {

class ICMPSessionAdapter;

class ICMPAnalyzer final : public IP::IPBasedAnalyzer {
public:
    ICMPAnalyzer();
    ~ICMPAnalyzer() override = default;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<ICMPAnalyzer>(); }

    packet_analysis::IP::SessionAdapter* MakeSessionAdapter(Connection* conn) override;

protected:
    bool InitConnKey(size_t len, const uint8_t* data, Packet* packet, IPBasedConnKey& key) override;

    void DeliverPacket(Connection* c, double t, bool is_orig, int remaining, Packet* pkt) override;

private:
    void NextICMP4(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr,
                   ICMPSessionAdapter* adapter);

    void NextICMP6(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr,
                   ICMPSessionAdapter* adapter);

    void ICMP_Sent(const struct icmp* icmpp, int len, int caplen, int icmpv6, const u_char* data, const IP_Hdr* ip_hdr,
                   ICMPSessionAdapter* adapter);

    void Echo(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr,
              ICMPSessionAdapter* adapter);
    void Redirect(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr,
                  ICMPSessionAdapter* adapter);
    void RouterAdvert(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                      const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter);
    void NeighborAdvert(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                        const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter);
    void NeighborSolicit(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                         const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter);
    void RouterSolicit(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data,
                       const IP_Hdr* ip_hdr, ICMPSessionAdapter* adapter);

    RecordValPtr BuildInfo(const struct icmp* icmpp, int len, bool icmpv6, const IP_Hdr* ip_hdr);

    RecordValPtr ExtractICMP4Context(int len, const u_char*& data);

    void Context4(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr,
                  ICMPSessionAdapter* adapter);

    TransportProto GetContextProtocol(const IP_Hdr* ip_hdr, uint32_t* src_port, uint32_t* dst_port);

    RecordValPtr ExtractICMP6Context(int len, const u_char*& data);

    void Context6(double t, const struct icmp* icmpp, int len, int caplen, const u_char*& data, const IP_Hdr* ip_hdr,
                  ICMPSessionAdapter* adapter);

    // RFC 4861 Neighbor Discover message options
    VectorValPtr BuildNDOptionsVal(int caplen, const u_char* data, ICMPSessionAdapter* adapter);

    void UpdateEndpointVal(const ValPtr& endp, bool is_orig);
};

// Returns the counterpart type to the given type (e.g., the counterpart
// to ICMP_ECHOREPLY is ICMP_ECHO).
extern int ICMP4_counterpart(int icmp_type, int icmp_code, bool& is_one_way);
extern int ICMP6_counterpart(int icmp_type, int icmp_code, bool& is_one_way);

} // namespace packet_analysis::ICMP
} // namespace zeek
