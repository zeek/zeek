// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/RuleMatcher.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::ICMP {

class ICMPSessionAdapter final : public IP::SessionAdapter {
public:
    ICMPSessionAdapter(Connection* conn) : IP::SessionAdapter("ICMP", conn) {}

    void AddExtraAnalyzers(Connection* conn) override;

    void UpdateLength(bool is_orig, int len);
    void Done() override;

    void InitEndpointMatcher(const IP_Hdr* ip_hdr, int len, bool is_orig);
    void MatchEndpoint(const u_char* data, int len, bool is_orig);

private:
    zeek_uint_t GetEndpointSize(bool is_orig) const override;
    zeek_uint_t GetEndpointState(bool is_orig) const override;

    zeek::detail::RuleMatcherState matcher_state;
    int request_len = -1;
    int reply_len = -1;
};

} // namespace zeek::packet_analysis::ICMP
