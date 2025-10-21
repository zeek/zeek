// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UDP {

class UDPSessionAdapter final : public IP::SessionAdapter {
public:
    UDPSessionAdapter(Connection* conn) : IP::SessionAdapter("UDP", conn) {}

    void AddExtraAnalyzers(Connection* conn) override;

    void UpdateLength(bool is_orig, int len);
    void HandleBadChecksum(bool is_orig);

    // For tracking checksum history. These are connection-specific so they
    // need to be stored in the session adapter created for each connection.
    uint32_t req_chk_cnt = 0;
    uint32_t req_chk_thresh = 1;
    uint32_t rep_chk_cnt = 0;
    uint32_t rep_chk_thresh = 1;

private:
    void ChecksumEvent(bool is_orig, uint32_t threshold);

    zeek_uint_t GetEndpointSize(bool is_orig) const override;
    zeek_uint_t GetEndpointState(bool is_orig) const override;

    zeek_int_t request_len = -1;
    zeek_int_t reply_len = -1;
};

} // namespace zeek::packet_analysis::UDP
