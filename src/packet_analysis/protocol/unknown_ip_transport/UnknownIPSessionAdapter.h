// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UnknownIPTransport {

class UnknownIPSessionAdapter final : public IP::SessionAdapter {
public:
    UnknownIPSessionAdapter(Connection* conn) : IP::SessionAdapter("Unknown_IP_Transport", conn) {}

    void AddExtraAnalyzers(Connection* conn) override;
};

} // namespace zeek::packet_analysis::UnknownIPTransport
