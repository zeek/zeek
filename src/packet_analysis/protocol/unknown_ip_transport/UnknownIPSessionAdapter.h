// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

namespace zeek::packet_analysis::UnknownIPTransport {

class UnknownIPSessionAdapter final : public IP::SessionAdapter {
public:
    UnknownIPSessionAdapter(Connection* conn) : IP::SessionAdapter("Unknown_IP_Transport", conn) {}

    void AddExtraAnalyzers(Connection* conn) override;

    void UpdateConnVal(RecordVal* conn_val) override {
        // Noop - do not install EndpointCallback into conn_val.
        // This keeps endpoint$state and endpoint$size unset
        // optionals.
        for ( Analyzer* a : GetChildren() )
            a->UpdateConnVal(conn_val);
    }

    zeek_uint_t GetEndpointSize(bool is_orig) const override {
        reporter->InternalError("GetEndpointSize() called on UnknownIPSessionAdapter");
        return 0;
    }

    zeek_uint_t GetEndpointState(bool is_orig) const override {
        reporter->InternalError("GetEndpointState() called on UnknownIPSessionAdapter");
        return 0;
    }
};

} // namespace zeek::packet_analysis::UnknownIPTransport
