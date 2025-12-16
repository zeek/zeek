// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/udp/UDPSessionAdapter.h"

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/conn-size/ConnSize.h"
#include "zeek/packet_analysis/protocol/udp/events.bif.h"

using namespace zeek::packet_analysis::UDP;
using namespace zeek::packet_analysis::IP;

enum UDP_EndpointState : uint8_t {
    UDP_INACTIVE, // no packet seen
    UDP_ACTIVE,   // packets seen
};

void UDPSessionAdapter::AddExtraAnalyzers(Connection* conn) {
    static zeek::Tag analyzer_connsize = analyzer_mgr->GetComponentTag("CONNSIZE");

    if ( analyzer_mgr->IsEnabled(analyzer_connsize) )
        // Add ConnSize analyzer. Needs to see packets, not stream.
        AddChildAnalyzer(new analyzer::conn_size::ConnSize_Analyzer(conn));
}

void UDPSessionAdapter::UpdateLength(bool is_orig, int len) {
    if ( is_orig ) {
        if ( request_len < 0 )
            request_len = len;
        else {
            request_len += len;
#ifdef DEBUG
            if ( request_len < 0 )
                reporter->Warning("wrapping around for UDP request length");
#endif
        }
    }
    else {
        if ( reply_len < 0 )
            reply_len = len;
        else {
            reply_len += len;
#ifdef DEBUG
            if ( reply_len < 0 )
                reporter->Warning("wrapping around for UDP reply length");
#endif
        }
    }
}

void UDPSessionAdapter::HandleBadChecksum(bool is_orig) {
    Weird("bad_UDP_checksum");

    if ( is_orig ) {
        uint32_t t = req_chk_thresh;

        if ( Conn()->ScaledHistoryEntry('C', req_chk_cnt, req_chk_thresh) )
            ChecksumEvent(is_orig, t);
    }
    else {
        uint32_t t = rep_chk_thresh;

        if ( Conn()->ScaledHistoryEntry('c', rep_chk_cnt, rep_chk_thresh) )
            ChecksumEvent(is_orig, t);
    }
}

void UDPSessionAdapter::ChecksumEvent(bool is_orig, uint32_t threshold) {
    Conn()->HistoryThresholdEvent(udp_multiple_checksum_errors, is_orig, threshold);
}

zeek_uint_t UDPSessionAdapter::GetEndpointSize(bool is_orig) const {
    zeek_int_t size = is_orig ? request_len : reply_len;
    // size may be negative if no data has bee been seen yet.
    return size < 0 ? 0 : size;
}

zeek_uint_t UDPSessionAdapter::GetEndpointState(bool is_orig) const {
    zeek_int_t size = is_orig ? request_len : reply_len;
    // size may be negative if no data has bee been seen yet.
    return size < 0 ? UDP_INACTIVE : UDP_ACTIVE;
}
