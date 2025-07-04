// See the file "COPYING" in the main distribution directory for copyright.
//
// See ConnSize.h for more extensive comments.

#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/protocol/conn-size/events.bif.h"

namespace zeek::analyzer::conn_size {

ConnSize_Analyzer::ConnSize_Analyzer(Connection* c) : Analyzer("CONNSIZE", c) { start_time = c->StartTime(); }

void ConnSize_Analyzer::Init() {
    Analyzer::Init();

    orig_bytes = 0;
    orig_pkts = 0;
    resp_bytes = 0;
    resp_pkts = 0;

    orig_bytes_thresh = 0;
    orig_pkts_thresh = 0;
    resp_bytes_thresh = 0;
    resp_pkts_thresh = 0;

    generic_pkt_thresh = 0;
    generic_pkt_thresh_next_idx = 0;
    if ( conn_generic_packet_threshold_crossed )
        NextGenericPacketThreshold();
}

void ConnSize_Analyzer::Done() { Analyzer::Done(); }

void ConnSize_Analyzer::ThresholdEvent(EventHandlerPtr f, uint64_t threshold, bool is_orig) {
    if ( ! f )
        return;

    EnqueueConnEvent(f, ConnVal(), val_mgr->Count(threshold), val_mgr->Bool(is_orig));
}

void ConnSize_Analyzer::NextGenericPacketThreshold() {
    static std::vector<uint64_t> threshold_cache;
    static bool have_cache = false;

    if ( ! have_cache ) {
        auto thresholds = id::find_const<TableVal>("ConnThreshold::generic_packet_thresholds");
        auto lv = thresholds->ToPureListVal();
        for ( auto i = 0; i < lv->Length(); i++ )
            threshold_cache.emplace_back(lv->Idx(i)->InternalUnsigned());
        std::sort(threshold_cache.begin(), threshold_cache.end());
        have_cache = true;
    }

    if ( generic_pkt_thresh_next_idx >= threshold_cache.size() ) {
        generic_pkt_thresh = 0;
        return;
    }

    generic_pkt_thresh = threshold_cache[generic_pkt_thresh_next_idx++];
}

void ConnSize_Analyzer::CheckThresholds(bool is_orig) {
    if ( generic_pkt_thresh && (orig_pkts + resp_pkts) == generic_pkt_thresh ) {
        EnqueueConnEvent(conn_generic_packet_threshold_crossed, ConnVal(), val_mgr->Count(generic_pkt_thresh));
        NextGenericPacketThreshold();
    }

    if ( is_orig ) {
        if ( orig_bytes_thresh && orig_bytes >= orig_bytes_thresh ) {
            ThresholdEvent(conn_bytes_threshold_crossed, orig_bytes_thresh, is_orig);
            orig_bytes_thresh = 0;
        }

        if ( orig_pkts_thresh && orig_pkts >= orig_pkts_thresh ) {
            ThresholdEvent(conn_packets_threshold_crossed, orig_pkts_thresh, is_orig);
            orig_pkts_thresh = 0;
        }
    }
    else {
        if ( resp_bytes_thresh && resp_bytes >= resp_bytes_thresh ) {
            ThresholdEvent(conn_bytes_threshold_crossed, resp_bytes_thresh, is_orig);
            resp_bytes_thresh = 0;
        }

        if ( resp_pkts_thresh && resp_pkts >= resp_pkts_thresh ) {
            ThresholdEvent(conn_packets_threshold_crossed, resp_pkts_thresh, is_orig);
            resp_pkts_thresh = 0;
        }
    }

    if ( duration_thresh != 0 ) {
        if ( (run_state::network_time - start_time) > duration_thresh && conn_duration_threshold_crossed ) {
            EnqueueConnEvent(conn_duration_threshold_crossed, ConnVal(), make_intrusive<IntervalVal>(duration_thresh),
                             val_mgr->Bool(is_orig));
            duration_thresh = 0;
        }
    }
}

void ConnSize_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig, uint64_t seq, const IP_Hdr* ip,
                                      int caplen) {
    Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

    if ( is_orig ) {
        orig_bytes += ip->TotalLen();
        orig_pkts++;
    }
    else {
        resp_bytes += ip->TotalLen();
        resp_pkts++;
    }

    CheckThresholds(is_orig);
}

void ConnSize_Analyzer::SetByteAndPacketThreshold(uint64_t threshold, bool bytes, bool orig) {
    if ( bytes ) {
        if ( orig )
            orig_bytes_thresh = threshold;
        else
            resp_bytes_thresh = threshold;
    }
    else {
        if ( orig )
            orig_pkts_thresh = threshold;
        else
            resp_pkts_thresh = threshold;
    }

    // Check if threshold is already crossed.
    CheckThresholds(orig);
}

uint64_t ConnSize_Analyzer::GetByteAndPacketThreshold(bool bytes, bool orig) {
    if ( bytes ) {
        if ( orig )
            return orig_bytes_thresh;
        else
            return resp_bytes_thresh;
    }
    else {
        if ( orig )
            return orig_pkts_thresh;
        else
            return resp_pkts_thresh;
    }
}

void ConnSize_Analyzer::SetDurationThreshold(double duration) {
    duration_thresh = duration;

    // for duration thresholds, it does not matter which direction we check.
    CheckThresholds(true);
}

void ConnSize_Analyzer::UpdateConnVal(RecordVal* conn_val) {
    static const auto& conn_type = zeek::id::find_type<zeek::RecordType>("connection");
    static const int origidx = conn_type->FieldOffset("orig");
    static const int respidx = conn_type->FieldOffset("resp");
    static const auto& endpoint_type = zeek::id::find_type<zeek::RecordType>("endpoint");
    static const int pktidx = endpoint_type->FieldOffset("num_pkts");
    static const int bytesidx = endpoint_type->FieldOffset("num_bytes_ip");

    auto* orig_endp = conn_val->GetFieldAs<RecordVal>(origidx);
    auto* resp_endp = conn_val->GetFieldAs<RecordVal>(respidx);
    orig_endp->Assign(pktidx, orig_pkts);
    orig_endp->Assign(bytesidx, orig_bytes);
    resp_endp->Assign(pktidx, resp_pkts);
    resp_endp->Assign(bytesidx, resp_bytes);

    Analyzer::UpdateConnVal(conn_val);
}

void ConnSize_Analyzer::FlipRoles() {
    Analyzer::FlipRoles();
    uint64_t tmp;

    tmp = orig_bytes;
    orig_bytes = resp_bytes;
    resp_bytes = tmp;

    tmp = orig_pkts;
    orig_pkts = resp_pkts;
    resp_pkts = tmp;
}

} // namespace zeek::analyzer::conn_size
