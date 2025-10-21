// See the file "COPYING" in the main distribution directory for copyright.
//
// See ConnSize.h for more extensive comments.

#include "zeek/analyzer/protocol/conn-size/ConnSize.h"

#include "zeek/IP.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/protocol/conn-size/events.bif.h"

namespace zeek::analyzer::conn_size {

namespace detail {

int EndpointRecordValCallback::num_pkts_offset = -1;
int EndpointRecordValCallback::num_bytes_ip_offset = -1;

void EndpointRecordValCallback::Init(ConnSize_Analyzer* arg_conn_size, RecordVal* arg_endp_val, bool arg_is_orig) {
    conn_size = arg_conn_size;
    endp_val = arg_endp_val;
    is_orig = arg_is_orig;

    endp_val->AssignCallback(num_pkts_offset, this);
    endp_val->AssignCallback(num_bytes_ip_offset, this);
}

void EndpointRecordValCallback::Done() {
    // Might have never been initialized.
    if ( ! endp_val ) {
        assert(conn_size == nullptr);
        return;
    }

    // During Done(), run the callbacks once more to gather the most recent data
    // and set it on the endpoint record.
    assert(conn_size != nullptr);

    auto final_num_pkts = Invoke(*endp_val, num_pkts_offset).AsCount();
    auto final_num_bytes_ip = Invoke(*endp_val, num_bytes_ip_offset).AsCount();
    endp_val->Assign(num_pkts_offset, final_num_pkts);
    endp_val->Assign(num_bytes_ip_offset, final_num_bytes_ip);

    endp_val = nullptr;
    conn_size = nullptr;
}

ZVal EndpointRecordValCallback::Invoke(const RecordVal& val, int field) const {
    if ( &val != endp_val )
        reporter->FatalErrorWithCore("endpoint callback: wrong endp_val %p != %p", &val, endp_val);

    if ( field == num_pkts_offset )
        return ZVal(is_orig ? conn_size->orig_pkts : conn_size->resp_pkts);
    else if ( field == num_bytes_ip_offset )
        return ZVal(is_orig ? conn_size->orig_bytes : conn_size->resp_bytes);

    // This is bad.
    reporter->InternalError("endpoint callback: bad field %d requested (num_pkts_offset=%d, num_bytes_ip_offset=%d)",
                            field, num_pkts_offset, num_bytes_ip_offset);
    return ZVal();
};

void EndpointRecordValCallback::InitPostScript() {
    num_pkts_offset = id::endpoint->FieldOffset("num_pkts");
    num_bytes_ip_offset = id::endpoint->FieldOffset("num_bytes_ip");

    if ( num_pkts_offset < 0 )
        reporter->InternalError("no num_pkts field in connection found");

    if ( num_bytes_ip_offset < 0 )
        reporter->InternalError("no num_bytes_ip field in connection found");
}

} // namespace detail

std::vector<uint64_t> ConnSize_Analyzer::generic_pkt_thresholds;

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

void ConnSize_Analyzer::Done() {
    orig_cb.Done();
    resp_cb.Done();
    Analyzer::Done();
}

void ConnSize_Analyzer::ThresholdEvent(EventHandlerPtr f, uint64_t threshold, bool is_orig) {
    if ( ! f )
        return;

    EnqueueConnEvent(f, ConnVal(), val_mgr->Count(threshold), val_mgr->Bool(is_orig));
}

void ConnSize_Analyzer::NextGenericPacketThreshold() {
    if ( generic_pkt_thresh_next_idx >= generic_pkt_thresholds.size() ) {
        generic_pkt_thresh = 0;
        return;
    }

    generic_pkt_thresh = generic_pkt_thresholds[generic_pkt_thresh_next_idx++];
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

void ConnSize_Analyzer::InitConnVal(RecordVal& conn_val) {
    assert(conn_val.GetOrigin() == Conn());
    assert(&conn_val == Conn()->RawVal());

    assert(! resp_cb.HasCallbacksAssigned());
    static const int orig_offset = id::connection->FieldOffset("orig");
    static const int resp_offset = id::connection->FieldOffset("resp");

    auto* orig_endp = conn_val.GetFieldAs<RecordVal>(orig_offset);
    auto* resp_endp = conn_val.GetFieldAs<RecordVal>(resp_offset);

    // Install callbacks for num_pkts and num_bytes_ip
    orig_cb.Init(this, orig_endp, true);
    resp_cb.Init(this, resp_endp, false);
}

void ConnSize_Analyzer::FlipRoles() {
    Analyzer::FlipRoles();
    orig_cb.FlipRoles();
    resp_cb.FlipRoles();

    uint64_t tmp;

    tmp = orig_bytes;
    orig_bytes = resp_bytes;
    resp_bytes = tmp;

    tmp = orig_pkts;
    orig_pkts = resp_pkts;
    resp_pkts = tmp;
}

} // namespace zeek::analyzer::conn_size
