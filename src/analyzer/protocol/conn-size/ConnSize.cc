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

int EndpointRecordValCallback::orig_endp_offset = -1;
int EndpointRecordValCallback::resp_endp_offset = -1;
int EndpointRecordValCallback::num_pkts_offset = -1;
int EndpointRecordValCallback::num_bytes_ip_offset = -1;

void EndpointRecordValCallback::Init(RecordVal& arg_conn_val, ConnSize_Analyzer* arg_analyzer) {
    static const int orig_offset = id::connection->FieldOffset("orig");
    static const int resp_offset = id::connection->FieldOffset("resp");
    assert(orig_offset >= 0);
    assert(resp_offset >= 0);

    analyzer = arg_analyzer;

    orig_endp = arg_conn_val.GetField<zeek::RecordVal>(orig_offset).get();
    orig_endp->AssignCallback(num_pkts_offset, this);
    orig_endp->AssignCallback(num_bytes_ip_offset, this);

    resp_endp = arg_conn_val.GetField<zeek::RecordVal>(resp_offset).get();
    resp_endp->AssignCallback(num_pkts_offset, this);
    resp_endp->AssignCallback(num_bytes_ip_offset, this);
}

void EndpointRecordValCallback::Done() {
    // Might have never been initialized.
    if ( ! analyzer ) {
        assert(orig_endp == nullptr);
        assert(resp_endp == nullptr);
        return;
    }

    // During Done() replace the fields on the endpoint values with the most recent value.
    orig_endp->Assign(num_pkts_offset, analyzer->GetPackets(true));
    orig_endp->Assign(num_bytes_ip_offset, analyzer->GetBytes(true));
    resp_endp->Assign(num_pkts_offset, analyzer->GetPackets(false));
    resp_endp->Assign(num_bytes_ip_offset, analyzer->GetBytes(false));

    orig_endp = nullptr;
    resp_endp = nullptr;
    analyzer = nullptr;
}

ZVal EndpointRecordValCallback::Invoke(const RecordVal& val, int field) const {
    if ( &val != orig_endp && &val != resp_endp )
        reporter->InternalError("invalid endpoint in EndpointCallback %p (orig_endp=%p resp_endp=%p)", &val, orig_endp,
                                resp_endp);

    if ( field != num_pkts_offset && field != num_bytes_ip_offset )
        reporter->InternalError("invalid field in EndpointCallback %d (num_pkts_offset=%d num_bytes_ip_offset=%d)",
                                field, num_pkts_offset, num_bytes_ip_offset);

    bool is_orig = &val == orig_endp;
    bool is_num_pkts = field == num_pkts_offset;

    if ( field == num_pkts_offset )
        return analyzer->GetPackets(is_orig);
    else
        return analyzer->GetBytes(is_orig);
};

void EndpointRecordValCallback::InitPostScript() {
    orig_endp_offset = id::connection->FieldOffset("orig");
    resp_endp_offset = id::connection->FieldOffset("resp");
    num_pkts_offset = id::endpoint->FieldOffset("num_pkts");
    num_bytes_ip_offset = id::endpoint->FieldOffset("num_bytes_ip");

    if ( num_pkts_offset < 0 )
        reporter->InternalError("no num_pkts field in endpoint found");

    if ( num_bytes_ip_offset < 0 )
        reporter->InternalError("no num_bytes_ip field in endpoint found");
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
    Analyzer::Done();
    endp_cb.Done();
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

    // Install callbacks for num_pkts and num_bytes_ip
    endp_cb.Init(conn_val, this);
}

void ConnSize_Analyzer::FlipRoles() {
    Analyzer::FlipRoles();
    endp_cb.FlipRoles();

    std::swap(orig_bytes, resp_bytes);
    std::swap(orig_pkts, resp_pkts);
}

} // namespace zeek::analyzer::conn_size
