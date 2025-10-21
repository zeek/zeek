// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Conn.h"

#include <binpac.h>
#include <cctype>
#include <memory>

#include "zeek/Desc.h"
#include "zeek/ID.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Timer.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/WeirdState.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"
#include "zeek/packet_analysis/protocol/tcp/TCP.h"
#include "zeek/session/Manager.h"

namespace zeek {

uint64_t Connection::total_connections = 0;
uint64_t Connection::current_connections = 0;
zeek::RecordValPtr Connection::conn_id_ctx_singleton;


namespace detail {

int ConnectionRecordValCallback::duration_offset = -1;
int ConnectionRecordValCallback::history_offset = -1;

void ConnectionRecordValCallback::AssignCallbacks(const Connection* arg_conn, RecordVal* arg_conn_val) {
    conn = arg_conn;
    conn_val = arg_conn_val;
    conn_val->AssignCallback(duration_offset, this);
    conn_val->AssignCallback(history_offset, this);
    cached_history = ZValElement(zeek::val_mgr->EmptyString(), zeek::base_type(TYPE_STRING));
}

void ConnectionRecordValCallback::RemoveCallbacks() {
    if ( ! HasCallbacksAssigned() )
        reporter->FatalErrorWithCore("connection callback: RemoveCallbacks() but none assigned");

    auto final_duration = Invoke(*conn_val, duration_offset).AsDouble();
    auto* final_history = Invoke(*conn_val, history_offset).AsString();

    conn_val->Assign(duration_offset, final_duration);
    // The record field adopts the ref taken by the Invoke() call above.
    conn_val->Assign(history_offset, final_history);

    cached_history.Reset();
    conn = nullptr;
    conn_val = nullptr;
}

ZVal ConnectionRecordValCallback::Invoke(const RecordVal& val, int field) const {
    if ( &val != conn_val )
        reporter->FatalErrorWithCore("connection callback: wrong val %p != %p", &val, conn_val);

    if ( field == duration_offset ) {
        auto duration = conn->LastTime() - conn->StartTime();
        return duration;
    }
    else if ( field == history_offset ) {
        const auto& history_str = conn->GetHistory();
        if ( ! cached_history->ManagedVal() || cached_history->AsString()->ToStdStringView() != history_str ) {
            // Adopt the reference into a ZValElement, unrefs the original one in cached_history.
            cached_history = ZVal(new StringVal(history_str));
        }

        // Hand out a new reference.
        zeek::Ref(cached_history->ManagedVal());
        return *cached_history;
    }

    // This is bad.
    reporter->InternalError("connection callback: bad field %d requested (duration_offset=%d, history_offset=%d)",
                            field, duration_offset, history_offset);
    return {};
}

void ConnectionRecordValCallback::InitPostScript() {
    duration_offset = id::connection->FieldOffset("duration");
    if ( duration_offset < 0 )
        reporter->InternalError("no duration field in connection found");

    history_offset = id::connection->FieldOffset("history");
    if ( history_offset < 0 )
        reporter->InternalError("no history field in connection found");
}

}; // namespace detail


void Connection::InitPostScript() {
    if ( id::conn_id_ctx->NumFields() == 0 )
        conn_id_ctx_singleton = zeek::make_intrusive<zeek::RecordVal>(id::conn_id_ctx);

    detail::ConnectionRecordValCallback::InitPostScript();
}

Connection::Connection(zeek::IPBasedConnKeyPtr k, double t, uint32_t flow, const Packet* pkt)
    : Session(t, connection_timeout, connection_status_update, detail::connection_status_update_interval),
      key(std::move(k)) {
    orig_addr = key->SrcAddr();
    resp_addr = key->DstAddr();
    orig_port = key->SrcPort();
    resp_port = key->DstPort();
    proto = key->GetTransportProto();

    orig_flow_label = flow;
    resp_flow_label = 0;
    saw_first_orig_packet = true;
    saw_first_resp_packet = false;

    if ( pkt->l2_src )
        memcpy(orig_l2_addr, pkt->l2_src, sizeof(orig_l2_addr));
    else
        memset(orig_l2_addr, 0, sizeof(orig_l2_addr));

    if ( pkt->l2_dst )
        memcpy(resp_l2_addr, pkt->l2_dst, sizeof(resp_l2_addr));
    else
        memset(resp_l2_addr, 0, sizeof(resp_l2_addr));

    vlan = pkt->vlan;
    inner_vlan = pkt->inner_vlan;

    weird = false;

    suppress_event = 0;

    finished = false;

    adapter = nullptr;
    primary_PIA = nullptr;

    ++current_connections;
    ++total_connections;

    encapsulation = pkt->encap;
}

Connection::~Connection() {
    if ( ! finished )
        reporter->InternalError("Done() not called before destruction of Connection");

    CancelTimers();

    if ( conn_val )
        conn_val->SetOrigin(nullptr);

    if ( conn_val_cb.HasCallbacksAssigned() )
        conn_val_cb.RemoveCallbacks();

    delete adapter;

    --current_connections;
}

void Connection::CheckEncapsulation(const std::shared_ptr<EncapsulationStack>& arg_encap) {
    if ( encapsulation && arg_encap ) {
        if ( *encapsulation != *arg_encap ) {
            if ( tunnel_changed && (zeek::detail::tunnel_max_changes_per_connection == 0 ||
                                    tunnel_changes < zeek::detail::tunnel_max_changes_per_connection) ) {
                tunnel_changes++;
                EnqueueEvent(tunnel_changed, nullptr, GetVal(), arg_encap->ToVal());
            }

            encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
        }
    }

    else if ( encapsulation ) {
        if ( tunnel_changed ) {
            EncapsulationStack empty;
            EnqueueEvent(tunnel_changed, nullptr, GetVal(), empty.ToVal());
        }

        encapsulation = nullptr;
    }

    else if ( arg_encap ) {
        if ( tunnel_changed )
            EnqueueEvent(tunnel_changed, nullptr, GetVal(), arg_encap->ToVal());

        encapsulation = std::make_shared<EncapsulationStack>(*arg_encap);
    }
}

void Connection::Done() {
    finished = true;

    if ( adapter ) {
        if ( ConnTransport() == TRANSPORT_TCP ) {
            auto* ta = static_cast<packet_analysis::TCP::TCPSessionAdapter*>(adapter);
            assert(ta->IsAnalyzer("TCP"));
            analyzer::tcp::TCP_Endpoint* to = ta->Orig();
            analyzer::tcp::TCP_Endpoint* tr = ta->Resp();

            packet_analysis::TCP::TCPAnalyzer::GetStats().StateLeft(to->state, tr->state);
        }

        if ( ! adapter->IsFinished() )
            adapter->Done();
    }

    if ( conn_val_cb.HasCallbacksAssigned() )
        conn_val_cb.RemoveCallbacks();
}

void Connection::NextPacket(double t, bool is_orig, const IP_Hdr* ip, int len, int caplen, const u_char*& data,
                            int& record_packet, int& record_content,
                            // arguments for reproducing packets
                            const Packet* pkt) {
    run_state::current_timestamp = t;
    run_state::current_pkt = pkt;

    if ( adapter ) {
        if ( adapter->Skipping() )
            return;

        record_current_packet = record_packet;
        record_current_content = record_content;
        adapter->NextPacket(len, data, is_orig, -1, ip, caplen);
        record_packet = record_current_packet;
        record_content = record_current_content;
    }
    else
        last_time = t;

    run_state::current_timestamp = 0;
    run_state::current_pkt = nullptr;
}


const ConnKey& Connection::Key() const { return *key; }

session::detail::Key Connection::SessionKey(bool copy) const { return key->SessionKey(); }

uint8_t Connection::KeyProto() const { return key->PackedTuple().proto; }

bool Connection::IsReuse(double t, const u_char* pkt) { return adapter && adapter->IsReuse(t, pkt); }

const RecordValPtr& Connection::GetVal() {
    if ( ! conn_val ) {
        conn_val = make_intrusive<RecordVal>(id::connection);
        conn_val->SetOrigin(this);
        conn_val->AssignTime(3, start_time);

        // Assign field callbacks in connection record.
        conn_val_cb.AssignCallbacks(this, conn_val.get());
        assert(conn_val_cb.HasCallbacksAssigned());

        auto id_val = make_intrusive<RecordVal>(id::conn_id);

        constexpr int ctx_offset = 5;

        // If the conn_id_ctx type has no fields at all, set it to the singleton instance,
        // otherwise the instance is initialized on first access through GetField() below.
        if ( conn_id_ctx_singleton ) {
            assert(id::conn_id_ctx->NumFields() == 0);
            id_val->Assign(ctx_offset, conn_id_ctx_singleton);
        }

        auto ctx = id_val->GetField<zeek::RecordVal>(ctx_offset);

        // Allow customized ConnKeys to augment conn_id and ctx.
        key->PopulateConnIdVal(*id_val, *ctx);

        auto orig_endp = make_intrusive<RecordVal>(id::endpoint);
        orig_endp->Assign(0, 0);
        orig_endp->Assign(1, 0);
        orig_endp->Assign(4, orig_flow_label);

        const int l2_len = sizeof(orig_l2_addr);
        char null[l2_len]{};

        if ( memcmp(&orig_l2_addr, &null, l2_len) != 0 ) {
            auto [mac_bytes, mac_len] = fmt_mac_bytes(orig_l2_addr, l2_len);
            orig_endp->Assign(5, new String(true, mac_bytes.release(), mac_len));
        }

        auto resp_endp = make_intrusive<RecordVal>(id::endpoint);
        resp_endp->Assign(0, 0);
        resp_endp->Assign(1, 0);
        resp_endp->Assign(4, resp_flow_label);

        if ( memcmp(&resp_l2_addr, &null, l2_len) != 0 ) {
            auto [mac_bytes, mac_len] = fmt_mac_bytes(resp_l2_addr, l2_len);
            resp_endp->Assign(5, new String(true, mac_bytes.release(), mac_len));
        }

        conn_val->Assign(0, std::move(id_val));
        conn_val->Assign(1, std::move(orig_endp));
        conn_val->Assign(2, std::move(resp_endp));
        // 3 and 4 are set below.
        // Do not assign to 5 (service). It is a non-optional set, which will be default-initialized
        // using the script-level settings; this easily applies the &ordered attribute to it.
        // conn_val->Assign(5, make_intrusive<TableVal>(id::ordered_string_set)); // service

        if ( ! uid )
            uid.Set(zeek::detail::bits_per_uid);

        conn_val->Assign(7, uid.Base62("C"));

        if ( encapsulation && encapsulation->Depth() > 0 )
            conn_val->Assign(8, encapsulation->ToVal());

        if ( vlan != 0 )
            conn_val->Assign(9, vlan);

        if ( inner_vlan != 0 )
            conn_val->Assign(10, inner_vlan);
    }

    if ( adapter )
        adapter->UpdateConnVal(conn_val.get());

    return conn_val;
}

analyzer::Analyzer* Connection::FindAnalyzer(analyzer::ID id) { return adapter ? adapter->FindChild(id) : nullptr; }

analyzer::Analyzer* Connection::FindAnalyzer(const zeek::Tag& tag) {
    return adapter ? adapter->FindChild(tag) : nullptr;
}

analyzer::Analyzer* Connection::FindAnalyzer(const char* name) { return adapter->FindChild(name); }

void Connection::Match(detail::Rule::PatternType type, const u_char* data, int len, bool is_orig, bool bol, bool eol,
                       bool clear_state) {
    if ( primary_PIA )
        primary_PIA->Match(type, data, len, is_orig, bol, eol, clear_state);
}

void Connection::RemovalEvent() {
    if ( connection_state_remove )
        EnqueueEvent(connection_state_remove, nullptr, GetVal());
}

void Connection::Weird(const char* name, const char* addl, const char* source) {
    weird = true;
    reporter->Weird(this, name, addl ? addl : "", source ? source : "");
}

void Connection::FlipRoles() {
    IPAddr tmp_addr = resp_addr;
    resp_addr = orig_addr;
    orig_addr = tmp_addr;

    uint32_t tmp_port = resp_port;
    resp_port = orig_port;
    orig_port = tmp_port;

    const int l2_len = sizeof(orig_l2_addr);
    u_char tmp_l2_addr[l2_len];
    memcpy(tmp_l2_addr, resp_l2_addr, l2_len);
    memcpy(resp_l2_addr, orig_l2_addr, l2_len);
    memcpy(orig_l2_addr, tmp_l2_addr, l2_len);

    bool tmp_bool = saw_first_resp_packet;
    saw_first_resp_packet = saw_first_orig_packet;
    saw_first_orig_packet = tmp_bool;

    uint32_t tmp_flow = resp_flow_label;
    resp_flow_label = orig_flow_label;
    orig_flow_label = tmp_flow;

    if ( conn_val ) {
        // Delegate flipping of conn_id and ctx records to the key instance.
        auto id_val = conn_val->GetField<zeek::RecordVal>(0);
        auto* ctx = id_val->GetFieldAs<zeek::RecordVal>(5);
        key->FlipRoles(*id_val, *ctx);

        // Flip the connection's endpoints
        const auto& tmp_endp = conn_val->GetField<zeek::RecordVal>(1);
        conn_val->Assign(1, conn_val->GetField(2));
        conn_val->Assign(2, tmp_endp);
    }
    else {
        // Even we haven't yet allocated a connection value, still need to flip the key's
        // idea of originator and responder
        key->FlipRoles();
    }

    if ( adapter )
        adapter->FlipRoles();

    analyzer_mgr->ApplyScheduledAnalyzers(this);

    AddHistory('^');

    if ( connection_flipped )
        EnqueueEvent(connection_flipped, nullptr, GetVal());
}

void Connection::Describe(ODesc* d) const {
    session::Session::Describe(d);

    switch ( proto ) {
        case TRANSPORT_TCP: d->Add("TCP"); break;

        case TRANSPORT_UDP: d->Add("UDP"); break;

        case TRANSPORT_ICMP: d->Add("ICMP"); break;

        case TRANSPORT_UNKNOWN:
            d->Add("unknown");
            reporter->InternalWarning("unknown transport in Connection::Describe()");

            break;

        default: reporter->InternalError("unhandled transport type in Connection::Describe");
    }

    d->SP();
    d->Add(orig_addr);
    d->Add(":");
    d->Add(ntohs(orig_port));

    d->SP();
    d->AddSP("->");

    d->Add(resp_addr);
    d->Add(":");
    d->Add(ntohs(resp_port));

    d->NL();
}

void Connection::IDString(ODesc* d) const {
    d->Add(orig_addr);
    d->AddRaw(":", 1);
    d->Add(ntohs(orig_port));
    d->AddRaw(" > ", 3);
    d->Add(resp_addr);
    d->AddRaw(":", 1);
    d->Add(ntohs(resp_port));
}

void Connection::SetSessionAdapter(packet_analysis::IP::SessionAdapter* aa, analyzer::pia::PIA* pia) {
    adapter = aa;
    primary_PIA = pia;
}

void Connection::CheckFlowLabel(bool is_orig, uint32_t flow_label) {
    uint32_t& my_flow_label = is_orig ? orig_flow_label : resp_flow_label;

    if ( my_flow_label != flow_label ) {
        if ( conn_val ) {
            RecordVal* endp = conn_val->GetFieldAs<RecordVal>(is_orig ? 1 : 2);
            endp->Assign(4, flow_label);
        }

        if ( connection_flow_label_changed && (is_orig ? saw_first_orig_packet : saw_first_resp_packet) ) {
            EnqueueEvent(connection_flow_label_changed, nullptr, GetVal(), val_mgr->Bool(is_orig),
                         val_mgr->Count(my_flow_label), val_mgr->Count(flow_label));
        }

        my_flow_label = flow_label;
    }

    if ( is_orig )
        saw_first_orig_packet = true;
    else
        saw_first_resp_packet = true;
}

bool Connection::PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration) {
    if ( ! weird_state )
        weird_state = std::make_unique<detail::WeirdStateMap>();

    return detail::PermitWeird(*weird_state, name, threshold, rate, duration);
}

} // namespace zeek
