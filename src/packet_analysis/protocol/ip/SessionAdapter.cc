// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/SessionAdapter.h"

#include "zeek/File.h"
#include "zeek/ZVal.h"
#include "zeek/ZeekString.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

using namespace zeek::packet_analysis::IP;


void EndpointRecordValCallback::Init(RecordVal& arg_conn_val, const SessionAdapter* arg_adapter) {
    adapter = arg_adapter;

    orig_endp = arg_conn_val.GetField<zeek::RecordVal>(orig_endp_offset).get();
    orig_endp->AssignCallback(size_offset, this);
    orig_endp->AssignCallback(state_offset, this);

    resp_endp = arg_conn_val.GetField<zeek::RecordVal>(resp_endp_offset).get();
    resp_endp->AssignCallback(size_offset, this);
    resp_endp->AssignCallback(state_offset, this);
}

void EndpointRecordValCallback::Done() {
    if ( ! adapter ) {
        assert(orig_endp == nullptr);
        assert(resp_endp == nullptr);
        return;
    }

    orig_endp->Assign(size_offset, adapter->GetEndpointSize(true));
    resp_endp->Assign(size_offset, adapter->GetEndpointSize(false));

    orig_endp->Assign(state_offset, adapter->GetEndpointState(true));
    resp_endp->Assign(state_offset, adapter->GetEndpointState(false));

    adapter = nullptr;
    orig_endp = nullptr;
    resp_endp = nullptr;
}

zeek::ZVal EndpointRecordValCallback::Invoke(const RecordVal& val, int field) const {
    if ( &val != orig_endp && &val != resp_endp )
        reporter->InternalError("invalid endpoint in EndpointCallback %p (orig_endp=%p resp_endp=%p)", &val, orig_endp,
                                resp_endp);

    if ( field != size_offset && field != state_offset )
        reporter->InternalError("invalid field in EndpointCallback %d (size_offset=%d state_offset=%d)", field,
                                size_offset, state_offset);

    // Call the callbacks provided by the SessionAdapters.
    bool is_orig = &val == orig_endp;
    bool is_size = field == size_offset;

    if ( is_size )
        return adapter->GetEndpointSize(is_orig);
    else
        return adapter->GetEndpointState(is_orig);
}

void EndpointRecordValCallback::InitPostScript() {
    orig_endp_offset = id::connection->FieldOffset("orig");
    resp_endp_offset = id::connection->FieldOffset("resp");
    size_offset = id::endpoint->FieldOffset("size");
    state_offset = id::endpoint->FieldOffset("state");

    if ( size_offset < 0 )
        reporter->InternalError("no size field in endpoint found");

    if ( state_offset < 0 )
        reporter->InternalError("no state field in connection found");
}

int EndpointRecordValCallback::orig_endp_offset = -1;
int EndpointRecordValCallback::resp_endp_offset = -1;
int EndpointRecordValCallback::size_offset = -1;
int EndpointRecordValCallback::state_offset = -1;

void SessionAdapter::Done() {
    Analyzer::Done();

    endp_cb.Done();

    for ( const auto& ta : tap_analyzers )
        ta->Done();
}

bool SessionAdapter::IsReuse(double t, const u_char* pkt) { return parent->IsReuse(t, pkt); }

void SessionAdapter::SetContentsFile(unsigned int /* direction */, FilePtr /* f */) {
    reporter->Error("analyzer type does not support writing to a contents file");
}

zeek::FilePtr SessionAdapter::GetContentsFile(unsigned int /* direction */) const {
    reporter->Error("analyzer type does not support writing to a contents file");
    return nullptr;
}

void SessionAdapter::PacketContents(const u_char* data, int len) {
    if ( packet_contents && len > 0 ) {
        zeek::String* cbs = new zeek::String(data, len, true);
        auto contents = make_intrusive<StringVal>(cbs);
        EnqueueConnEvent(packet_contents, ConnVal(), std::move(contents));
    }
}

void SessionAdapter::AddTapAnalyzer(TapAnalyzerPtr ta) {
    assert(! IsFinished());
    tap_analyzers.push_back(std::move(ta));
    tap_analyzers.back()->Init();
}

bool SessionAdapter::RemoveTapAnalyzer(const TapAnalyzer* ta) {
    // Find the raw pointer, call Done(), remove it, thereby destructing it.
    for ( auto it = tap_analyzers.begin(); it != tap_analyzers.end(); ++it ) {
        if ( it->get() == ta ) {
            // Ensure Done() is called only after removal from tap_analyzers.
            auto ptr{std::move(*it)};
            tap_analyzers.erase(it);
            ptr->Done();
            ptr.reset();
            return true;
        }
    }

    return false;
}

void SessionAdapter::TapPacket(const Packet* pkt, PacketAction action, SkipReason skip_reason) const {
    for ( const auto& ta : tap_analyzers )
        ta->TapPacket(*pkt, action, skip_reason);
}

// Remove in v9.1: UpdateConnVal() has been removed.
void SessionAdapter::UpdateConnVal(RecordVal* conn_val) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    Analyzer::UpdateConnVal(conn_val);

    for ( const auto& ta : tap_analyzers )
        ta->UpdateConnVal(conn_val);
#pragma GCC diagnostic pop
}

void SessionAdapter::InitConnVal(RecordVal& conn_val) {
    Analyzer::InitConnVal(conn_val);

    assert(&conn_val == Conn()->RawVal());
    assert(conn_val.GetOrigin() == Conn());

    endp_cb.Init(conn_val, this);
}

void SessionAdapter::FlipRoles() {
    Analyzer::FlipRoles();
    endp_cb.FlipRoles();
}

void SessionAdapter::InitPostScript() {
    // Initialize some offsets.
    EndpointRecordValCallback::InitPostScript();
}
