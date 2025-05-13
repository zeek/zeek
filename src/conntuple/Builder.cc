// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/Builder.h"

#include "zeek/Val.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::conntuple {

Builder::Builder() {}
Builder::~Builder() {}

bool fill_from_val(const IPBasedConnKey* ck, const zeek::ValPtr& v) {
    auto& t = ck->RawTuple();

    const auto& vt = v->GetType();
    if ( ! IsRecord(vt->Tag()) ) {
        t.transport = detail::INVALID_CONN_KEY_IP_PROTO;
        assert(ck->Error().has_value());
        return false;
    }

    RecordType* vr = vt->AsRecordType();
    auto vl = v->As<RecordVal*>();

    int orig_h, orig_p; // indices into record's value list
    int resp_h, resp_p;
    int proto;

    if ( vr == id::conn_id ) {
        orig_h = 0;
        orig_p = 1;
        resp_h = 2;
        resp_p = 3;
        proto = 4;
    }
    else {
        // While it's not a conn_id, it may have equivalent fields.
        orig_h = vr->FieldOffset("orig_h");
        resp_h = vr->FieldOffset("resp_h");
        orig_p = vr->FieldOffset("orig_p");
        resp_p = vr->FieldOffset("resp_p");
        proto = vr->FieldOffset("proto");

        if ( orig_h < 0 || resp_h < 0 || orig_p < 0 || resp_p < 0 || proto < 0 ) {
            t.transport = detail::INVALID_CONN_KEY_IP_PROTO;
            assert(ck->Error().has_value());
            return false;
        }

        // TODO we ought to check that the fields have the right
        // types, too.
    }

    if ( ! vl->HasField(orig_h) || ! vl->HasField(resp_h) || ! vl->HasField(orig_p) || ! vl->HasField(resp_p) ) {
        t.transport = detail::INVALID_CONN_KEY_IP_PROTO;
        assert(ck->Error().has_value());
        return false;
    }

    const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
    const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

    const auto& orig_portv = vl->GetFieldAs<PortVal>(orig_p);
    const auto& resp_portv = vl->GetFieldAs<PortVal>(resp_p);

    const auto& protov = vl->GetField<CountVal>(proto);

    auto ct = ConnTuple{orig_addr, resp_addr, ntohs(orig_portv->Port()), ntohs(resp_portv->Port()),
                        static_cast<uint16_t>(protov->AsCount())};

    detail::init_raw_tuple(t, ct);
    assert(! ck->Error().has_value());
    return true;
}

zeek::ConnKeyPtr Builder::NewConnKey() { return std::make_unique<zeek::IPConnKey>(); }

// Creating a ConnKey instance from a ValPtr, assuming conn_id.
zeek::ConnKeyPtr Builder::FromVal(const zeek::ValPtr& v) {
    auto ck = NewConnKey();
    auto* k = static_cast<zeek::IPBasedConnKey*>(ck.get());
    if ( ! fill_from_val(k, v) ) {
        assert(ck->Error().has_value());
    }

    return ck;
}

} // namespace zeek::conntuple
