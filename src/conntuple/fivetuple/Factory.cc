// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/fivetuple/Factory.h"

#include "zeek/packet_analysis/protocol/ip/ConnKey.h"

namespace zeek::conntuple::fivetuple {

zeek::ConnKeyPtr Factory::NewConnKey() { return std::make_unique<zeek::IPConnKey>(); }

zeek::ConnKeyPtr Factory::FromVal(const zeek::ValPtr& v) {
    auto ck = NewConnKey();
    auto* ick = static_cast<zeek::IPBasedConnKey*>(ck.get());
    auto& pt = ick->PackedTuple();
    const auto& vt = v->GetType();

    if ( ! IsRecord(vt->Tag()) ) {
        pt.proto = detail::INVALID_CONN_KEY_IP_PROTO;
        assert(ck->Error().has_value());
        return ck;
    }

    RecordType* vr = vt->AsRecordType();
    auto vl = v->As<RecordVal*>();

    // Indices into conn_id's record field value list:
    int orig_h = 0, orig_p = 1, resp_h = 2, resp_p = 3, proto = 4;

    if ( vr != id::conn_id ) {
        // While it's not a conn_id, it may have equivalent fields.
        orig_h = vr->FieldOffset("orig_h");
        resp_h = vr->FieldOffset("resp_h");
        orig_p = vr->FieldOffset("orig_p");
        resp_p = vr->FieldOffset("resp_p");
        proto = vr->FieldOffset("proto");

        // clang-format off
        if ( orig_h < 0 || vr->GetFieldType(orig_h)->Tag() != TYPE_ADDR ||
	     resp_h < 0 || vr->GetFieldType(resp_h)->Tag() != TYPE_ADDR ||
	     orig_p < 0 || vr->GetFieldType(orig_p)->Tag() != TYPE_PORT ||
	     resp_p < 0 || vr->GetFieldType(resp_p)->Tag() != TYPE_PORT ||
	     proto < 0  || vr->GetFieldType(proto)->Tag() != TYPE_COUNT ) {
            pt.proto = detail::INVALID_CONN_KEY_IP_PROTO;
            assert(ck->Error().has_value());
            return ck;
        }
        // clang-format on
    }

    if ( ! vl->HasField(orig_h) || ! vl->HasField(resp_h) || ! vl->HasField(orig_p) || ! vl->HasField(resp_p) ||
         ! vl->HasField(proto) ) {
        pt.proto = detail::INVALID_CONN_KEY_IP_PROTO;
        assert(ck->Error().has_value());
        return ck;
    }

    const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
    const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

    const auto& orig_portv = vl->GetFieldAs<PortVal>(orig_p);
    const auto& resp_portv = vl->GetFieldAs<PortVal>(resp_p);

    const auto& protov = vl->GetField<CountVal>(proto);

    ick->InitTuple(orig_addr, htons(orig_portv->Port()), resp_addr, htons(resp_portv->Port()),
                   static_cast<uint16_t>(protov->AsCount()));

    // Asserting here on the absence of errors can fail btests.

    return ck;
}

} // namespace zeek::conntuple::fivetuple
