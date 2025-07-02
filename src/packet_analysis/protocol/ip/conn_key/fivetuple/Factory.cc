// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

#include "zeek/IP.h"
#include "zeek/Val.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/util.h"

namespace zeek::conn_key::fivetuple {

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<zeek::IPConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::Val& v) const {
    static auto unexpected_conn_id = zeek::unexpected<std::string>{"invalid connection ID record encountered"};
    auto ck = NewConnKey();
    auto* ick = static_cast<zeek::IPBasedConnKey*>(ck.get());
    auto& pt = ick->PackedTuple();
    const auto& vt = v.GetType();

    if ( ! IsRecord(vt->Tag()) )
        return unexpected_conn_id;

    auto* vr = vt->AsRecordType();
    auto vl = v.AsRecordVal();

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
            return unexpected_conn_id;
        }
        // clang-format on
    }

    if ( ! vl->HasField(orig_h) || ! vl->HasField(resp_h) || ! vl->HasField(orig_p) || ! vl->HasField(resp_p) ||
         ! vl->HasField(proto) ) {
        return unexpected_conn_id;
    }

    const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
    const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

    const auto& orig_portv = vl->GetFieldAs<PortVal>(orig_p);
    const auto& resp_portv = vl->GetFieldAs<PortVal>(resp_p);

    const auto& protov = vl->GetField<CountVal>(proto);
    auto proto16_t = static_cast<uint16_t>(protov->AsCount());

    if ( proto16_t == UNKNOWN_IP_PROTO )
        return zeek::unexpected<std::string>(
            "invalid connection ID record encountered: the proto field has the \"unknown\" 65535 value. "
            "Did you forget to set it?");

    ick->InitTuple(orig_addr, htons(orig_portv->Port()), resp_addr, htons(resp_portv->Port()), proto16_t);

    // Asserting here on the absence of errors can fail btests.

    return ck;
}

} // namespace zeek::conn_key::fivetuple
