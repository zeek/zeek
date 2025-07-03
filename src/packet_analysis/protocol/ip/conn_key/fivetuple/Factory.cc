// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"

#include "zeek/Desc.h"
#include "zeek/IP.h"
#include "zeek/Val.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/util-types.h"

namespace zeek::conn_key::fivetuple {

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<zeek::IPConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::Val& v) const {
    auto ck = NewConnKey();
    auto* ick = static_cast<zeek::IPBasedConnKey*>(ck.get());
    auto& pt = ick->PackedTuple();

    if ( v.GetType() != id::conn_id )
        return zeek::unexpected<std::string>{
            util::fmt("expected conn_id, got %s", obj_desc_short(v.GetType()).c_str())};

    auto vl = v.AsRecordVal();

    // Indices into conn_id's record field value list:
    constexpr int orig_h = 0;
    constexpr int orig_p = 1;
    constexpr int resp_h = 2;
    constexpr int resp_p = 3;
    constexpr int proto = 4;
    constexpr int ctx = 5;
    if ( ! vl->HasField(orig_h) || ! vl->HasField(resp_h) || ! vl->HasField(orig_p) || ! vl->HasField(resp_p) ||
         ! vl->HasField(proto) || ! vl->HasField(ctx) )
        return zeek::unexpected<std::string>{"invalid connection ID record encountered"};

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

    return ck;
}

} // namespace zeek::conn_key::fivetuple
