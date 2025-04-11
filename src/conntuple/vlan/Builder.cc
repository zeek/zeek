// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/vlan/Builder.h"

#include "zeek/Conn.h"
#include "zeek/ID.h"
#include "zeek/IPAddr.h"
#include "zeek/session/Session.h"

namespace zeek::plugin::Zeek_Conntuple_VLAN {

// Add 802.1Q vlan tags to connection tuples. The tag representation here is as
// in the Packet class, since that's where we learn the tag values from.
struct VlanConnTuple : public ConnTuple {
    uint32_t vlan = 0;
    uint32_t inner_vlan = 0;
};

class VlanConnKey : public detail::ConnKey {
public:
    uint32_t vlan = 0;
    uint32_t inner_vlan = 0;

    VlanConnKey(const ConnTuple& conn) : detail::ConnKey(conn) {};
    VlanConnKey(const VlanConnTuple& conn) : detail::ConnKey(conn), vlan(conn.vlan), inner_vlan(conn.inner_vlan) {}

    VlanConnKey(Val* v) : detail::ConnKey(v) {
        const auto& vt = v->GetType();
        if ( ! IsRecord(vt->Tag()) )
            return;

        RecordType* rt = vt->AsRecordType();
        auto vl = v->As<RecordVal*>();

        // Be safe in case we get here without the expected
        // conn_id redef from policy/protocols/conntuple/vlan.
        if ( rt == id::conn_id && vl->HasField(5) && rt->GetFieldType(5)->Tag() == TYPE_INT )
            vlan = vl->GetField<CountVal>(5)->AsCount();
        if ( rt == id::conn_id && vl->HasField(6) && rt->GetFieldType(6)->Tag() == TYPE_INT )
            inner_vlan = vl->GetField<CountVal>(6)->AsCount();
    }

    size_t PackedSize() const override {
        // This depends on whether we actually have VLANs.
        // We can go with the basic 5-tuple if not.
        size_t result = detail::ConnKey::PackedSize();

        if ( vlan > 0 )
            result += sizeof(vlan);
        if ( inner_vlan > 0 )
            result += sizeof(inner_vlan);

        return result;
    }

    size_t Pack(uint8_t* data, size_t size) const override {
        if ( size < PackedSize() )
            return 0;

        uint8_t* ptr = data;

        ptr += detail::ConnKey::Pack(data, size);

        if ( vlan > 0 ) {
            memcpy(ptr, &vlan, sizeof(vlan));
            ptr += sizeof(vlan);
        }
        if ( inner_vlan > 0 ) {
            memcpy(ptr, &inner_vlan, sizeof(inner_vlan));
            ptr += sizeof(inner_vlan);
        }

        return ptr - data;
    }
};

ConnTuplePtr Builder::GetTuple(const Packet* pkt) {
    auto res = std::make_shared<VlanConnTuple>();
    res->vlan = pkt->vlan;
    res->inner_vlan = pkt->inner_vlan;
    return res;
}

zeek::detail::ConnKeyPtr Builder::GetKey(const ConnTuple& tuple) {
    const VlanConnTuple& vtuple = dynamic_cast<const VlanConnTuple&>(tuple);
    auto res = std::make_shared<VlanConnKey>(tuple);
    res->vlan = vtuple.vlan;
    res->inner_vlan = vtuple.inner_vlan;
    return res;
}

zeek::detail::ConnKeyPtr Builder::GetKey(Val* v) { return std::make_shared<VlanConnKey>(v); }

void Builder::FillConnIdVal(detail::ConnKeyPtr key, RecordValPtr& tuple) {
    if ( tuple->NumFields() <= 5 )
        return;

    RecordType* rt = tuple->GetType()->AsRecordType();
    auto vkey = dynamic_cast<VlanConnKey*>(key.get());

    // Assign only if VLAN tags are present and the record has compatible fields:
    if ( vkey->vlan > 0 && rt->GetFieldType(5)->Tag() == TYPE_INT )
        tuple->Assign(5, vkey->vlan);
    if ( vkey->inner_vlan > 0 && tuple->NumFields() >= 6 && rt->GetFieldType(6)->Tag() == TYPE_INT )
        tuple->Assign(6, vkey->inner_vlan);
}

} // namespace zeek::plugin::Zeek_Conntuple_VLAN
