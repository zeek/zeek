// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/vlan/Factory.h"

#include <memory>

#include "zeek/ID.h"
#include "zeek/packet_analysis/protocol/ip/ConnKey.h"
#include "zeek/session/Session.h"

namespace zeek::conntuple::vlan {

struct IPVlanConnKey : zeek::IPBasedConnKey {
public:
    IPVlanConnKey() {
        // Fill any holes since we use the full tuple as a key:
        memset(static_cast<void*>(&key), '\0', sizeof(key));
    }

    zeek::session::detail::Key SessionKey() const override {
        return zeek::session::detail::Key(reinterpret_cast<const void*>(&key), sizeof(key),
                                          session::detail::Key::CONNECTION_KEY_TYPE);
    }

    detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

    virtual void CompleteConnIdVal(RecordValPtr& conn_id) override {
        if ( conn_id->NumFields() <= 5 )
            return;

        // Nothing to do if we have no VLAN tags at all.
        if ( key.vlan == 0 && key.inner_vlan == 0 )
            return;

        int vlan_off, inner_vlan_off;
        GetConnIdFieldOffsets(vlan_off, inner_vlan_off);

        if ( key.vlan && vlan_off >= 0 )
            conn_id->Assign(vlan_off, key.vlan);
        if ( key.inner_vlan && inner_vlan_off >= 0 )
            conn_id->Assign(inner_vlan_off, key.inner_vlan);
    };

    void GetConnIdFieldOffsets(int& a_vlan_off, int& a_inner_vlan_off) {
        static int vlan_off, inner_vlan_off;

        if ( vlan_off == 0 && inner_vlan_off == 0 ) {
            vlan_off = id::conn_id->FieldOffset("vlan");
            if ( vlan_off < 0 || id::conn_id->GetFieldType(vlan_off)->Tag() != TYPE_INT )
                vlan_off = -1;

            inner_vlan_off = id::conn_id->FieldOffset("inner_vlan");
            if ( inner_vlan_off < 0 || id::conn_id->GetFieldType(inner_vlan_off)->Tag() != TYPE_INT )
                inner_vlan_off = -1;
        }

        a_vlan_off = vlan_off;
        a_inner_vlan_off = inner_vlan_off;
    }

protected:
    void DoInit(const Packet& pkt) override {
        key.vlan = pkt.vlan;
        key.inner_vlan = pkt.inner_vlan;
    }

private:
    friend class Factory;

    // Key bytes:
    struct {
        mutable struct detail::PackedConnTuple tuple;
        // Add 802.1Q vlan tags to connection tuples. The tag representation
        // here is as in the Packet class (where it's oddly 32-bit), since
        // that's where we learn the tag values from. 0 indicates absence.
        uint32_t vlan;
        uint32_t inner_vlan;
    } __attribute__((packed, aligned)) key;
};

zeek::ConnKeyPtr Factory::NewConnKey() { return std::make_unique<IPVlanConnKey>(); }

zeek::ConnKeyPtr Factory::FromVal(const zeek::ValPtr& v) {
    auto ck = zeek::conntuple::fivetuple::Factory::FromVal(v);

    if ( ck->Error().has_value() )
        return ck;

    auto* k = static_cast<IPVlanConnKey*>(ck.get());
    auto rt = v->GetType()->AsRecordType();
    auto vl = v->As<RecordVal*>();

    int vlan_off, inner_vlan_off;

    if ( rt == id::conn_id ) {
        k->GetConnIdFieldOffsets(vlan_off, inner_vlan_off);
    }
    else {
        // We don't know what we've been passed:
        vlan_off = rt->FieldOffset("vlan");
        inner_vlan_off = rt->FieldOffset("inner_vlan");

        if ( vlan_off >= 0 && rt->GetFieldType(vlan_off)->Tag() == TYPE_INT && vl->HasField(vlan_off) )
            k->key.vlan = vl->GetFieldAs<zeek::IntVal>(vlan_off);

        if ( inner_vlan_off >= 0 && rt->GetFieldType(inner_vlan_off)->Tag() == TYPE_INT &&
             vl->HasField(inner_vlan_off) )
            k->key.inner_vlan = vl->GetFieldAs<zeek::IntVal>(inner_vlan_off);
    }

    return ck;
}

} // namespace zeek::conntuple::vlan
