// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/conn_key/vlan_fivetuple/Factory.h"

#include <memory>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"
#include "zeek/util-types.h"

namespace zeek::conn_key::vlan_fivetuple {

class IPVlanConnKey : public zeek::IPBasedConnKey {
public:
    /**
     * Constructor.
     *
     * Fill any holes in the key struct as we use the full tuple as a key.
     */
    IPVlanConnKey() { memset(static_cast<void*>(&key), 0, sizeof(key)); }

    /**
     * @copydoc
     */
    detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:
    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key), session::detail::Key::CONNECTION_KEY_TYPE};
    }

    void DoPopulateConnIdVal(const RecordValPtr& conn_id) override {
        if ( conn_id->NumFields() <= 5 )
            return;

        // Nothing to do if we have no VLAN tags at all.
        if ( key.vlan == 0 && key.inner_vlan == 0 )
            return;

        auto [vlan_off, inner_vlan_off] = GetConnIdFieldOffsets();

        if ( key.vlan && vlan_off >= 0 )
            conn_id->Assign(vlan_off, static_cast<int>(key.vlan));
        if ( key.inner_vlan && inner_vlan_off >= 0 )
            conn_id->Assign(inner_vlan_off, static_cast<int>(key.inner_vlan));
    };

    std::pair<int, int> GetConnIdFieldOffsets() {
        static int vlan_off = -2, inner_vlan_off = -2;

        if ( vlan_off == -2 && inner_vlan_off == -2 ) {
            vlan_off = id::conn_id->FieldOffset("vlan");
            if ( vlan_off < 0 || id::conn_id->GetFieldType(vlan_off)->Tag() != TYPE_INT )
                vlan_off = -1;

            inner_vlan_off = id::conn_id->FieldOffset("inner_vlan");
            if ( inner_vlan_off < 0 || id::conn_id->GetFieldType(inner_vlan_off)->Tag() != TYPE_INT )
                inner_vlan_off = -1;
        }

        return {vlan_off, inner_vlan_off};
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

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<IPVlanConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::ValPtr& v) const {
    auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);

    if ( ! ck.has_value() )
        return ck;

    auto* k = static_cast<IPVlanConnKey*>(ck.value().get());
    auto rt = v->GetType()->AsRecordType();
    auto vl = v->As<RecordVal*>();

    int vlan_off, inner_vlan_off;
    if ( rt == id::conn_id ) {
        std::tie(vlan_off, inner_vlan_off) = k->GetConnIdFieldOffsets();
    }
    else {
        // We don't know what we've been passed:
        vlan_off = rt->FieldOffset("vlan");
        inner_vlan_off = rt->FieldOffset("inner_vlan");
    }

    if ( vlan_off < 0 || inner_vlan_off < 0 )
        return zeek::unexpected<std::string>{"missing vlan or inner_vlan field"};

    if ( rt->GetFieldType(vlan_off)->Tag() != TYPE_INT || rt->GetFieldType(inner_vlan_off)->Tag() != TYPE_INT )
        return zeek::unexpected<std::string>{"vlan or inner_vlan field not of type int"};

    if ( vl->HasField(vlan_off) )
        k->key.vlan = vl->GetFieldAs<zeek::IntVal>(vlan_off);

    if ( vl->HasField(inner_vlan_off) )
        k->key.inner_vlan = vl->GetFieldAs<zeek::IntVal>(inner_vlan_off);

    return ck;
}

} // namespace zeek::conn_key::vlan_fivetuple
