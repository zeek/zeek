// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/ip/conn_key/vlan_fivetuple/Factory.h"

#include <memory>

#include "zeek/Desc.h"
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
    detail::PackedConnTuple& PackedTuple() override { return key.tuple; }

    /**
     * @copydoc
     */
    const detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:
    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key), session::detail::Key::CONNECTION_KEY_TYPE};
    }

    void DoPopulateConnIdVal(RecordVal& conn_id, RecordVal& ctx) override {
        IPBasedConnKey::DoPopulateConnIdVal(conn_id, ctx);

        // Nothing to do if we have no VLAN tags at all.
        if ( key.vlan == vlan_unset_val && key.inner_vlan == vlan_unset_val )
            return;

        auto [vlan_offset, inner_vlan_offset] = GetConnCtxFieldOffsets();

        if ( key.vlan != vlan_unset_val && vlan_offset >= 0 )
            ctx.Assign(vlan_offset, static_cast<int>(key.vlan));
        if ( key.inner_vlan != vlan_unset_val && inner_vlan_offset >= 0 )
            ctx.Assign(inner_vlan_offset, static_cast<int>(key.inner_vlan));
    };

    std::pair<int, int> GetConnCtxFieldOffsets() {
        static int vlan_offset = -2;
        static int inner_vlan_offset = -2;

        if ( vlan_offset == -2 && inner_vlan_offset == -2 ) {
            vlan_offset = id::conn_id_ctx->FieldOffset("vlan");
            if ( vlan_offset < 0 || id::conn_id_ctx->GetFieldType(vlan_offset)->Tag() != TYPE_INT )
                vlan_offset = -1;

            inner_vlan_offset = id::conn_id_ctx->FieldOffset("inner_vlan");
            if ( inner_vlan_offset < 0 || id::conn_id_ctx->GetFieldType(inner_vlan_offset)->Tag() != TYPE_INT )
                inner_vlan_offset = -1;
        }

        return {vlan_offset, inner_vlan_offset};
    }

protected:
    void DoInit(const Packet& pkt) override {
        auto vlan_tag = pkt.GetVlanTag();
        if ( vlan_tag )
            key.vlan = vlan_tag->id;
        else
            key.vlan = vlan_unset_val;

        auto inner_vlan_tag = pkt.GetInnerVlanTag();
        if ( inner_vlan_tag )
            key.inner_vlan = inner_vlan_tag->id;
        else
            key.inner_vlan = vlan_unset_val;
    }

private:
    friend class Factory;

    struct {
        struct detail::PackedConnTuple tuple;
        // Add 802.1Q vlan tags to connection tuples. The tag representation
        // here is as in the Packet class (where it's oddly 32-bit), since
        // that's where we learn the tag values from. 0xFF000000 indicates
        // absence.
        uint32_t vlan;
        uint32_t inner_vlan;
    } __attribute__((packed, aligned)) key;
};

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<IPVlanConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::Val& v) const {
    auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);

    if ( ! ck.has_value() )
        return ck;

    auto* k = static_cast<IPVlanConnKey*>(ck.value().get());
    auto vl = v.AsRecordVal();
    auto ctx = vl->GetFieldAs<zeek::RecordVal>(5);

    auto [vlan_offset, inner_vlan_offset] = k->GetConnCtxFieldOffsets();

    if ( vlan_offset < 0 || inner_vlan_offset < 0 )
        return zeek::unexpected<std::string>{"missing vlan or inner_vlan field in context"};

    if ( ctx->HasField(vlan_offset) )
        k->key.vlan = ctx->GetFieldAs<zeek::IntVal>(vlan_offset);
    else
        k->key.vlan = vlan_unset_val;

    if ( ctx->HasField(inner_vlan_offset) )
        k->key.inner_vlan = ctx->GetFieldAs<zeek::IntVal>(inner_vlan_offset);
    else
        k->key.inner_vlan = vlan_unset_val;

    return ck;
}

} // namespace zeek::conn_key::vlan_fivetuple
