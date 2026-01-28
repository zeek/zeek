// See the file "COPYING" in the main distribution directory for copyright.

#include "Factory.h"

#include <memory>

#include "zeek/ID.h"
#include "zeek/Val.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/fivetuple/Factory.h"
#include "zeek/util-types.h"

namespace zeek::conn_key::vxlan_vni_fivetuple {

class VxlanVniConnKey : public zeek::IPBasedConnKey {
public:
    VxlanVniConnKey() {
        // Ensure padding holes in the key struct are filled with zeroes.
        memset(static_cast<void*>(&key), 0, sizeof(key));
    }

    detail::PackedConnTuple& PackedTuple() override { return key.tuple; }

    const detail::PackedConnTuple& PackedTuple() const override { return key.tuple; }

protected:
    zeek::session::detail::Key DoSessionKey() const override {
        return {reinterpret_cast<const void*>(&key), sizeof(key), session::detail::Key::CONNECTION_KEY_TYPE};
    }

    void DoPopulateConnIdVal(zeek::RecordVal& conn_id, zeek::RecordVal& ctx) override {
        // Base class populates conn_id fields (orig_h, orig_p, resp_h, resp_p)
        zeek::IPBasedConnKey::DoPopulateConnIdVal(conn_id, ctx);

        if ( conn_id.GetType() != id::conn_id )
            return;

        if ( (key.vxlan_vni & 0xFF000000) == 0 ) // High-bits unset: Have VNI
            ctx.Assign(GetVxlanVniOffset(), static_cast<zeek_uint_t>(key.vxlan_vni));
        else
            ctx.Remove(GetVxlanVniOffset());
    }

    // Extract VNI from most outer VXLAN layer.
    void DoInit(const Packet& pkt) override {
        static const auto& analyzer = zeek::packet_mgr->GetAnalyzer("VXLAN");

        // Set the high-bits: This is needed because keys can get reused.
        key.vxlan_vni = 0xFF000000;

        if ( ! analyzer || ! analyzer->IsEnabled() )
            return;

        auto spans = zeek::packet_mgr->GetAnalyzerData(analyzer);

        if ( spans.empty() || spans[0].size() < 8 )
            return;

        key.vxlan_vni = spans[0][4] << 16 | spans[0][5] << 8 | spans[0][6];
    }

    static int GetVxlanVniOffset() {
        static const auto& conn_id_ctx = zeek::id::find_type<zeek::RecordType>("conn_id_ctx");
        static int vxlan_vni_offset = conn_id_ctx->FieldOffset("vxlan_vni");
        return vxlan_vni_offset;
    }

private:
    friend class Factory;

    struct {
        struct detail::PackedConnTuple tuple;
        uint32_t vxlan_vni;
    } __attribute__((packed, aligned)) key; // packed and aligned due to usage for hashing
};

zeek::ConnKeyPtr Factory::DoNewConnKey() const { return std::make_unique<VxlanVniConnKey>(); }

zeek::expected<zeek::ConnKeyPtr, std::string> Factory::DoConnKeyFromVal(const zeek::Val& v) const {
    if ( v.GetType() != id::conn_id )
        return zeek::unexpected<std::string>{"unexpected value type"};

    auto ck = zeek::conn_key::fivetuple::Factory::DoConnKeyFromVal(v);
    if ( ! ck.has_value() )
        return ck;

    int vxlan_vni_offset = VxlanVniConnKey::GetVxlanVniOffset();
    static int ctx_offset = id::conn_id->FieldOffset("ctx");

    auto* k = static_cast<VxlanVniConnKey*>(ck.value().get());
    auto* ctx = v.AsRecordVal()->GetFieldAs<zeek::RecordVal>(ctx_offset);

    if ( vxlan_vni_offset < 0 )
        return zeek::unexpected<std::string>{"missing vlxan_vni field"};

    if ( ctx->HasField(vxlan_vni_offset) )
        k->key.vxlan_vni = ctx->GetFieldAs<zeek::CountVal>(vxlan_vni_offset);

    return ck;
}

} // namespace zeek::conn_key::vxlan_vni_fivetuple
