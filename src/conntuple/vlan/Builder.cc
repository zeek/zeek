// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/vlan/Builder.h"

#include "zeek/ID.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/session/Session.h"

namespace zeek::plugin::Zeek_Conntuple_VLAN {

struct IPVlanConnKey : zeek::IPBasedConnKey {
public:
    IPVlanConnKey() {
        // Fill holes, we the whole struct as a key!
        memset(static_cast<void*>(&key), '\0', sizeof(key));
    }

    void DoInit(const Packet& pkt) override {
        key.vlan = pkt.vlan;
        key.inner_vlan = pkt.inner_vlan;
    }

    bool FromConnIdVal(const zeek::RecordValPtr& rv) override {
        if ( ! zeek::IPBasedConnKey::FromConnIdVal(rv) )
            return false;

        // TODO: Also load vlan and inner_vlan from the record!
    }

    zeek::Span<const std::byte> Key() const override {
        return {reinterpret_cast<const std::byte*>(&key), reinterpret_cast<const std::byte*>(&key) + sizeof(key)};
    }

    detail::RawConnTuple& RawTuple() override { return key.tuple; }

    virtual void FillConnIdVal(RecordValPtr& conn_id) override {
        if ( conn_id->NumFields() <= 5 )
            return;

        // XXX: Use named fields and cache offsets.
        RecordType* rt = conn_id->GetType()->AsRecordType();
        if ( key.vlan > 0 && rt->GetFieldType(5)->Tag() == TYPE_INT )
            conn_id->Assign(5, key.vlan);

        if ( key.inner_vlan > 0 && conn_id->NumFields() >= 6 && rt->GetFieldType(6)->Tag() == TYPE_INT )
            conn_id->Assign(6, key.inner_vlan);
    };

private:
    // Key bytes.
    struct {
        struct detail::RawConnTuple tuple;
        // Add 802.1Q vlan tags to connection tuples. The tag representation here is as
        // in the Packet class, since that's where we learn the tag values from.
        uint32_t vlan;
        uint32_t inner_vlan;
    } key;
};

} // namespace zeek::plugin::Zeek_Conntuple_VLAN
