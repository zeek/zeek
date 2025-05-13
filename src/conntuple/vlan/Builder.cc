// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/conntuple/vlan/Builder.h"

#include <memory>

#include "zeek/ID.h"
#include "zeek/conntuple/Builder.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/session/Session.h"

namespace zeek::plugin::Zeek_Conntuple_VLAN {

struct IPVlanConnKey : zeek::IPBasedConnKey {
public:
    IPVlanConnKey() {
        // Fill holes, we the whole struct as a key!
        memset(static_cast<void*>(&key), '\0', sizeof(key));
    }

    zeek::session::detail::Key SessionKey() const override {
        return zeek::session::detail::Key(reinterpret_cast<const void*>(&key), sizeof(key),
                                          // XXX: Not sure we need CONNECTION_KEY_TYPE and it adds an extra comparison
                                          // that's anyhow true.
                                          session::detail::Key::CONNECTION_KEY_TYPE);
    }

    detail::RawConnTuple& RawTuple() const override { return key.tuple; }

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

protected:
    void DoInit(const Packet& pkt) override {
        key.vlan = pkt.vlan;
        key.inner_vlan = pkt.inner_vlan;
    }


private:
    friend class Builder;

    // Key bytes.
    struct {
        // mutable for non-const RawTuple() return value.
        mutable struct detail::RawConnTuple tuple;
        // Add 802.1Q vlan tags to connection tuples. The tag representation here is as
        // in the Packet class, since that's where we learn the tag values from.
        uint32_t vlan;
        uint32_t inner_vlan;
    } __attribute__((packed, aligned)) key;
};

zeek::ConnKeyPtr Builder::NewConnKey() { return std::make_unique<IPVlanConnKey>(); }

zeek::ConnKeyPtr Builder::FromVal(const zeek::ValPtr& v) {
    auto ck = NewConnKey();
    auto* k = static_cast<IPVlanConnKey*>(ck.get());
    if ( ! zeek::conntuple::fill_from_val(k, v) ) {
        assert(ck->Error().has_value());
        return ck;
    }

    auto rt = v->GetType()->AsRecordType();
    auto vl = v->As<RecordVal*>();

    // XXX: Use static field offsets
    if ( rt->GetFieldType(5)->Tag() == TYPE_INT && vl->HasField(5) )
        k->key.vlan = vl->GetFieldAs<zeek::IntVal>(5);

    if ( rt->GetFieldType(6)->Tag() == TYPE_INT && vl->HasField(6) )
        k->key.inner_vlan = vl->GetFieldAs<zeek::IntVal>(6);


    return ck;
}

} // namespace zeek::plugin::Zeek_Conntuple_VLAN
