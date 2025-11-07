#include "ShuntThread.h"

#include <zeek/Event.h>
#include <zeek/Reporter.h>

#include "conn_id_shunter.bif.h"
#include "ip_pair_shunter.bif.h"

zeek::EventMgr zeek::event_mgr;

namespace xdp::shunter::detail {

void handle_canonical(void* data) {
    auto* key = static_cast<const canonical_tuple*>(data);
    auto zeek_key = zeek::make_intrusive<zeek::RecordVal>(zeek::id::conn_id);
    if ( IN6_IS_ADDR_V4MAPPED(&key->ip1) )
        zeek_key->Assign(0, zeek::make_intrusive<zeek::AddrVal>(
                                *reinterpret_cast<const uint32_t*>(&key->ip1.s6_addr[12])));
    else
        zeek_key->Assign(0, zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&key->ip1.s6_addr)));

    zeek_key->Assign(1, zeek::val_mgr->Port(key->port1));

    if ( IN6_IS_ADDR_V4MAPPED(&key->ip2) )
        zeek_key->Assign(2, zeek::make_intrusive<zeek::AddrVal>(
                                *reinterpret_cast<const uint32_t*>(&key->ip2.s6_addr[12])));
    else
        zeek_key->Assign(2, zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&key->ip2.s6_addr)));

    zeek_key->Assign(3, zeek::val_mgr->Port(key->port2));
    zeek_key->Assign(4, zeek::val_mgr->Count(key->protocol));

    zeek::event_mgr.Enqueue(XDP::Shunt::ConnID::first_fin, zeek_key);
}

void handle_ip_pair(void* data) {
    auto* key = static_cast<const ip_pair_key*>(data);
    static auto ip_pair = zeek::id::find_type<zeek::RecordType>("XDP::ip_pair");
    auto zeek_key = zeek::make_intrusive<zeek::RecordVal>(ip_pair);
    if ( IN6_IS_ADDR_V4MAPPED(&key->ip1) )
        zeek_key->Assign(0, zeek::make_intrusive<zeek::AddrVal>(
                                *reinterpret_cast<const uint32_t*>(&key->ip1.s6_addr[12])));
    else
        zeek_key->Assign(0, zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&key->ip1.s6_addr)));


    if ( IN6_IS_ADDR_V4MAPPED(&key->ip2) )
        zeek_key->Assign(1, zeek::make_intrusive<zeek::AddrVal>(
                                *reinterpret_cast<const uint32_t*>(&key->ip2.s6_addr[12])));
    else
        zeek_key->Assign(1, zeek::make_intrusive<zeek::AddrVal>(reinterpret_cast<const uint32_t*>(&key->ip2.s6_addr)));

    zeek::event_mgr.Enqueue(XDP::Shunt::IPPair::first_fin, zeek_key);
}

int ShuntThread::handle_event(void* ctx, void* data, size_t data_sz) {
    if ( data_sz == sizeof(canonical_tuple) )
        handle_canonical(data);
    else if ( data_sz == sizeof(ip_pair_key) )
        handle_ip_pair(data);
    else
        zeek::reporter->InternalError("XDP Shunter: Invalid ring buffer type");

    return 0;
}

} // namespace xdp::shunter::detail
