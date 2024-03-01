// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/session/Manager.h"

#include "zeek/zeek-config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include <unistd.h>
#include <cstdlib>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/RunState.h"
#include "zeek/Timer.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/session/Session.h"
#include "zeek/telemetry/Manager.h"

zeek::session::Manager* zeek::session_mgr = nullptr;

namespace zeek::session {
namespace detail {

class ProtocolStats {
public:
    struct Protocol {
        std::shared_ptr<telemetry::IntGauge> active;
        std::shared_ptr<telemetry::IntCounter> total;
        ssize_t max = 0;

        Protocol(const std::shared_ptr<telemetry::IntGaugeFamily>& active_family,
                 const std::shared_ptr<telemetry::IntCounterFamily>& total_family, std::string protocol)
            : active(active_family->GetOrAdd({{"protocol", protocol}})),
              total(total_family->GetOrAdd({{"protocol", protocol}})) {}
    };

    using ProtocolMap = std::map<std::string, Protocol>;

    ProtocolMap::iterator InitCounters(const std::string& protocol) {
        auto active_family =
            telemetry_mgr->GaugeFamily("zeek", "active-sessions", {"protocol"}, "Active Zeek Sessions");
        auto total_family =
            telemetry_mgr->CounterFamily("zeek", "total-sessions", {"protocol"}, "Total number of sessions", "1", true);

        auto [it, inserted] = entries.insert({protocol, Protocol{active_family, total_family, protocol}});

        if ( inserted )
            return it;

        return entries.end();
    }

    Protocol* GetCounters(const std::string& protocol) {
        auto it = entries.find(protocol);
        if ( it == entries.end() )
            it = InitCounters(protocol);

        if ( it != entries.end() )
            return &(it->second);

        return nullptr;
    }

private:
    ProtocolMap entries;
};

} // namespace detail

Manager::Manager() { stats = new detail::ProtocolStats(); }

Manager::~Manager() {
    Clear();
    delete stats;
}

void Manager::Done() {}

Connection* Manager::FindConnection(Val* v) {
    zeek::detail::ConnKey conn_key(v);

    if ( ! conn_key.valid )
        return nullptr;

    return FindConnection(conn_key);
}

Connection* Manager::FindConnection(const zeek::detail::ConnKey& conn_key) {
    detail::Key key(&conn_key, sizeof(conn_key), detail::Key::CONNECTION_KEY_TYPE, false);

    auto it = session_map.find(key);
    if ( it != session_map.end() )
        return static_cast<Connection*>(it->second);

    return nullptr;
}

void Manager::Remove(Session* s) {
    if ( s->IsInSessionTable() ) {
        s->CancelTimers();
        s->Done();
        s->RemovalEvent();

        detail::Key key = s->SessionKey(false);

        if ( session_map.erase(key) == 0 )
            reporter->InternalWarning("connection missing");
        else {
            Connection* c = static_cast<Connection*>(s);
            if ( auto* stat_block = stats->GetCounters(c->TransportIdentifier()) )
                stat_block->active->Dec();
        }

        // Mark that the session isn't in the table so that in case the
        // session has been Ref()'d somewhere, we know that on a future
        // call to Remove() that it's no longer in the map.
        s->SetInSessionTable(false);

        Unref(s);
    }
}

void Manager::Insert(Session* s, bool remove_existing) {
    Session* old = nullptr;
    detail::Key key = s->SessionKey(true);

    if ( remove_existing ) {
        auto it = session_map.find(key);
        if ( it != session_map.end() )
            old = it->second;

        session_map.erase(key);
    }

    InsertSession(std::move(key), s);

    if ( old && old != s ) {
        // Some clean-ups similar to those in Remove() (but invisible
        // to the script layer).
        old->CancelTimers();
        old->SetInSessionTable(false);
        Unref(old);
    }
}

void Manager::Drain() {
    // If a random seed was passed in, we're most likely in testing mode and need the
    // order of the sessions to be consistent. Sort the keys to force that order
    // every run.
    if ( zeek::util::detail::have_random_seed() ) {
        std::vector<const detail::Key*> keys;
        keys.reserve(session_map.size());

        for ( auto& entry : session_map )
            keys.push_back(&(entry.first));
        std::sort(keys.begin(), keys.end(), [](const detail::Key* a, const detail::Key* b) { return *a < *b; });

        for ( const auto* k : keys ) {
            Session* tc = session_map.at(*k);
            tc->Done();
            tc->RemovalEvent();
        }
    }
    else {
        for ( const auto& entry : session_map ) {
            Session* tc = entry.second;
            tc->Done();
            tc->RemovalEvent();
        }
    }
}

void Manager::Clear() {
    for ( const auto& entry : session_map )
        Unref(entry.second);

    session_map.clear();

    zeek::detail::fragment_mgr->Clear();
}

void Manager::GetStats(Stats& s) {
    auto* tcp_stats = stats->GetCounters("tcp");
    s.max_TCP_conns = tcp_stats->max;
    s.num_TCP_conns = tcp_stats->active->Value();
    s.cumulative_TCP_conns = tcp_stats->total->Value();

    auto* udp_stats = stats->GetCounters("udp");
    s.max_UDP_conns = udp_stats->max;
    s.num_UDP_conns = udp_stats->active->Value();
    s.cumulative_UDP_conns = udp_stats->total->Value();

    auto* icmp_stats = stats->GetCounters("icmp");
    s.max_ICMP_conns = icmp_stats->max;
    s.num_ICMP_conns = icmp_stats->active->Value();
    s.cumulative_ICMP_conns = icmp_stats->total->Value();

    s.num_fragments = zeek::detail::fragment_mgr->Size();
    s.max_fragments = zeek::detail::fragment_mgr->MaxFragments();
    s.num_packets = packet_mgr->PacketsProcessed();
}

void Manager::Weird(const char* name, const Packet* pkt, const char* addl, const char* source) {
    const char* weird_name = name;

    if ( pkt ) {
        pkt->dump_packet = true;

        if ( pkt->encap && pkt->encap->LastType() != BifEnum::Tunnel::NONE )
            weird_name = util::fmt("%s_in_tunnel", name);

        if ( pkt->ip_hdr ) {
            reporter->Weird(pkt->ip_hdr->SrcAddr(), pkt->ip_hdr->DstAddr(), weird_name, addl, source);
            return;
        }
    }

    reporter->Weird(weird_name, addl, source);
}

void Manager::Weird(const char* name, const IP_Hdr* ip, const char* addl) {
    reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name, addl);
}

void Manager::InsertSession(detail::Key key, Session* session) {
    session->SetInSessionTable(true);
    key.CopyData();
    session_map.insert_or_assign(std::move(key), session);

    std::string protocol = session->TransportIdentifier();

    if ( auto* stat_block = stats->GetCounters(protocol) ) {
        stat_block->active->Inc();
        stat_block->total->Inc();

        if ( stat_block->active->Value() > stat_block->max )
            stat_block->max++;
    }
}

} // namespace zeek::session
