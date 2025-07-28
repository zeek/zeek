// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <unordered_map>

#include "zeek/ConnKey.h"
#include "zeek/Frag.h"
#include "zeek/session/Session.h"

namespace zeek {

namespace telemetry {
class CounterFamily;
using CounterFamilyPtr = std::shared_ptr<CounterFamily>;
class Counter;
using CounterPtr = std::shared_ptr<Counter>;
} // namespace telemetry

namespace detail {
class PacketFilter;
}

class EncapsulationStack;
class Packet;
class Connection;
struct ConnTuple;
class StatBlocks;

namespace session {

namespace detail {
class ProtocolStats;
}

struct Stats {
    size_t num_TCP_conns;
    size_t max_TCP_conns;
    uint64_t cumulative_TCP_conns;

    size_t num_UDP_conns;
    size_t max_UDP_conns;
    uint64_t cumulative_UDP_conns;

    size_t num_ICMP_conns;
    size_t max_ICMP_conns;
    uint64_t cumulative_ICMP_conns;

    size_t num_fragments;
    size_t max_fragments;
    uint64_t num_packets;
    uint64_t num_packets_unprocessed;
};

class Manager final {
public:
    Manager();
    ~Manager();

    [[deprecated("Remove in v8.1 - no functionality. Use Drain() and Clear().")]]
    void Done() {};

    // Looks up the connection referred to by the given Val,
    // which should be a conn_id record.  Returns nil if there's
    // no such connection or the Val is ill-formed.
    Connection* FindConnection(Val* v);

    /**
     * Looks up the connection referred to by a given key.
     *
     * @param conn_key The key for the connection to search for.
     * @return The connection, or nullptr if one doesn't exist.
     */
    Connection* FindConnection(const zeek::ConnKey& conn_key);

    void Remove(Session* s);
    void Insert(Session* c, bool remove_existing = true);

    // Generating connection_pending events for all connections
    // that are still active.
    void Drain();

    // Clears the session maps.
    void Clear();

    void GetStats(Stats& s);

    void Weird(const char* name, const Packet* pkt, const char* addl = "", const char* source = "");
    void Weird(const char* name, const IP_Hdr* ip, const char* addl = "");

    size_t CurrentSessions() { return session_map.size(); }

private:
    using SessionMap = std::unordered_map<detail::Key, Session*, detail::KeyHash>;

    // Inserts a new connection into the sessions map. If a connection with
    // the same key already exists in the map, it will be overwritten by
    // the new one.  Connection count stats get updated either way (so most
    // cases should likely check that the key is not already in the map to
    // avoid unnecessary incrementing of connecting counts).
    void InsertSession(detail::Key key, Session* session);

    SessionMap session_map;
    detail::ProtocolStats* stats;
    telemetry::CounterFamilyPtr ended_sessions_metric_family;
    telemetry::CounterPtr ended_by_inactivity_metric;
};

} // namespace session

// Manager for the currently active sessions.
extern session::Manager* session_mgr;

} // namespace zeek
