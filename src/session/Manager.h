// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <map>
#include <utility>

#include "zeek/Frag.h"
#include "zeek/NetVar.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/Hash.h"
#include "zeek/session/Session.h"

namespace zeek {

namespace detail { class PacketFilter; }

class EncapsulationStack;
class Packet;
class Connection;
struct ConnTuple;
class StatBlocks;

namespace session {

namespace detail { class ProtocolStats; }

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
};

class Manager final {
public:
	Manager();
	~Manager();

	void Done();	// call to drain events before destructing

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
	Connection* FindConnection(const zeek::detail::ConnKey& conn_key);

	void Remove(Session* s);
	void Insert(Session* c, bool remove_existing=true);

	// Generating connection_pending events for all connections
	// that are still active.
	void Drain();

	// Clears the session maps.
	void Clear();

	void GetStats(Stats& s);

	void Weird(const char* name, const Packet* pkt,
	           const char* addl = "", const char* source = "");
	void Weird(const char* name, const IP_Hdr* ip,
	           const char* addl = "");

	[[deprecated("Remove in v5.1. Use packet_mgr->GetPacketFilter().")]]
	zeek::detail::PacketFilter* GetPacketFilter(bool init=true);

	unsigned int CurrentSessions()
		{
		return session_map.size();
		}

	[[deprecated("Remove in v5.1. Use CurrentSessions().")]]
	unsigned int CurrentConnections() { return CurrentSessions(); }

	unsigned int SessionMemoryUsage();
	unsigned int SessionMemoryUsageVals();

	[[deprecated("Remove in v5.1. Use SessionMemoryUsage().")]]
	unsigned int ConnectionMemoryUsage() { return SessionMemoryUsage(); }
	[[deprecated("Remove in v5.1. Use SessionMemoryUsageVals().")]]
	unsigned int ConnectionMemoryUsageConnVals() { return SessionMemoryUsageVals(); }

	unsigned int MemoryAllocation();

private:

	using SessionMap = std::map<detail::Key, Session*>;

	// Inserts a new connection into the sessions map. If a connection with
	// the same key already exists in the map, it will be overwritten by
	// the new one.  Connection count stats get updated either way (so most
	// cases should likely check that the key is not already in the map to
	// avoid unnecessary incrementing of connecting counts).
	void InsertSession(detail::Key key, Session* session);

	SessionMap session_map;
	detail::ProtocolStats* stats;
};

} // namespace session

// Manager for the currently active sessions.
extern session::Manager* session_mgr;

extern session::Manager*& sessions [[deprecated("Remove in v5.1. Use zeek::sessions::session_mgr.")]];
using NetSessions [[deprecated("Remove in v5.1. Use zeek::session::Manager.")]] = session::Manager;

} // namespace zeek
