// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <map>
#include <utility>

#include "zeek/Frag.h"
#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/tcp/Stats.h"
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
	 * @param key The key for the connection to search for.
	 * @param proto The transport protocol for the connection.
	 * @return The connection, or nullptr if one doesn't exist.
	 */
	Connection* FindConnection(const zeek::detail::ConnKey& key, TransportProto proto);

	void Remove(Session* s);
	void Insert(Session* c);

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

	/**
	 * Main entry point for processing packets destined for session analyzers. This
	 * method is called by the packet analysis manager when after it has processed
	 * an IP-based packet, and shouldn't be called directly from other places.
	 *
	 * @param t The timestamp for this packet.
	 * @param pkt The packet being processed.
	 * @param len The number of bytes that haven't been processed yet by packet
	 * analysis.
	 */
	void ProcessTransportLayer(double t, const Packet *pkt, size_t len);

	unsigned int SessionMemoryUsage();
	unsigned int SessionMemoryUsageVals();

	[[deprecated("Remove in v5.1. Use SessionMemoryUsage().")]]
	unsigned int ConnectionMemoryUsage() { return SessionMemoryUsage(); }
	[[deprecated("Remove in v5.1. Use SessionMemoryUsageVals().")]]
	unsigned int ConnectionMemoryUsageConnVals() { return SessionMemoryUsageVals(); }

	unsigned int MemoryAllocation();

	// TODO: should this move somewhere else?
	analyzer::tcp::TCPStateStats tcp_stats;	// keeps statistics on TCP states

private:

	using SessionMap = std::map<detail::Key, Session*>;

	Connection* NewConn(const zeek::detail::ConnKey& k, double t, const ConnTuple* id,
	                    const u_char* data, int proto, uint32_t flow_label,
	                    const Packet* pkt);

	// Returns true if the port corresonds to an application
	// for which there's a Bro analyzer (even if it might not
	// be used by the present policy script), or it's more
	// generally a likely server port, false otherwise.
	//
	// Note, port is in host order.
	bool IsLikelyServerPort(uint32_t port, TransportProto transport_proto) const;

	// Upon seeing the first packet of a connection, checks whether
	// we want to analyze it (e.g., we may not want to look at partial
	// connections), and, if yes, whether we should flip the roles of
	// originator and responder (based on known ports or such).
	// Use tcp_flags=0 for non-TCP.
	bool WantConnection(uint16_t src_port, uint16_t dest_port,
	                    TransportProto transport_proto,
	                    uint8_t tcp_flags, bool& flip_roles);

	// For a given protocol, checks whether the header's length as derived
	// from lower-level headers or the length actually captured is less
	// than that protocol's minimum header size.
	bool CheckHeaderTrunc(int proto, uint32_t len, uint32_t caplen, const Packet *pkt);

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
