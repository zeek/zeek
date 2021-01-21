// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <map>
#include <utility>

#include "zeek/Frag.h"
#include "zeek/PacketFilter.h"
#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/tcp/Stats.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(EncapsulationStack, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Packet, zeek);
ZEEK_FORWARD_DECLARE_NAMESPACED(Connection, zeek);
class ConnCompressor;

ZEEK_FORWARD_DECLARE_NAMESPACED(SteppingStoneManager, zeek, analyzer::stepping_stone);

namespace zeek {

struct ConnID;

struct SessionStats {
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

class NetSessions {
public:
	NetSessions();
	~NetSessions();

	void Done();	// call to drain events before destructing

	// Looks up the connection referred to by the given Val,
	// which should be a conn_id record.  Returns nil if there's
	// no such connection or the Val is ill-formed.
	Connection* FindConnection(Val* v);

	void Remove(Connection* c);
	void Insert(Connection* c);

	// Generating connection_pending events for all connections
	// that are still active.
	void Drain();

	// Clears the session maps.
	void Clear();

	void GetStats(SessionStats& s) const;

	void Weird(const char* name, const Packet* pkt,
	           const char* addl = "", const char* source = "");
	void Weird(const char* name, const IP_Hdr* ip,
	           const char* addl = "");

	detail::PacketFilter* GetPacketFilter(bool init=true)
		{
		if ( ! packet_filter && init )
			packet_filter = new detail::PacketFilter(detail::packet_filter_default);
		return packet_filter;
		}

	analyzer::stepping_stone::SteppingStoneManager* GetSTPManager()	{ return stp_manager; }

	unsigned int CurrentConnections()
		{
		return tcp_conns.size() + udp_conns.size() + icmp_conns.size();
		}

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

	/**
	 * Returns a wrapper IP_Hdr object if \a pkt appears to be a valid IPv4
	 * or IPv6 header based on whether it's long enough to contain such a header,
	 * if version given in the header matches the proto argument, and also checks
	 * that the payload length field of that header matches the actual
	 * length of \a pkt given by \a caplen.
	 *
	 * @param caplen The length of \a pkt in bytes.
	 * @param pkt The inner IP packet data.
	 * @param proto Either IPPROTO_IPV6 or IPPROTO_IPV4 to indicate which IP
	 *        protocol \a pkt corresponds to.
	 * @param inner The inner IP packet wrapper pointer to be allocated/assigned
	 *        if \a pkt looks like a valid IP packet or at least long enough
	 *        to hold an IP header.
	 * @return 0 If the inner IP packet appeared valid, else -1 if \a caplen
	 *         is greater than the supposed IP packet's payload length field, -2
	 *         if the version of the inner header does not match proto or
	 *         1 if \a caplen is less than the supposed packet's payload length.
	 *         In the -1 case, \a inner may still be non-null if \a caplen was
	 *         long enough to be an IP header, and \a inner is always non-null
	 *         for other return values.
	 */
	int ParseIPPacket(int caplen, const u_char* const pkt, int proto,
	                  IP_Hdr*& inner);

	unsigned int ConnectionMemoryUsage();
	unsigned int ConnectionMemoryUsageConnVals();
	unsigned int MemoryAllocation();
	analyzer::tcp::TCPStateStats tcp_stats;	// keeps statistics on TCP states

protected:
	friend class ConnCompressor;

	using ConnectionMap = std::map<detail::ConnIDKey, Connection*>;

	Connection* NewConn(const detail::ConnIDKey& k, double t, const ConnID* id,
	                    const u_char* data, int proto, uint32_t flow_label,
	                    const Packet* pkt);

	Connection* LookupConn(const ConnectionMap& conns, const detail::ConnIDKey& key);

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
	void InsertConnection(ConnectionMap* m, const detail::ConnIDKey& key, Connection* conn);

	ConnectionMap tcp_conns;
	ConnectionMap udp_conns;
	ConnectionMap icmp_conns;

	SessionStats stats;

	analyzer::stepping_stone::SteppingStoneManager* stp_manager;
	detail::PacketFilter* packet_filter;
};

// Manager for the currently active sessions.
extern NetSessions* sessions;

} // namespace zeek
