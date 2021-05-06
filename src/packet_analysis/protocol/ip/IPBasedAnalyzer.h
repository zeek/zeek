// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"

namespace zeek::analyzer::pia { class PIA; }

namespace zeek::packet_analysis::IP {

class IPBasedTransportAnalyzer;

/**
 * A base class for any packet analyzer based on IP. This is used by default by
 * the TCP, UDP, and ICMP analyzers to reduce a large amount of duplicated code
 * that those plugins have in common.
 */
class IPBasedAnalyzer : public Analyzer {
public:
	~IPBasedAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	/**
	 * Returns true if the analyzer determines that in fact a new
	 * connection has started without the connection statement having
	 * terminated the previous one, i.e., the new data is arriving at
	 * what's the analyzer for the previous instance. This is used only
	 * for TCP.
	 */
	virtual bool IsReuse(double t, const u_char* pkt) { return false; }

	/**
	 * TODO: comment
	 */
	virtual void CreateTransportAnalyzer(Connection* conn, IPBasedTransportAnalyzer*& root,
	                                     analyzer::pia::PIA*& pia, bool& check_port) = 0;

protected:

	/**
	 * Construct a new IP-based analyzer.
	 *
	 * @param name The name for the type of analyzer. The name must match
	 * the one the corresponding Component registers.
	 * @param proto The transport protocol implemented by this analyzer.
	 * @param mask The mask used to determine if a port is a server port
	 * for this protocol. This is used by IsLikelyServerPort().
	 * @param report_unknown_protocols Flag for whether to report unknown
	 * protocols during packet forwarding. This is typically false for IP
	 * protocols since packets may go into the session analysis framework
	 * as well.
	 */
	IPBasedAnalyzer(const char* name, TransportProto proto, uint32_t mask,
	                bool report_unknown_protocols);

	/**
	 * Parse the header from the packet into a ConnTuple object.
	 */
	virtual bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
	                            ConnTuple& tuple) = 0;

	/**
	 * Continues process of packet after the connection has been inserted into the
	 * session manager. This should be implemented by all child classes.
	 *
	 * @param conn The connection currently being processed.
	 * @param t The timestamp for the current packet.
	 * @param is_orig Flag denoting whether this packet is from the originator of
	 * the connection.
	 * @param remaining The remaining about of data in the packet.
	 * @param pkt The packet being processed.
	 */
	virtual void DeliverPacket(Connection* conn, double t, bool is_orig, int remaining,
	                           Packet* pkt) {}

	/**
	 * Upon seeing the first packet of a connection, checks whether we want
	 * to analyze it (e.g. we may not want to look at partial connections)
	 * and, if yes, whether we should flip the roles of originator and
	 * responder based on known ports and such.
	 *
	 * @param src_port The source port of the connection.
	 * @param dst_port The destination port of the connection.
	 * @param data The payload data for the packet being processed.
	 * @param flip_roles Return value if the roles should be flipped.
	 * @return True if the connection is wanted. False otherwise.
	 */
	virtual bool WantConnection(uint16_t src_port, uint16_t dst_port,
	                            const u_char* data, bool& flip_roles) const
		{
		flip_roles = false;
		return true;
		}

	/**
	 * Verifies that there is enough data in the packet to process the header
	 * length requested.
	 *
	 * @param min_hdr_len The minimum data in bytes that needs to exist.
	 * @param remaining The remaining number of bytes in the packet reported by
	 * previous analyzer.
	 * @param packet The packet being processed. This will be used to pull out the
	 * number of bytes the IP header says we have remaining.
	 */
	bool CheckHeaderTrunc(size_t min_hdr_len, size_t remaining, Packet* packet);

	/**
	 * Returns true if the port corresponds to an application for which there
	 * is a Zeek analyzer (even if it might not be used by the present policy
	 * script) or if it's generally a likely server port.
	 *
	 * @param port The port number to check, in host order.
	 */
	bool IsLikelyServerPort(uint32_t port) const;


	// TODO: temporary, until all of the plugins are implemented
	bool new_plugin = false;

private:

	/**
	 * Creates a new Connection object from data gleaned from the current packet.
	 *
	 * @param id A connection ID generated from the packet data. This should have been
	 * passed in from a child analyzer.
	 * @param key A connection ID key generated from the ID.
	 * @param pkt The packet associated with the new connection.
	 */
	zeek::Connection* NewConn(const ConnTuple* id, const detail::ConnKey& key,
	                          const Packet* pkt);

	TransportProto transport;
	uint32_t server_port_mask;
};

/**
 * This class represents the interface between the packet analysis framework and
 * the session analysis framework. One of these should be implemented for each
 * packet analyzer that intends to forward into the session analysis.
 */
class IPBasedTransportAnalyzer : public zeek::analyzer::TransportLayerAnalyzer {

public:

	IPBasedTransportAnalyzer(const char* name, Connection* conn)
		: TransportLayerAnalyzer(name, conn) { }

	/**
	 * Sets the parent packet analyzer for this transport analyzer. This can't be passed to
	 * the constructor due to the way that TransportLayerAnalyzer gets instantiated.
	 *
	 * @param p The parent packet analyzer to store
	 */
	void SetParent(IPBasedAnalyzer* p) { parent = p; }

	/**
	 * Returns true if the analyzer determines that in fact a new connection has started
	 * without the connection statement having terminated the previous one, i.e., the new
	 * data is arriving at what's the analyzer for the previous instance. This is used only
	 * for TCP.
	 */
	bool IsReuse(double t, const u_char* pkt) override { return parent->IsReuse(t, pkt); }

	/**
	 * Pure virtual method to allow extra session analzyers to be added to this analyzer's
	 * tree of children. This is used by analyzer::Manager when creating the session analyzer
	 * tree.
	 */
	virtual void AddExtraAnalyzers(Connection* conn) = 0;

protected:

	IPBasedAnalyzer* parent;
};

}
