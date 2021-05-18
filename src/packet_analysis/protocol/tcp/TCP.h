// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"
#include "zeek/packet_analysis/protocol/tcp/Stats.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"

namespace zeek::analyzer::tcp { class TCP_Endpoint; }

namespace zeek::packet_analysis::TCP {

class TCPSessionAdapter;

class TCPAnalyzer final : public IP::IPBasedAnalyzer {
public:
	TCPAnalyzer();
	~TCPAnalyzer() override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<TCPAnalyzer>();
		}

	/*
	 * Initialize the analyzer. This method is called after the configuration
	 * was read. Derived classes can override this method to implement custom
	 * initialization.
	 */
	void Initialize() override;

	static TCPStateStats& GetStats()
		{
		static TCPStateStats stats;
		return stats;
		}

protected:

	/**
	 * Parse the header from the packet into a ConnTuple object.
	 */
	bool BuildConnTuple(size_t len, const uint8_t* data, Packet* packet,
	                    ConnTuple& tuple) override;

	void DeliverPacket(Connection* c, double t, bool is_orig, int remaining,
	                        Packet* pkt) override;

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
	bool WantConnection(uint16_t src_port, uint16_t dst_port,
	                    const u_char* data, bool& flip_roles) const override;

	/**
	 * Returns an analyzer adapter appropriate for this IP-based analyzer. This adapter
	 * is used to hook into the session analyzer framework. This function can also be used
	 * to do any extra initialization of connection timers, etc.
	 */
	packet_analysis::IP::SessionAdapter* MakeSessionAdapter(Connection* conn) override;

	/**
	 * Returns a PIA appropriate for this IP-based analyzer. This method is optional to
	 * override in child classes, as not all analyzers need a PIA.
	 */
	analyzer::pia::PIA* MakePIA(Connection* conn) override;

private:

	const struct tcphdr* ExtractTCP_Header(const u_char*& data, int& len, int& remaining,
	                                       TCPSessionAdapter* adapter);

	void SynWeirds(analyzer::tcp::TCP_Flags flags, analyzer::tcp::TCP_Endpoint* endpoint,
	               int data_len) const;

	int ParseTCPOptions(TCPSessionAdapter* adapter, const struct tcphdr* tcp,
	                    bool is_orig) const;

	void CheckRecording(Connection* c, bool need_contents, analyzer::tcp::TCP_Flags flags);

	// Returns true if the checksum is valid, false if not (and in which
	// case also updates the status history of the endpoint).
	bool ValidateChecksum(const IP_Hdr* ip, const struct tcphdr* tp,
	                      analyzer::tcp::TCP_Endpoint* endpoint,
	                      int len, int caplen, TCPSessionAdapter* adapter);

	TableValPtr ignored_nets;
};

}
