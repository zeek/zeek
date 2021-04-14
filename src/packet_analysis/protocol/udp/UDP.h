// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/packet_analysis/Analyzer.h"
#include "zeek/packet_analysis/Component.h"
#include "zeek/packet_analysis/protocol/ip/IPBasedAnalyzer.h"

namespace zeek::packet_analysis::UDP {

class UDPAnalyzer final : public IP::IPBasedAnalyzer {
public:
	UDPAnalyzer();
	~UDPAnalyzer() override;

	bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

	static zeek::packet_analysis::AnalyzerPtr Instantiate()
		{
		return std::make_shared<UDPAnalyzer>();
		}

	void CreateTransportAnalyzer(Connection* conn, IP::IPBasedTransportAnalyzer*& root,
	                             analyzer::pia::PIA*& pia, bool& check_port) override;

	/**
	 * Initialize the analyzer. This method is called after the configuration
	 * was read. Derived classes can override this method to implement custom
	 * initialization.
	 */
	void Initialize() override;

protected:

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

	void ContinueProcessing(Connection* c, double t, bool is_orig, int remaining,
	                        Packet* pkt) override;

private:

	// Returns true if the checksum is valid, false if not
	static bool ValidateChecksum(const IP_Hdr* ip, const struct udphdr* up,
	                             int len);

	void ChecksumEvent(bool is_orig, uint32_t threshold);

	Connection* conn;

	std::vector<uint16_t> vxlan_ports;
};

class UDPTransportAnalyzer final : public IP::IPBasedTransportAnalyzer {

public:

	UDPTransportAnalyzer(Connection* conn) :
		IP::IPBasedTransportAnalyzer("UDP", conn) { }

	static zeek::analyzer::Analyzer* Instantiate(Connection* conn)
		{
		return new UDPTransportAnalyzer(conn);
		}

	void AddExtraAnalyzers(Connection* conn) override;
	void UpdateConnVal(RecordVal* conn_val) override;

	void UpdateLength(bool is_orig, int len);

	// For tracking checksum history. These are connection-specific so they
	// need to be stored in the transport analyzer created for each
	// connection.
	uint32_t req_chk_cnt = 0;
	uint32_t req_chk_thresh = 1;
	uint32_t rep_chk_cnt = 0;
	uint32_t rep_chk_thresh = 1;

private:

	void UpdateEndpointVal(const ValPtr& endp_arg, bool is_orig);

	bro_int_t request_len = -1;
	bro_int_t reply_len = -1;
};

}
